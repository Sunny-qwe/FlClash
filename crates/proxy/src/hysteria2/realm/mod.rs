mod control;
mod punch;
mod stun;

use std::io;
use std::net::{IpAddr, SocketAddr};

use concord_common::{Address, DialCx, Initiator, IpVersion, SockOpts};
use concord_config::proxy::Hysteria2Realm;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::UdpSocket;
use tracing::debug;

use self::control::Control;
use self::punch::Metadata;
use crate::ctx::{BuildCtx, BuildError};
use crate::node::Egress;
use crate::tlsmap::{TlsSpec, tls_options};

const DEFAULT_STUN_PORT: u16 = 3478;

/// How a hysteria2 node finds a server that sits behind a NAT: the control
/// server introduces both ends and each side punches a hole toward the other.
pub(crate) struct Realm {
    control: Control,
    id: String,
    stun: Vec<String>,
}

struct Family {
    v4: bool,
    socket: UdpSocket,
    mapped: Vec<SocketAddr>,
}

fn label(v4: bool) -> &'static str {
    if v4 { "v4" } else { "v6" }
}

fn context(err: io::Error, what: &str) -> io::Error {
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

impl Realm {
    pub(crate) fn new(opts: &Hysteria2Realm, ctx: &BuildCtx) -> Result<Self, BuildError> {
        let tls = concord_config::proxy::TlsOpts {
            skip_cert_verify: opts.skip_cert_verify,
            name_cert_verify: opts.name_cert_verify.clone(),
            fingerprint: opts.fingerprint.clone(),
            certificate: opts.certificate.clone(),
            private_key: opts.private_key.clone(),
            ..Default::default()
        };
        let options = tls_options(
            &tls,
            TlsSpec {
                sni: opts.sni.clone(),
                alpn: vec!["http/1.1".to_string()],
            },
            ctx,
            None,
        )?;
        let connector = concord_tls::TlsConnector::new(options, ctx.trust.clone())?;
        Ok(Realm {
            control: Control::new(opts.server_url.clone(), opts.token.clone(), connector),
            id: opts.realm_id.clone(),
            stun: opts.stun_servers.clone(),
        })
    }

    async fn stun_servers(&self, cx: &DialCx<'_>) -> io::Result<Vec<SocketAddr>> {
        let lookups = self.stun.iter().map(|server| async move {
            let (host, port) = match Address::parse(server) {
                Some(Address::Socket(addr)) => return Ok(vec![addr]),
                Some(Address::Domain(host, port)) => (host.to_string(), port),
                None => (server.clone(), DEFAULT_STUN_PORT),
            };
            if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
                return Ok(vec![SocketAddr::new(ip.to_canonical(), port)]);
            }
            let found = cx
                .env
                .resolver
                .lookup(&host, IpVersion::Dual, Initiator::Proxy)
                .await
                .map_err(|err| context(err, &format!("resolve STUN server: {server}")))?;
            Ok::<_, io::Error>(
                found
                    .v4
                    .into_iter()
                    .chain(found.v6)
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect(),
            )
        });
        let mut all = Vec::new();
        for resolved in futures_util::future::join_all(lookups).await {
            all.extend(resolved?);
        }
        if all.is_empty() {
            return Err(io::Error::other("no STUN servers resolved"));
        }
        Ok(all)
    }

    /// One socket per address family that has a STUN server, each asked for
    /// the address the outside world sees it at. A family that fails is dropped.
    async fn open(
        &self,
        cx: &DialCx<'_>,
        egress: &Egress,
        servers: &[SocketAddr],
    ) -> io::Result<Vec<Family>> {
        let opts = SockOpts {
            tunnel_udp_buffers: true,
            ..egress.sock_opts(cx.env)
        };
        let mut families = Vec::new();
        let mut errors = Vec::new();
        for v4 in [true, false] {
            let wanted: Vec<SocketAddr> = servers
                .iter()
                .copied()
                .filter(|server| server.is_ipv4() == v4)
                .collect();
            let Some(first) = wanted.first() else {
                continue;
            };
            let socket = match cx.env.sockets.bind_udp(first.ip(), &opts) {
                Ok(socket) => socket,
                Err(err) => {
                    errors.push(context(err, label(v4)));
                    continue;
                }
            };
            families.push((v4, socket, wanted));
        }
        let discovered = futures_util::future::join_all(
            families
                .iter()
                .map(|(_, socket, wanted)| stun::discover(socket, wanted)),
        )
        .await;
        let mut survivors = Vec::new();
        for ((v4, socket, _), outcome) in families.into_iter().zip(discovered) {
            match outcome {
                Ok(mapped) => survivors.push(Family { v4, socket, mapped }),
                Err(err) => errors.push(context(err, label(v4))),
            }
        }
        if survivors.is_empty() {
            let reason = errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(io::Error::other(if reason.is_empty() {
                "realm STUN discovery: no usable address family".to_string()
            } else {
                format!("realm STUN discovery: {reason}")
            }));
        }
        Ok(survivors)
    }

    /// Runs the whole introduction and returns the socket the punch opened
    /// with the address of the server behind it, ready to carry QUIC.
    pub(crate) async fn punch(
        &self,
        cx: &DialCx<'_>,
        egress: &Egress,
    ) -> io::Result<(UdpSocket, SocketAddr)> {
        let work = self.introduce(cx, egress);
        match cx.deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, work)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "realm punch timed out"))?,
            None => work.await,
        }
    }

    async fn introduce(
        &self,
        cx: &DialCx<'_>,
        egress: &Egress,
    ) -> io::Result<(UdpSocket, SocketAddr)> {
        let servers = self
            .stun_servers(cx)
            .await
            .map_err(|err| context(err, "resolve STUN servers"))?;
        let families = self.open(cx, egress, &servers).await?;
        let local: Vec<SocketAddr> = families
            .iter()
            .flat_map(|family| family.mapped.iter().copied())
            .collect();
        debug!("realm {} local addresses {local:?}", self.id);
        let metadata = Metadata::random();
        let reply = self
            .control
            .connect(cx, egress, &self.id, &local, &metadata)
            .await
            .map_err(|err| context(err, "realm connect"))?;
        debug!("realm {} peer addresses {:?}", self.id, reply.addresses);
        let (winner, peer) = race(families, &reply.addresses, &reply.metadata).await?;
        debug!("realm {} punched through to {peer}", self.id);
        Ok((winner, peer))
    }
}

async fn race(
    families: Vec<Family>,
    peers: &[SocketAddr],
    metadata: &Metadata,
) -> io::Result<(UdpSocket, SocketAddr)> {
    let mut winner = None;
    let mut errors = Vec::new();
    {
        let mut running: FuturesUnordered<_> = families
            .iter()
            .enumerate()
            .map(|(index, family)| async move {
                let wanted: Vec<SocketAddr> = peers
                    .iter()
                    .copied()
                    .filter(|peer| peer.is_ipv4() == family.v4)
                    .collect();
                let result = punch::punch(&family.socket, &wanted, metadata).await;
                (index, result)
            })
            .collect();
        while let Some((index, result)) = running.next().await {
            match result {
                Ok((peer, _kind)) => {
                    winner = Some((index, peer));
                    break;
                }
                Err(err) => {
                    let v4 = families.get(index).is_some_and(|family| family.v4);
                    errors.push(context(err, label(v4)));
                }
            }
        }
    }
    match winner {
        Some((index, peer)) => families
            .into_iter()
            .nth(index)
            .map(|family| (family.socket, peer))
            .ok_or_else(|| io::Error::other("realm punch lost its socket")),
        None => {
            let reason = errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            Err(io::Error::other(format!("realm punch: {reason}")))
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "the tests talk to loopback sockets directly"
)]
mod tests {
    use concord_common::{DialCx, Initiator};
    use concord_config::proxy::CommonOpts;
    use concord_tls::TrustStore;
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::testing::test_env;

    fn realm(url: &str, stun: &[SocketAddr]) -> Realm {
        let opts = Hysteria2Realm {
            enable: true,
            server_url: url.to_string(),
            token: "tok".into(),
            realm_id: "my realm".into(),
            stun_servers: stun.iter().map(ToString::to_string).collect(),
            ..Default::default()
        };
        Realm::new(&opts, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap()
    }

    async fn stun_responder() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok((read, from)) = socket.recv_from(&mut buf).await {
                if let Some(reply) = stun::answer(&buf[..read], from) {
                    let _ = socket.send_to(&reply, from).await;
                }
            }
        });
        addr
    }

    /// Answers one `/connect` with the peer's address and the metadata it was sent, and hands the request on.
    async fn control(peer: SocketAddr) -> (String, oneshot::Receiver<(String, Value)>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/prefix/", listener.local_addr().unwrap());
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            let (head, body) = loop {
                let read = conn.read(&mut buf).await.unwrap();
                seen.extend_from_slice(&buf[..read]);
                let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&seen[..end]).into_owned();
                let length: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.parse().ok())
                    .unwrap();
                if seen.len() >= end + 4 + length {
                    break (head, seen[end + 4..end + 4 + length].to_vec());
                }
            };
            let request: Value = serde_json::from_slice(&body).unwrap();
            let reply = json!({
                "addresses": [peer.to_string()],
                "nonce": request["nonce"],
                "obfs": request["obfs"],
            })
            .to_string();
            let _ = tx.send((head, request));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}",
                reply.len()
            );
            conn.write_all(response.as_bytes()).await.unwrap();
        });
        (url, rx)
    }

    #[tokio::test]
    async fn the_introduction_ends_with_a_socket_that_reaches_the_peer() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let stun = stun_responder().await;
        let (url, request) = control(peer_addr).await;
        let realm = realm(&url, &[stun]);

        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let egress = Egress::new("realm-test", &CommonOpts::default());
        let punching = realm.punch(&cx, &egress);
        let answering = async {
            let (head, body) = request.await.unwrap();
            let mapped: Vec<SocketAddr> = body["addresses"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry.as_str().unwrap().parse().unwrap())
                .collect();
            let metadata = Metadata {
                nonce: hex::decode(body["nonce"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                key: hex::decode(body["obfs"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
            };
            let (from, _) = punch::punch(&peer, &mapped, &metadata).await.unwrap();
            (head, mapped, from)
        };
        let (punched, (head, mapped, from)) = tokio::join!(punching, answering);
        let (socket, reached) = punched.unwrap();

        assert!(head.starts_with("POST /prefix/v1/my%20realm/connect HTTP/1.1"));
        assert!(head.contains("Authorization: Bearer tok"));
        assert_eq!(reached, peer_addr);
        let port = socket.local_addr().unwrap().port();
        assert_eq!(mapped, [SocketAddr::from(([127, 0, 0, 1], port))]);
        assert_eq!(from.port(), port);
    }

    #[tokio::test]
    async fn a_missing_stun_server_is_reported_before_the_control_server_is_asked() {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Direct, None);
        let egress = Egress::new("realm-test", &CommonOpts::default());
        let err = realm("http://127.0.0.1:9", &[])
            .punch(&cx, &egress)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no STUN servers resolved"),
            "{err}"
        );
    }
}
