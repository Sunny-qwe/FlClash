use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use concord_common::Address;
use concord_common::addr::unmap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ctx::{Client, dst_address};
use crate::spec::{Authenticator, HostCredential};

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

/// A UDP header is three bytes and an address of at most 1 + 1 + 255 + 2.
pub(crate) const MAX_UDP_HEADER: usize = 3 + 1 + 1 + 255 + 2;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Connect,
    UdpAssociate,
}

pub(crate) struct Request {
    pub(crate) command: Command,
    pub(crate) target: Address,
    pub(crate) client: Client,
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(out: &'a mut [u8]) -> Self {
        Writer { out, at: 0 }
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) {
        if let Some(slot) = self.out.get_mut(self.at..self.at + bytes.len()) {
            slot.copy_from_slice(bytes);
            self.at += bytes.len();
        }
    }
}

pub(crate) fn addr_len(addr: &Address) -> io::Result<usize> {
    Ok(match addr {
        Address::Socket(SocketAddr::V4(_)) => 1 + 4 + 2,
        Address::Socket(SocketAddr::V6(_)) => 1 + 16 + 2,
        Address::Domain(host, _) if host.len() <= 255 => 1 + 1 + host.len() + 2,
        Address::Domain(..) => return Err(refused("domain name longer than 255 bytes")),
    })
}

/// `out` must be `addr_len(addr)` bytes. An IPv4-mapped address goes out as IPv4.
pub(crate) fn write_addr(out: &mut Writer<'_>, addr: &Address) {
    match addr {
        Address::Socket(sock) => match unmap(sock.ip()) {
            IpAddr::V4(ip) => {
                out.put(&[ATYP_IPV4]);
                out.put(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.put(&[ATYP_IPV6]);
                out.put(&ip.octets());
            }
        },
        Address::Domain(host, _) => {
            out.put(&[ATYP_DOMAIN, host.len() as u8]);
            out.put(host.as_bytes());
        }
    }
    out.put(&addr.port().to_be_bytes());
}

async fn read_addr<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<Address> {
    match io.read_u8().await? {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            io.read_exact(&mut octets).await?;
            let port = io.read_u16().await?;
            Ok(Address::Socket(SocketAddr::new(
                Ipv4Addr::from(octets).into(),
                port,
            )))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            io.read_exact(&mut octets).await?;
            let port = io.read_u16().await?;
            Ok(Address::from(SocketAddr::new(
                Ipv6Addr::from(octets).into(),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let len = usize::from(io.read_u8().await?);
            let mut name = [0u8; 255];
            let name = name
                .get_mut(..len)
                .ok_or_else(|| refused("invalid domain length"))?;
            io.read_exact(name).await?;
            let port = io.read_u16().await?;
            if name.is_empty() {
                return Err(refused("empty domain name"));
            }
            Ok(dst_address(&String::from_utf8_lossy(name), port))
        }
        _ => Err(refused("address type not supported")),
    }
}

enum Method<'a> {
    None,
    Password(Option<&'a Authenticator>),
}

/// `transport/socks5.ServerHandshake`: the offered methods are only counted,
/// and any other command, or an unknown address type, is closed with no
/// reply. The reply to CONNECT and UDP ASSOCIATE is [`reply_success`], sent
/// by the caller before the outbound is dialed.
pub(crate) async fn server_handshake<S>(
    io: &mut S,
    auth: Option<&Authenticator>,
    host: Option<&HostCredential>,
) -> io::Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    io.read_exact(&mut head).await?;
    let count = usize::from(head[1]);
    let mut methods = [0u8; 255];
    let methods = methods
        .get_mut(..count)
        .ok_or_else(|| refused("invalid method count"))?;
    io.read_exact(methods).await?;

    let method = match auth {
        Some(auth) => Method::Password(Some(auth)),
        None if methods == [2] => Method::Password(None),
        None => Method::None,
    };

    let mut client = Client::default();
    match method {
        Method::None => io.write_all(&[5, 0]).await?,
        Method::Password(auth) => {
            io.write_all(&[5, 2]).await?;
            let mut header = [0u8; 2];
            io.read_exact(&mut header).await?;
            let user_len = usize::from(header[1]);
            if user_len == 0 {
                io.write_all(&[1, 1]).await?;
                return Err(refused("auth failed"));
            }
            let mut buf = [0u8; 255];
            let name = buf
                .get_mut(..user_len)
                .ok_or_else(|| refused("invalid user length"))?;
            io.read_exact(name).await?;
            let user = String::from_utf8_lossy(name).into_owned();

            let pass_len = usize::from(io.read_u8().await?);
            if pass_len == 0 {
                io.write_all(&[1, 1]).await?;
                return Err(refused("auth failed"));
            }
            let pass = buf
                .get_mut(..pass_len)
                .ok_or_else(|| refused("invalid password length"))?;
            io.read_exact(pass).await?;
            let pass = String::from_utf8_lossy(pass);

            client = if host.is_some_and(|host| host.matches(&user, &pass)) {
                Client::host()
            } else if auth.is_some_and(|auth| !auth.verify(&user, &pass)) {
                io.write_all(&[1, 1]).await?;
                return Err(refused("auth failed"));
            } else {
                Client::named(&user)
            };
            io.write_all(&[1, 0]).await?;
        }
    }

    let mut request = [0u8; 3];
    io.read_exact(&mut request).await?;
    let command = match request[1] {
        CMD_CONNECT => Command::Connect,
        CMD_UDP_ASSOCIATE => Command::UdpAssociate,
        _ => {
            read_addr(io).await?;
            return Err(refused("command not supported"));
        }
    };
    let target = read_addr(io).await?;

    Ok(Request {
        command,
        target,
        client,
    })
}

/// A UDP client sends its first datagram as soon as it reads this, so a UDP
/// ASSOCIATE registers before it is sent.
pub(crate) async fn reply_success<S>(io: &mut S, local: SocketAddr) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bound = Address::Socket(local);
    let mut reply = [0u8; 3 + 1 + 16 + 2];
    let len = 3 + addr_len(&bound)?;
    {
        let mut out = Writer::new(&mut reply);
        out.put(&[5, 0, 0]);
        write_addr(&mut out, &bound);
    }
    io.write_all(reply.get(..len).unwrap_or_default()).await
}

/// Splits `RSV RSV FRAG ATYP DST.ADDR DST.PORT` off a datagram. Reserved
/// bytes must be zero and a fragmented datagram is refused, as upstream does.
pub(crate) fn decode_udp(packet: &[u8]) -> Option<(Address, usize)> {
    let [0, 0, 0, atyp, rest @ ..] = packet else {
        return None;
    };
    let (addr, used) = match *atyp {
        ATYP_IPV4 => {
            let (octets, tail) = rest.split_first_chunk::<4>()?;
            let (port, _) = tail.split_first_chunk::<2>()?;
            (
                Address::Socket(SocketAddr::new(
                    Ipv4Addr::from(*octets).into(),
                    u16::from_be_bytes(*port),
                )),
                4 + 2,
            )
        }
        ATYP_IPV6 => {
            let (octets, tail) = rest.split_first_chunk::<16>()?;
            let (port, _) = tail.split_first_chunk::<2>()?;
            (
                Address::from(SocketAddr::new(
                    Ipv6Addr::from(*octets).into(),
                    u16::from_be_bytes(*port),
                )),
                16 + 2,
            )
        }
        ATYP_DOMAIN => {
            let (&len, tail) = rest.split_first()?;
            let len = usize::from(len);
            let name = tail.get(..len)?;
            let (port, _) = tail.get(len..)?.split_first_chunk::<2>()?;
            (
                dst_address(&String::from_utf8_lossy(name), u16::from_be_bytes(*port)),
                1 + len + 2,
            )
        }
        _ => return None,
    };
    Some((addr, 4 + used))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{ListenSpec, Policy};

    fn policy(user: &str, pass: &str) -> Policy {
        Policy::from_spec(&ListenSpec {
            authentication: vec![(user.into(), pass.into())],
            ..Default::default()
        })
    }

    fn local() -> SocketAddr {
        "127.0.0.1:7890".parse().unwrap()
    }

    async fn run(client: &[u8], auth: Option<&Authenticator>) -> (io::Result<Request>, Vec<u8>) {
        run_as(client, auth, None).await
    }

    async fn run_as(
        client: &[u8],
        auth: Option<&Authenticator>,
        host: Option<&HostCredential>,
    ) -> (io::Result<Request>, Vec<u8>) {
        let (mut near, far) = tokio::io::duplex(1024);
        let mut far = far;
        near.write_all(client).await.unwrap();
        near.shutdown().await.unwrap();
        let result = match server_handshake(&mut far, auth, host).await {
            Ok(request) => reply_success(&mut far, local()).await.map(|()| request),
            Err(err) => Err(err),
        };
        drop(far);
        let mut reply = Vec::new();
        near.read_to_end(&mut reply).await.unwrap();
        (result, reply)
    }

    #[tokio::test]
    async fn connect_without_auth_replies_with_the_local_address() {
        let (result, reply) = run(
            &[5, 1, 0, 5, 1, 0, 3, 3, b'a', b'.', b'b', 0x01, 0xbb],
            None,
        )
        .await;
        let request = result.unwrap();
        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.target, Address::new("a.b", 443));
        assert_eq!(request.client, Client::default());
        assert_eq!(reply, [5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0x1e, 0xd2]);
    }

    #[tokio::test]
    async fn a_client_offering_only_password_auth_is_accepted_with_any_credentials() {
        let wire = [5, 1, 2, 1, 1, b'u', 1, b'p', 5, 1, 0, 1, 1, 2, 3, 4, 0, 80];
        let (result, reply) = run(&wire, None).await;
        let request = result.unwrap();
        assert_eq!(request.client, Client::named("u"));
        assert_eq!(request.target, Address::new("1.2.3.4", 80));
        assert_eq!(reply.get(..4), Some(&[5, 2, 1, 0][..]));
    }

    #[tokio::test]
    async fn configured_auth_refuses_a_wrong_password_with_0x01_0x01() {
        let policy = policy("u", "p");
        let auth = policy.authenticator(std::net::Ipv4Addr::LOCALHOST.into());
        let (result, reply) = run(&[5, 1, 2, 1, 1, b'u', 1, b'x'], auth).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 2, 1, 1]);
        let (result, reply) = run(
            &[5, 1, 2, 1, 1, b'u', 1, b'p', 5, 1, 0, 1, 9, 9, 9, 9, 0, 1],
            auth,
        )
        .await;
        assert_eq!(result.unwrap().client, Client::named("u"));
        assert_eq!(reply.get(..4), Some(&[5, 2, 1, 0][..]));
    }

    #[tokio::test]
    async fn the_host_credential_passes_configured_auth_and_names_no_user() {
        let policy = Policy::from_spec(&ListenSpec {
            authentication: vec![("u".into(), "p".into())],
            host_credential: Some(("h".into(), "s".into())),
            ..Default::default()
        });
        let loopback = std::net::Ipv4Addr::LOCALHOST.into();
        let (auth, host) = (policy.authenticator(loopback), policy.host(loopback));
        let wire = [5, 1, 2, 1, 1, b'h', 1, b's', 5, 1, 0, 1, 9, 9, 9, 9, 0, 1];
        let (result, reply) = run_as(&wire, auth, host).await;
        assert_eq!(result.unwrap().client, Client::host());
        assert_eq!(reply.get(..4), Some(&[5, 2, 1, 0][..]));
        let (result, reply) = run_as(&[5, 1, 2, 1, 1, b'h', 1, b'x'], auth, host).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 2, 1, 1]);
    }

    #[tokio::test]
    async fn empty_user_or_password_is_refused() {
        let policy = policy("u", "p");
        let auth = policy.authenticator(std::net::Ipv4Addr::LOCALHOST.into());
        let (result, reply) = run(&[5, 1, 2, 1, 0], auth).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 2, 1, 1]);
        let (result, reply) = run(&[5, 1, 2, 1, 1, b'u', 0], auth).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 2, 1, 1]);
    }

    #[tokio::test]
    async fn bind_and_unknown_address_types_close_without_a_reply() {
        let (result, reply) = run(&[5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80], None).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 0]);
        let (result, reply) = run(&[5, 1, 0, 5, 1, 0, 9, 1, 2, 3, 4, 0, 80], None).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 0]);
    }

    #[tokio::test]
    async fn an_empty_domain_and_a_truncated_request_are_errors() {
        let (result, _) = run(&[5, 1, 0, 5, 1, 0, 3, 0, 0, 80], None).await;
        assert!(result.is_err());
        let (result, _) = run(&[5, 1, 0, 5, 1], None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn the_udp_associate_reply_carries_the_ipv6_local_address() {
        let (mut near, mut far) = tokio::io::duplex(1024);
        near.write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let v6: SocketAddr = "[::1]:7890".parse().unwrap();
        let request = server_handshake(&mut far, None, None).await.unwrap();
        assert_eq!(request.command, Command::UdpAssociate);
        reply_success(&mut far, v6).await.unwrap();
        drop(far);
        let mut reply = Vec::new();
        near.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply.get(2..5), Some(&[5, 0, 0][..]));
        assert_eq!(reply.get(5), Some(&4));
        assert_eq!(reply.len(), 2 + 3 + 1 + 16 + 2);
    }

    #[test]
    fn udp_datagrams_decode_for_each_address_type() {
        let mut v4 = vec![0, 0, 0, 1, 8, 8, 4, 4, 0, 53];
        v4.extend_from_slice(b"payload");
        let (addr, used) = decode_udp(&v4).unwrap();
        assert_eq!(addr, Address::new("8.8.4.4", 53));
        assert_eq!(v4.get(used..), Some(&b"payload"[..]));

        let domain = [0, 0, 0, 3, 3, b'a', b'.', b'b', 1, 187, 9];
        let (addr, used) = decode_udp(&domain).unwrap();
        assert_eq!(addr, Address::new("a.b", 443));
        assert_eq!(used, domain.len() - 1);

        let mut v6 = vec![0, 0, 0, 4];
        v6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6.extend_from_slice(&[0, 80]);
        assert_eq!(decode_udp(&v6).unwrap().0, Address::new("::1", 80));
    }

    #[test]
    fn fragmented_reserved_and_truncated_datagrams_are_refused() {
        assert!(decode_udp(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 80]).is_none());
        assert!(decode_udp(&[0, 1, 0, 1, 1, 2, 3, 4, 0, 80]).is_none());
        assert!(decode_udp(&[1, 0, 0, 1, 1, 2, 3, 4, 0, 80]).is_none());
        assert!(decode_udp(&[0, 0, 0, 1, 1, 2, 3, 4, 0]).is_none());
        assert!(decode_udp(&[0, 0, 0, 3, 9, b'a', 0, 80]).is_none());
        assert!(decode_udp(&[0, 0, 0, 7, 1, 2, 3, 4, 0, 80]).is_none());
        assert!(decode_udp(&[0, 0, 0, 1]).is_none());
    }

    #[test]
    fn headers_encode_in_place_and_round_trip() {
        for addr in [
            Address::new("1.2.3.4", 9),
            Address::new("2001:db8::1", 9),
            Address::new("example.com", 9),
        ] {
            let len = 3 + addr_len(&addr).unwrap();
            let mut buf = vec![0u8; len];
            let mut out = Writer::new(&mut buf);
            out.put(&[0, 0, 0]);
            write_addr(&mut out, &addr);
            assert_eq!(decode_udp(&buf), Some((addr, len)));
        }
    }

    #[test]
    fn an_overlong_domain_cannot_be_encoded() {
        assert!(addr_len(&Address::new(&"a".repeat(256), 1)).is_err());
    }
}
