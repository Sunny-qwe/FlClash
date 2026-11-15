use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use concord_common::Address;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ctx::{dst_address, user_of};
use crate::spec::Authenticator;

const CMD_CONNECT: u8 = 1;
const GRANTED: u8 = 90;
const IDENTD_MISMATCHED: u8 = 93;
const MAX_FIELD: usize = 256;

pub(crate) struct Request {
    pub(crate) target: Address,
    pub(crate) user: Option<Arc<str>>,
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn read_until_null<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match io.read_u8().await? {
            0 => return Ok(out),
            _ if out.len() >= MAX_FIELD => return Err(refused("field too long")),
            byte => out.push(byte),
        }
    }
}

/// `0.0.0.x` with `x` non-zero marks a SOCKS4a request that carries a host name.
fn is_reserved(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    (a, b, c) == (0, 0, 0) && d != 0
}

/// `transport/socks4.ServerHandshake`. SOCKS4 has no password, so with
/// authentication configured the user id is verified against an empty password.
/// The reply goes out before the outbound is dialed, and also when auth fails.
pub(crate) async fn server_handshake<S>(
    io: &mut S,
    auth: Option<&Authenticator>,
) -> io::Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 8];
    io.read_exact(&mut head).await?;
    let [version, command, p1, p2, i1, i2, i3, i4] = head;
    if version != 4 {
        return Err(refused("version code mismatched"));
    }
    if command != CMD_CONNECT {
        return Err(refused("command not supported"));
    }
    let ip = Ipv4Addr::new(i1, i2, i3, i4);
    let port = u16::from_be_bytes([p1, p2]);

    let user = String::from_utf8_lossy(&read_until_null(io).await?).into_owned();
    let host = if is_reserved(ip) {
        String::from_utf8_lossy(&read_until_null(io).await?).into_owned()
    } else {
        String::new()
    };
    let target = if host.is_empty() {
        Address::from(SocketAddr::new(ip.into(), port))
    } else {
        dst_address(&host, port)
    };

    let granted = auth.is_none_or(|auth| auth.verify(&user, ""));
    let code = if granted { GRANTED } else { IDENTD_MISMATCHED };
    io.write_all(&[0, code, p1, p2, i1, i2, i3, i4]).await?;
    if !granted {
        return Err(refused(
            "request rejected because the client program and identd report different user-ids",
        ));
    }
    Ok(Request {
        target,
        user: user_of(&user),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{ListenSpec, Policy};

    async fn run(client: &[u8], auth: Option<&Authenticator>) -> (io::Result<Request>, Vec<u8>) {
        let (mut near, mut far) = tokio::io::duplex(1024);
        near.write_all(client).await.unwrap();
        near.shutdown().await.unwrap();
        let result = server_handshake(&mut far, auth).await;
        drop(far);
        let mut reply = Vec::new();
        near.read_to_end(&mut reply).await.unwrap();
        (result, reply)
    }

    #[tokio::test]
    async fn connect_to_an_ip_grants_and_echoes_the_destination() {
        let (result, reply) = run(&[4, 1, 0x01, 0xbb, 1, 2, 3, 4, b'b', b'o', b'b', 0], None).await;
        let request = result.unwrap();
        assert_eq!(request.target, Address::new("1.2.3.4", 443));
        assert_eq!(request.user.as_deref(), Some("bob"));
        assert_eq!(reply, [0, 90, 0x01, 0xbb, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn socks4a_reads_the_host_name_after_the_user_id() {
        let mut wire = vec![4, 1, 0, 80, 0, 0, 0, 1, 0];
        wire.extend_from_slice(b"example.com\0");
        let (result, reply) = run(&wire, None).await;
        let request = result.unwrap();
        assert_eq!(request.target, Address::new("example.com", 80));
        assert_eq!(request.user, None);
        assert_eq!(reply, [0, 90, 0, 80, 0, 0, 0, 1]);
    }

    #[tokio::test]
    async fn auth_failure_replies_93_and_errors() {
        let policy = Policy::from_spec(&ListenSpec {
            authentication: vec![("bob".into(), "secret".into())],
            ..Default::default()
        });
        let auth = policy.authenticator(std::net::Ipv4Addr::LOCALHOST.into());
        let (result, reply) = run(&[4, 1, 0, 80, 1, 2, 3, 4, b'b', b'o', b'b', 0], auth).await;
        assert!(result.is_err());
        assert_eq!(reply, [0, 93, 0, 80, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn a_user_with_an_empty_password_passes_the_user_id_check() {
        let policy = Policy::from_spec(&ListenSpec {
            authentication: vec![("bob".into(), String::new())],
            ..Default::default()
        });
        let auth = policy.authenticator(std::net::Ipv4Addr::LOCALHOST.into());
        let (result, _) = run(&[4, 1, 0, 80, 1, 2, 3, 4, b'b', b'o', b'b', 0], auth).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn bind_a_wrong_version_and_an_unterminated_user_id_are_errors_without_a_reply() {
        let (result, reply) = run(&[4, 2, 0, 80, 1, 2, 3, 4, 0], None).await;
        assert!(result.is_err());
        assert!(reply.is_empty());
        let (result, reply) = run(&[5, 1, 0, 80, 1, 2, 3, 4, 0], None).await;
        assert!(result.is_err());
        assert!(reply.is_empty());
        let mut long = vec![4, 1, 0, 80, 1, 2, 3, 4];
        long.extend(std::iter::repeat_n(b'x', 300));
        let (result, reply) = run(&long, None).await;
        assert!(result.is_err());
        assert!(reply.is_empty());
    }
}
