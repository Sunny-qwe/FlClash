use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

/// Reads a Windows `SOCKADDR_IN` or `SOCKADDR_IN6`, whose layout is fixed by the ABI.
pub fn sockaddr_from_bytes(bytes: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes(bytes.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    match family {
        AF_INET => {
            let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        AF_INET6 => {
            let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            let scope = u32::from_ne_bytes(bytes.get(24..28)?.try_into().ok()?);
            let addr = Ipv6Addr::from(octets);
            Some(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, scope)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_families_are_read() {
        let mut v4 = vec![0u8; 16];
        v4[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        v4[2..4].copy_from_slice(&53u16.to_be_bytes());
        v4[4..8].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            sockaddr_from_bytes(&v4),
            Some("10.0.0.1:53".parse().unwrap())
        );

        let mut v6 = vec![0u8; 28];
        v6[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        v6[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        v6[24..28].copy_from_slice(&5u32.to_ne_bytes());
        let Some(SocketAddr::V6(parsed)) = sockaddr_from_bytes(&v6) else {
            panic!("expected an IPv6 address");
        };
        assert_eq!((*parsed.ip(), parsed.scope_id()), (Ipv6Addr::LOCALHOST, 5));
    }

    #[test]
    fn short_or_foreign_input_is_rejected() {
        assert_eq!(sockaddr_from_bytes(&[2, 0, 0]), None);
        assert_eq!(sockaddr_from_bytes(&[17, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(sockaddr_from_bytes(&AF_INET6.to_ne_bytes()), None);
    }
}
