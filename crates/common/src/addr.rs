use std::fmt;
use std::net::{IpAddr, SocketAddr};

use compact_str::CompactString;
use serde::{Deserialize, Serialize};

/// Inline up to 24 bytes, so most domain names do not touch the heap.
pub type Host = CompactString;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    Socket(SocketAddr),
    Domain(Host, u16),
}

impl Address {
    /// An IP literal becomes `Socket` and an IPv4-mapped address is unmapped,
    /// so one destination has one spelling in the NAT and DNS tables.
    pub fn new(host: &str, port: u16) -> Self {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match bare.parse::<IpAddr>() {
            Ok(ip) => Address::Socket(SocketAddr::new(unmap(ip), port)),
            Err(_) => Address::Domain(CompactString::from(host), port),
        }
    }

    /// Reads `host:port` and `[v6]:port`.
    pub fn parse(text: &str) -> Option<Self> {
        let (host, port) = split_host_port(text)?;
        Some(Address::new(host, port))
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::Socket(addr) => addr.port(),
            Address::Domain(_, port) => *port,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Address::Socket(addr) => Some(addr.ip()),
            Address::Domain(..) => None,
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            Address::Socket(_) => None,
            Address::Domain(host, _) => Some(host),
        }
    }

    /// The host without the port, in the spelling a user would type.
    pub fn host_string(&self) -> String {
        match self {
            Address::Socket(addr) => addr.ip().to_string(),
            Address::Domain(host, _) => host.to_string(),
        }
    }

    pub fn with_port(&self, port: u16) -> Self {
        match self {
            Address::Socket(addr) => Address::Socket(SocketAddr::new(addr.ip(), port)),
            Address::Domain(host, _) => Address::Domain(host.clone(), port),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Socket(addr) => write!(f, "{addr}"),
            Address::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        Address::Socket(SocketAddr::new(unmap(addr.ip()), addr.port()))
    }
}

pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// An IP4P record keeps an IPv4 address and port in `2001:0::/32`: the port is bytes 10 and 11, the
/// address bytes 12 to 15.
pub fn ip4p_target(addr: SocketAddr) -> Option<SocketAddr> {
    let IpAddr::V6(v6) = addr.ip() else {
        return None;
    };
    let octets = v6.octets();
    let [0x20, 0x01, 0x00, 0x00, _, _, _, _, _, _, p0, p1, a, b, c, d] = octets else {
        return None;
    };
    Some(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)),
        u16::from_be_bytes([p0, p1]),
    ))
}

/// Splits `host:port` the way Go's `net.SplitHostPort` does: a bare IPv6 address
/// without brackets is not a host and port.
pub fn split_host_port(text: &str) -> Option<(&str, u16)> {
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let (host, port) = text.rsplit_once(':')?;
    if host.contains(':') {
        return None;
    }
    Some((host, port.parse().ok()?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `ip-version` of a proxy, which decides the families its server resolves to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IpVersion {
    #[default]
    Dual,
    Ipv4,
    Ipv6,
    Ipv4Prefer,
    Ipv6Prefer,
}

impl IpVersion {
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "" | "dual" => IpVersion::Dual,
            "ipv4" => IpVersion::Ipv4,
            "ipv6" => IpVersion::Ipv6,
            "ipv4-prefer" => IpVersion::Ipv4Prefer,
            "ipv6-prefer" => IpVersion::Ipv6Prefer,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_become_socket_addresses_and_unmap() {
        assert_eq!(
            Address::new("::ffff:1.2.3.4", 80),
            Address::Socket("1.2.3.4:80".parse().unwrap())
        );
        assert_eq!(
            Address::new("[::1]", 80),
            Address::Socket("[::1]:80".parse().unwrap())
        );
        assert_eq!(
            Address::new("example.com", 80).domain(),
            Some("example.com")
        );
    }

    #[test]
    fn split_host_port_rejects_a_bare_ipv6_address() {
        assert_eq!(split_host_port("::1:80"), None);
        assert_eq!(split_host_port("[::1]:80"), Some(("::1", 80)));
        assert_eq!(split_host_port("a.b:80"), Some(("a.b", 80)));
        assert_eq!(split_host_port("a.b"), None);
    }

    #[test]
    fn display_brackets_ipv6() {
        assert_eq!(Address::new("::1", 80).to_string(), "[::1]:80");
        assert_eq!(Address::new("a.b", 443).to_string(), "a.b:443");
    }
}

#[cfg(test)]
mod ip4p_tests {
    use super::*;

    fn target(text: &str) -> Option<String> {
        ip4p_target(text.parse().unwrap()).map(|addr| addr.to_string())
    }

    #[test]
    fn a_2001_0_record_carries_an_ipv4_address_and_port() {
        assert_eq!(
            target("[2001:0:0:0:0:1bb:cb00:7101]:9").as_deref(),
            Some("203.0.113.1:443")
        );
        assert_eq!(
            target("[2001::1f90:c0a8:1]:1").as_deref(),
            Some("192.168.0.1:8080")
        );
    }

    #[test]
    fn other_addresses_are_left_alone() {
        assert_eq!(target("[2001:db8::1]:9"), None);
        assert_eq!(target("[2001:1::1]:9"), None);
        assert_eq!(target("32.1.0.0:9"), None);
        assert_eq!(target("[::ffff:32.1.0.0]:9"), None);
    }
}
