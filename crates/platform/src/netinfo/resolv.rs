use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

pub fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        if line.starts_with([';', '#']) {
            continue;
        }
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(server) = fields.next().and_then(parse_server) {
            servers.push(server);
        }
    }
    servers
}

fn parse_server(text: &str) -> Option<SocketAddr> {
    let (host, zone) = match text.split_once('%') {
        Some((host, zone)) => (host, Some(zone)),
        None => (text, None),
    };
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => Some(SocketAddr::new(IpAddr::V4(v4), 53)),
        IpAddr::V6(v6) => Some(SocketAddr::V6(SocketAddrV6::new(
            v6,
            53,
            0,
            scope_of(v6, zone),
        ))),
    }
}

fn scope_of(addr: Ipv6Addr, zone: Option<&str>) -> u32 {
    let Some(zone) = zone else {
        return 0;
    };
    zone.parse().ok().unwrap_or_else(|| {
        let linked = (addr.segments()[0] & 0xffc0) == 0xfe80;
        crate::interface_by_name(zone)
            .filter(|_| linked)
            .map_or(0, |info| info.index)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameservers_come_out_in_file_order() {
        let text = "# generated\n;comment\nsearch lan\nnameserver 192.168.1.1\n\
            nameserver\nnameserver not-an-ip\n  nameserver 2001:4860:4860::8888 \noptions edns0\n";
        let servers = parse_resolv_conf(text);
        assert_eq!(
            servers,
            vec![
                "192.168.1.1:53".parse::<SocketAddr>().unwrap(),
                "[2001:4860:4860::8888]:53".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn a_numeric_zone_becomes_the_scope() {
        let servers = parse_resolv_conf("nameserver fe80::1%7\n");
        let Some(SocketAddr::V6(addr)) = servers.first() else {
            panic!("expected one IPv6 server");
        };
        assert_eq!(addr.scope_id(), 7);
        assert_eq!(addr.port(), 53);
    }

    #[test]
    fn an_empty_file_has_no_servers() {
        assert!(parse_resolv_conf("").is_empty());
    }
}
