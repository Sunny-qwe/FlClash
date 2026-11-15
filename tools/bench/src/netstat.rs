//! Diagnostic network counters for `--net-counters`, read only at the two edges of a window: each namespace's
//! `Ip`, `IpExt`, `Tcp` and `TcpExt` counters, and the packets the far namespace's link carried.

use std::collections::BTreeMap;

use crate::load::Metrics;

type Counters = BTreeMap<String, u64>;

const GROUPS: [&str; 4] = ["Ip", "IpExt", "Tcp", "TcpExt"];

pub struct Edge {
    near: Counters,
    far: Option<(Counters, Link)>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Link {
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
}

pub fn edge(far: Option<&str>) -> Edge {
    Edge {
        near: counters(),
        far: far.and_then(|name| crate::isolate::in_netns(name, || (counters(), link()))),
    }
}

// `/proc/net` follows the thread group leader's namespace; a thread that entered another one reads its own.
fn proc_net(file: &str) -> String {
    std::fs::read_to_string(format!("/proc/thread-self/net/{file}")).unwrap_or_default()
}

fn counters() -> Counters {
    let mut out = Counters::new();
    for file in ["snmp", "netstat"] {
        parse(&proc_net(file), &mut out);
    }
    out
}

fn parse(text: &str, out: &mut Counters) {
    let mut lines = text.lines();
    while let (Some(names), Some(values)) = (lines.next(), lines.next()) {
        let (Some((group, names)), Some((_, values))) =
            (names.split_once(':'), values.split_once(':'))
        else {
            continue;
        };
        if !GROUPS.contains(&group) {
            continue;
        }
        for (name, value) in names.split_whitespace().zip(values.split_whitespace()) {
            if let Ok(value) = value.parse() {
                out.insert(format!("{group}{name}"), value);
            }
        }
    }
}

fn link() -> Link {
    parse_link(&proc_net("dev"))
}

/// Sums every interface but loopback: in the far namespace that is the veth to the core.
fn parse_link(text: &str) -> Link {
    let mut sum = Link::default();
    for line in text.lines().skip(2) {
        let Some((name, fields)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let fields: Vec<u64> = fields
            .split_whitespace()
            .filter_map(|f| f.parse().ok())
            .collect();
        if let [
            rx_bytes,
            rx_packets,
            _,
            _,
            _,
            _,
            _,
            _,
            tx_bytes,
            tx_packets,
            ..,
        ] = fields[..]
        {
            sum.rx_bytes += rx_bytes;
            sum.rx_packets += rx_packets;
            sum.tx_bytes += tx_bytes;
            sum.tx_packets += tx_packets;
        }
    }
    sum
}

/// `payload` is the bytes the workload moved in the window.
pub fn metrics(before: &Edge, after: &Edge, payload: u64, m: &mut Metrics) {
    let mb = payload as f64 / 1e6;
    if mb <= 0.0 {
        return;
    }
    rates("near", &before.near, &after.near, mb, m);
    let (Some((far_before, link_before)), Some((far_after, link_after))) =
        (&before.far, &after.far)
    else {
        return;
    };
    rates("far", far_before, far_after, mb, m);
    for (direction, bytes, packets) in [
        (
            "to_core",
            link_after.tx_bytes.saturating_sub(link_before.tx_bytes),
            link_after.tx_packets.saturating_sub(link_before.tx_packets),
        ),
        (
            "to_server",
            link_after.rx_bytes.saturating_sub(link_before.rx_bytes),
            link_after.rx_packets.saturating_sub(link_before.rx_packets),
        ),
    ] {
        if packets > 0 {
            m.insert(
                format!("link_{direction}_bytes_per_packet"),
                bytes as f64 / packets as f64,
            );
            m.insert(
                format!("link_{direction}_packets_per_mb"),
                packets as f64 / mb,
            );
        }
    }
}

fn rates(side: &str, before: &Counters, after: &Counters, mb: f64, m: &mut Metrics) {
    for (name, end) in after {
        let delta = end.saturating_sub(before.get(name).copied().unwrap_or(*end));
        if delta > 0 {
            m.insert(format!("nstat_{side}_{name}_per_mb"), delta as f64 / mb);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETSTAT: &str = "TcpExt: SyncookiesSent TCPPureAcks TCPHPAcks\nTcpExt: 0 120 4000\n\
        MPTcpExt: MPCapableSYNRX\nMPTcpExt: 7\nIpExt: InOctets\nIpExt: 9000\n";
    const SNMP: &str =
        "Tcp: RtoAlgorithm MaxConn OutSegs\nTcp: 1 -1 500\nUdp: InDatagrams\nUdp: 3\n";

    #[test]
    fn keeps_the_ip_and_tcp_groups_and_skips_what_does_not_parse() {
        let mut out = Counters::new();
        parse(NETSTAT, &mut out);
        parse(SNMP, &mut out);
        assert_eq!(out["TcpExtTCPPureAcks"], 120);
        assert_eq!(out["IpExtInOctets"], 9000);
        assert_eq!(out["TcpOutSegs"], 500);
        assert!(!out.contains_key("TcpMaxConn"));
        assert!(
            !out.keys()
                .any(|k| k.starts_with("MPTcp") || k.starts_with("Udp"))
        );
    }

    #[test]
    fn counters_that_moved_are_reported_per_payload_mb() {
        let side = |acks: u64, octets: u64, link: Link| {
            let mut counters = Counters::new();
            counters.insert("TcpExtTCPPureAcks".into(), acks);
            counters.insert("IpExtInOctets".into(), octets);
            (counters, link)
        };
        let before = Edge {
            near: side(10, 5, Link::default()).0,
            far: Some(side(100, 7, Link::default())),
        };
        let moved = Link {
            rx_bytes: 6_600,
            rx_packets: 100,
            tx_bytes: 4_000_000,
            tx_packets: 250,
        };
        let after = Edge {
            near: side(10, 5, Link::default()).0,
            far: Some(side(300, 7, moved)),
        };
        let mut m = Metrics::new();
        metrics(&before, &after, 4_000_000, &mut m);
        assert_eq!(m["nstat_far_TcpExtTCPPureAcks_per_mb"], 50.0);
        assert!(!m.contains_key("nstat_far_IpExtInOctets_per_mb"));
        assert!(!m.keys().any(|k| k.starts_with("nstat_near_")));
        assert_eq!(m["link_to_core_bytes_per_packet"], 16_000.0);
        assert_eq!(m["link_to_core_packets_per_mb"], 62.5);
        assert_eq!(m["link_to_server_bytes_per_packet"], 66.0);
    }

    #[test]
    fn link_counters_leave_loopback_out() {
        let text = "Inter-|   Receive                                                |  Transmit\n \
            face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
            lo: 900 9 0 0 0 0 0 0 900 9 0 0 0 0 0 0\n \
            cbf12: 6600 100 0 0 0 0 0 0 4000000 250 0 0 0 0 0 0\n";
        assert_eq!(
            parse_link(text),
            Link {
                rx_bytes: 6_600,
                rx_packets: 100,
                tx_bytes: 4_000_000,
                tx_packets: 250,
            }
        );
    }
}
