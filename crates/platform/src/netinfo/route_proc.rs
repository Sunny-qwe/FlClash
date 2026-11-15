#![cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(
        dead_code,
        reason = "only the parsers run on hosts without /proc/net/route"
    )
)]

use super::select::{Candidate, pick};

const RTF_UP: u32 = 0x1;
const RTF_REJECT: u32 = 0x200;

pub fn parse_route_v4(text: &str) -> Vec<Candidate> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [name, destination, _, flags, _, _, metric, mask, ..] = fields.as_slice() else {
                return None;
            };
            let flags = u32::from_str_radix(flags, 16).ok()?;
            let default = u32::from_str_radix(destination, 16).ok()? == 0
                && u32::from_str_radix(mask, 16).ok()? == 0;
            (default && flags & RTF_UP != 0).then(|| Candidate {
                name: (*name).to_string(),
                metric: metric.parse().unwrap_or(u32::MAX),
                scoped: false,
            })
        })
        .collect()
}

pub fn parse_route_v6(text: &str) -> Vec<Candidate> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [destination, prefix, _, _, _, metric, _, _, flags, name] = fields.as_slice()
            else {
                return None;
            };
            let flags = u32::from_str_radix(flags, 16).ok()?;
            let default = destination.bytes().all(|b| b == b'0')
                && u32::from_str_radix(prefix, 16).ok()? == 0;
            (default && flags & RTF_UP != 0 && flags & RTF_REJECT == 0).then(|| Candidate {
                name: (*name).to_string(),
                metric: u32::from_str_radix(metric, 16).unwrap_or(u32::MAX),
                scoped: false,
            })
        })
        .collect()
}

pub fn default_interface_name(excluded: &[String]) -> Option<String> {
    let v4 = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    if let Some(found) = pick(&parse_route_v4(&v4), excluded) {
        return Some(found.name.clone());
    }
    let v6 = std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default();
    pick(&parse_route_v6(&v6), excluded).map(|found| found.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V4: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
        tun0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
        wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
        eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
        eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
        eth1\t00000000\t0101A8C0\t0002\t0\t0\t10\t00000000\t0\t0\t0\n";

    const V6: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
        fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n\
        00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
        00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n\
        20010db8000000000000000000000000 20 00000000000000000000000000000000 00 \
        00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n";

    #[test]
    fn only_up_default_routes_are_candidates() {
        let names: Vec<_> = parse_route_v4(V4).into_iter().map(|c| c.name).collect();
        assert_eq!(names, ["tun0", "wlan0", "eth0"]);
    }

    #[test]
    fn the_tunnel_is_skipped_and_the_lowest_metric_wins() {
        let candidates = parse_route_v4(V4);
        let excluded = vec!["tun0".to_string()];
        assert_eq!(
            pick(&candidates, &excluded).map(|c| c.name.as_str()),
            Some("eth0")
        );
    }

    #[test]
    fn ipv6_defaults_skip_the_reject_route() {
        let candidates = parse_route_v6(V6);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].name, "eth0");
        assert_eq!(candidates[0].metric, 0x400);
    }
}
