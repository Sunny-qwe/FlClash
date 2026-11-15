#[cfg(test)]
use crate::options::to_bits;
use crate::options::{IdRange, Prefix, TunOptions, from_bits};

const USER_END: u32 = u32::MAX - 1;

fn interval(prefix: &Prefix) -> (u128, u128) {
    prefix.range()
}

fn merge(mut spans: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    spans.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn subtract_spans(keep: Vec<(u128, u128)>, remove: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut out = Vec::with_capacity(keep.len());
    for (mut start, end) in keep {
        let mut open = true;
        for &(r_start, r_end) in remove {
            if r_end < start || r_start > end {
                continue;
            }
            if r_start > start {
                out.push((start, r_start - 1));
            }
            if r_end >= end {
                open = false;
                break;
            }
            start = r_end + 1;
        }
        if open {
            out.push((start, end));
        }
    }
    out
}

fn span_to_prefixes(v4: bool, mut start: u128, end: u128, out: &mut Vec<Prefix>) {
    let width: u32 = if v4 { 32 } else { 128 };
    loop {
        let alignment = if start == 0 {
            width
        } else {
            start.trailing_zeros().min(width)
        };
        let mut bits = alignment;
        while bits > 0 {
            let last = if bits >= 128 {
                u128::MAX
            } else {
                start + ((1u128 << bits) - 1)
            };
            if last <= end {
                break;
            }
            bits -= 1;
        }
        if let Some(prefix) = Prefix::new(from_bits(v4, start), (width - bits) as u8) {
            out.push(prefix);
        }
        let step = if bits >= 128 {
            None
        } else {
            Some(1u128 << bits)
        };
        match step.and_then(|step| start.checked_add(step)) {
            Some(next) if next <= end => start = next,
            _ => break,
        }
    }
}

/// `include` minus `exclude`, as the smallest list of prefixes, for one address family at a time.
pub fn subtract(include: &[Prefix], exclude: &[Prefix]) -> Vec<Prefix> {
    let mut out = Vec::new();
    for v4 in [true, false] {
        let keep: Vec<_> = include
            .iter()
            .filter(|prefix| prefix.is_ipv4() == v4)
            .map(interval)
            .collect();
        let remove: Vec<_> = exclude
            .iter()
            .filter(|prefix| prefix.is_ipv4() == v4)
            .map(interval)
            .collect();
        let spans = subtract_spans(merge(keep), &merge(remove));
        for (start, end) in spans {
            span_to_prefixes(v4, start, end, &mut out);
        }
    }
    out
}

#[cfg(test)]
fn contains_all(prefixes: &[Prefix], host: std::net::IpAddr) -> bool {
    let bits = to_bits(host);
    prefixes.iter().any(|prefix| {
        prefix.is_ipv4() == host.is_ipv4() && {
            let (start, end) = prefix.range();
            bits >= start && bits <= end
        }
    })
}

fn eight_ranges(v4: bool) -> Vec<Prefix> {
    (0..8u32)
        .filter_map(|shift| {
            let first = 1u128 << shift;
            let width: u32 = if v4 { 32 } else { 128 };
            let bits = first << (width - 8);
            Prefix::new(from_bits(v4, bits), (8 - shift) as u8)
        })
        .collect()
}

/// The prefixes the tunnel's route table gets: `route-address`, or the default route
/// (split in eight on macOS), minus `route-exclude-address`. A family without an interface
/// address gets none.
pub fn auto_route_ranges(options: &TunOptions, darwin: bool) -> Vec<Prefix> {
    let mut out = Vec::new();
    for v4 in [true, false] {
        let addresses = if v4 {
            &options.inet4_address
        } else {
            &options.inet6_address
        };
        if addresses.is_empty() {
            continue;
        }
        let explicit: Vec<Prefix> = options
            .route_address
            .iter()
            .filter(|prefix| prefix.is_ipv4() == v4)
            .copied()
            .collect();
        let own = || {
            addresses
                .iter()
                .filter(|a| a.len() < 32)
                .map(Prefix::masked)
        };
        let mut ranges = if !explicit.is_empty() {
            let mut ranges = explicit;
            if darwin {
                ranges.extend(own());
            }
            ranges
        } else if options.auto_route {
            if darwin {
                eight_ranges(v4)
            } else {
                vec![Prefix::new(from_bits(v4, 0), 0).unwrap_or(Prefix::host(from_bits(v4, 0)))]
            }
        } else if darwin {
            own().collect()
        } else {
            Vec::new()
        };
        let excludes: Vec<Prefix> = options
            .route_exclude_address
            .iter()
            .filter(|prefix| prefix.is_ipv4() == v4)
            .copied()
            .collect();
        if !excludes.is_empty() {
            ranges = subtract(&ranges, &excludes);
        }
        out.extend(ranges);
    }
    out
}

fn id_spans(ranges: &[IdRange]) -> Vec<(u128, u128)> {
    merge(
        ranges
            .iter()
            .map(|range| (u128::from(range.start), u128::from(range.end)))
            .collect(),
    )
}

/// The uid ranges to leave out of the tunnel: the excludes alone, or everything
/// but the includes (less the excludes) when includes are given.
pub fn excluded_uids(include: &[IdRange], exclude: &[IdRange]) -> Vec<IdRange> {
    let spans = if include.is_empty() {
        id_spans(exclude)
    } else {
        let inside = subtract_spans(id_spans(include), &id_spans(exclude));
        subtract_spans(vec![(0, u128::from(USER_END))], &merge(inside))
    };
    spans
        .into_iter()
        .map(|(start, end)| IdRange {
            start: start as u32,
            end: end as u32,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Prefix {
        Prefix::parse(text).unwrap()
    }

    fn texts(prefixes: &[Prefix]) -> Vec<String> {
        prefixes.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn excluding_a_subnet_leaves_the_complement_in_cidr_form() {
        let result = subtract(&[p("0.0.0.0/0")], &[p("192.168.0.0/16")]);
        assert_eq!(
            texts(&result),
            [
                "0.0.0.0/1",
                "128.0.0.0/2",
                "192.0.0.0/9",
                "192.128.0.0/11",
                "192.160.0.0/13",
                "192.169.0.0/16",
                "192.170.0.0/15",
                "192.172.0.0/14",
                "192.176.0.0/12",
                "192.192.0.0/10",
                "193.0.0.0/8",
                "194.0.0.0/7",
                "196.0.0.0/6",
                "200.0.0.0/5",
                "208.0.0.0/4",
                "224.0.0.0/3",
            ]
            .map(String::from)
            .to_vec()
        );
        assert!(!contains_all(&result, "192.168.1.1".parse().unwrap()));
        assert!(contains_all(&result, "192.167.255.255".parse().unwrap()));
        assert!(contains_all(&result, "192.169.0.0".parse().unwrap()));
        assert!(contains_all(&result, "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn no_excludes_keeps_the_include_and_families_stay_apart() {
        let result = subtract(&[p("0.0.0.0/0"), p("::/0")], &[p("10.0.0.0/8")]);
        assert!(!contains_all(&result, "10.1.2.3".parse().unwrap()));
        assert!(contains_all(&result, "2001:db8::1".parse().unwrap()));
        assert!(result.contains(&p("::/0")));
        let same = subtract(&[p("172.16.0.0/12")], &[]);
        assert_eq!(texts(&same), ["172.16.0.0/12"]);
    }

    #[test]
    fn excluding_everything_or_a_single_host_works() {
        assert!(subtract(&[p("10.0.0.0/8")], &[p("0.0.0.0/0")]).is_empty());
        let result = subtract(&[p("10.0.0.0/30")], &[p("10.0.0.1/32")]);
        assert_eq!(texts(&result), ["10.0.0.0/32", "10.0.0.2/31"]);
        let v6 = subtract(&[p("fd00::/8")], &[p("fd00::1/128")]);
        assert!(!contains_all(&v6, "fd00::1".parse().unwrap()));
        assert!(contains_all(&v6, "fd00::2".parse().unwrap()));
        assert!(contains_all(
            &v6,
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn overlapping_includes_merge() {
        let result = subtract(&[p("10.0.0.0/9"), p("10.0.0.0/8"), p("10.128.0.0/9")], &[]);
        assert_eq!(texts(&result), ["10.0.0.0/8"]);
    }

    fn ids(pairs: &[(u32, u32)]) -> Vec<IdRange> {
        pairs
            .iter()
            .map(|&(start, end)| IdRange { start, end })
            .collect()
    }

    fn tun(auto: bool) -> TunOptions {
        TunOptions {
            auto_route: auto,
            inet4_address: vec![p("198.18.0.1/30")],
            inet6_address: vec![p("fdfe:dcba:9876::1/126")],
            ..TunOptions::default()
        }
    }

    #[test]
    fn auto_route_is_the_default_route_per_family() {
        let ranges = auto_route_ranges(&tun(true), false);
        assert_eq!(texts(&ranges), ["0.0.0.0/0", "::/0"]);
        let mut v4_only = tun(true);
        v4_only.inet6_address.clear();
        assert_eq!(texts(&auto_route_ranges(&v4_only, false)), ["0.0.0.0/0"]);
        assert!(auto_route_ranges(&tun(false), false).is_empty());
    }

    #[test]
    fn macos_splits_the_default_route_in_eight_and_excludes_leave_holes() {
        let mut options = tun(true);
        options.inet6_address.clear();
        let ranges = auto_route_ranges(&options, true);
        assert_eq!(
            texts(&ranges),
            [
                "1.0.0.0/8",
                "2.0.0.0/7",
                "4.0.0.0/6",
                "8.0.0.0/5",
                "16.0.0.0/4",
                "32.0.0.0/3",
                "64.0.0.0/2",
                "128.0.0.0/1",
            ]
        );
        options.route_exclude_address = vec![p("10.0.0.0/8")];
        let ranges = auto_route_ranges(&options, true);
        assert!(!contains_all(&ranges, "10.9.9.9".parse().unwrap()));
        assert!(contains_all(&ranges, "9.255.255.255".parse().unwrap()));
        assert!(contains_all(&ranges, "11.0.0.0".parse().unwrap()));
    }

    #[test]
    fn explicit_route_addresses_replace_the_default_route() {
        let mut options = tun(true);
        options.inet6_address.clear();
        options.route_address = vec![p("8.8.0.0/16")];
        assert_eq!(texts(&auto_route_ranges(&options, false)), ["8.8.0.0/16"]);
        assert_eq!(
            texts(&auto_route_ranges(&options, true)),
            ["8.8.0.0/16", "198.18.0.0/30"]
        );
    }

    #[test]
    fn uid_excludes_alone_pass_through_merged() {
        let result = excluded_uids(&[], &ids(&[(5, 7), (8, 9), (100, 100)]));
        assert_eq!(result, ids(&[(5, 9), (100, 100)]));
    }

    #[test]
    fn uid_includes_invert_to_everything_else() {
        let result = excluded_uids(&ids(&[(1000, 1999)]), &[]);
        assert_eq!(result, ids(&[(0, 999), (2000, USER_END)]));
        let result = excluded_uids(&ids(&[(1000, 1999)]), &ids(&[(1500, 1500)]));
        assert_eq!(result, ids(&[(0, 999), (1500, 1500), (2000, USER_END)]));
    }
}
