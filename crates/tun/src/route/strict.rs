/// What `strict-route` asks of the Windows firewall, as sing-tun builds it: the tunnel's own
/// traffic and the core's are let through, IPv6 is shut when the tunnel has no IPv6 address,
/// and port-53 traffic that is not the tunnel's is blocked so no other adapter leaks a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrictRoute {
    pub if_index: u32,
    pub inet4: bool,
    pub inet6: bool,
    pub block_dns: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Permit,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cond {
    /// The executable of this process.
    SelfProcess,
    Interface(u32),
    RemotePort(u16),
    /// An ICMPv6 message of this type and code 0, to every router when asked.
    Icmpv6 {
        kind: u16,
        to_all_routers: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterSpec {
    pub name: &'static str,
    pub layer: Layer,
    pub weight: u8,
    pub verdict: Verdict,
    pub conds: Vec<Cond>,
    /// A permit that a later block in another sublayer cannot override.
    pub clear_action_right: bool,
}

const SELF_WEIGHT: u8 = 13;
const BLOCK_V6_WEIGHT: u8 = 12;
const TUN_WEIGHT: u8 = 11;
const BLOCK_DNS_WEIGHT: u8 = 10;
const ICMPV6_ROUTER_SOLICITATION: u16 = 133;
const ICMPV6_NEIGHBOR_SOLICITATION: u16 = 135;
const ICMPV6_NEIGHBOR_ADVERTISEMENT: u16 = 136;

fn filter(
    name: &'static str,
    layer: Layer,
    weight: u8,
    verdict: Verdict,
    conds: Vec<Cond>,
) -> FilterSpec {
    FilterSpec {
        name,
        layer,
        weight,
        verdict,
        conds,
        clear_action_right: false,
    }
}

impl StrictRoute {
    /// The filters in the order sing-tun adds them. Higher weight wins inside the sublayer.
    pub fn filters(&self) -> Vec<FilterSpec> {
        let mut specs = Vec::new();
        for (name, layer) in [("protect ipv4", Layer::V4), ("protect ipv6", Layer::V6)] {
            let mut spec = filter(
                name,
                layer,
                SELF_WEIGHT,
                Verdict::Permit,
                vec![Cond::SelfProcess],
            );
            spec.clear_action_right = true;
            specs.push(spec);
        }
        if !self.inet6 {
            for (name, kind, to_all_routers) in [
                (
                    "allow ipv6 router solicitation",
                    ICMPV6_ROUTER_SOLICITATION,
                    true,
                ),
                (
                    "allow ipv6 neighbor solicitation",
                    ICMPV6_NEIGHBOR_SOLICITATION,
                    false,
                ),
                (
                    "allow ipv6 neighbor advertisement",
                    ICMPV6_NEIGHBOR_ADVERTISEMENT,
                    false,
                ),
            ] {
                specs.push(filter(
                    name,
                    Layer::V6,
                    SELF_WEIGHT,
                    Verdict::Permit,
                    vec![Cond::Icmpv6 {
                        kind,
                        to_all_routers,
                    }],
                ));
            }
            specs.push(filter(
                "block ipv6",
                Layer::V6,
                BLOCK_V6_WEIGHT,
                Verdict::Block,
                Vec::new(),
            ));
        }
        if self.inet4 {
            specs.push(filter(
                "allow ipv4",
                Layer::V4,
                TUN_WEIGHT,
                Verdict::Permit,
                vec![Cond::Interface(self.if_index)],
            ));
        }
        if self.inet6 {
            specs.push(filter(
                "allow ipv6",
                Layer::V6,
                TUN_WEIGHT,
                Verdict::Permit,
                vec![Cond::Interface(self.if_index)],
            ));
        }
        if self.block_dns {
            for (name, layer) in [("block ipv4 dns", Layer::V4), ("block ipv6 dns", Layer::V6)] {
                specs.push(filter(
                    name,
                    layer,
                    BLOCK_DNS_WEIGHT,
                    Verdict::Block,
                    vec![Cond::RemotePort(53)],
                ));
            }
        }
        specs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(strict: &StrictRoute) -> Vec<&'static str> {
        strict.filters().iter().map(|spec| spec.name).collect()
    }

    #[test]
    fn a_tunnel_with_only_ipv4_shuts_ipv6_after_letting_neighbour_discovery_through() {
        let strict = StrictRoute {
            if_index: 7,
            inet4: true,
            inet6: false,
            block_dns: false,
        };
        assert_eq!(
            names(&strict),
            [
                "protect ipv4",
                "protect ipv6",
                "allow ipv6 router solicitation",
                "allow ipv6 neighbor solicitation",
                "allow ipv6 neighbor advertisement",
                "block ipv6",
                "allow ipv4",
            ]
        );
        let filters = strict.filters();
        let block = filters.iter().find(|spec| spec.name == "block ipv6");
        assert_eq!(block.map(|spec| spec.verdict), Some(Verdict::Block));
        assert!(
            filters
                .iter()
                .filter(|spec| spec.verdict == Verdict::Permit && spec.layer == Layer::V6)
                .all(|spec| spec.weight > BLOCK_V6_WEIGHT)
        );
    }

    #[test]
    fn a_dual_stack_tunnel_blocks_no_family_and_dns_goes_below_the_tunnel_permit() {
        let strict = StrictRoute {
            if_index: 7,
            inet4: true,
            inet6: true,
            block_dns: true,
        };
        let filters = strict.filters();
        assert!(filters.iter().all(|spec| spec.name != "block ipv6"));
        let weight = |name: &str| {
            filters
                .iter()
                .find(|spec| spec.name == name)
                .map(|s| s.weight)
        };
        assert!(weight("allow ipv4") > weight("block ipv4 dns"));
        assert!(weight("allow ipv6") > weight("block ipv6 dns"));
        assert_eq!(
            filters
                .iter()
                .filter(|spec| spec.conds == [Cond::RemotePort(53)])
                .count(),
            2
        );
    }

    #[test]
    fn only_the_cores_own_permit_overrides_other_sublayers() {
        let strict = StrictRoute {
            if_index: 1,
            inet4: true,
            inet6: true,
            block_dns: true,
        };
        for spec in strict.filters() {
            assert_eq!(spec.clear_action_right, spec.conds == [Cond::SelfProcess]);
        }
    }

    #[test]
    fn only_router_solicitation_is_addressed_to_all_routers() {
        let strict = StrictRoute {
            if_index: 1,
            inet4: true,
            inet6: false,
            block_dns: false,
        };
        let to_routers: Vec<_> = strict
            .filters()
            .into_iter()
            .filter(|spec| {
                matches!(
                    spec.conds.as_slice(),
                    [Cond::Icmpv6 {
                        to_all_routers: true,
                        ..
                    }]
                )
            })
            .map(|spec| spec.name)
            .collect();
        assert_eq!(to_routers, ["allow ipv6 router solicitation"]);
    }
}
