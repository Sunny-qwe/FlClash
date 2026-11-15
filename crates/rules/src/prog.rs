use crate::eval::{Ev, EvResult, Node, has_domain_suffix};
use crate::runs::{DomainRun, IpRun};
use crate::table::RuleTable;

#[derive(Clone, Copy)]
pub(crate) enum HostMatch {
    Exact,
    Suffix,
    Keyword,
}

impl HostMatch {
    pub(crate) fn matches(self, host: &str, payload: &str) -> bool {
        match self {
            HostMatch::Exact => host == payload,
            HostMatch::Suffix => has_domain_suffix(host, payload),
            HostMatch::Keyword => host.contains(payload),
        }
    }
}

pub(crate) enum Op {
    Leaf {
        idx: u32,
        node: u32,
    },
    /// A lone domain rule, which needs nothing beyond its payload in the table.
    Host {
        idx: u32,
        how: HostMatch,
    },
    Domain(u32),
    Ip(u32),
}

/// One compiled rule list: the main list, a sub-rule list, or a classical rule set.
#[derive(Default)]
pub(crate) struct Prog {
    pub(crate) table: RuleTable,
    pub(crate) ops: Box<[Op]>,
    pub(crate) nodes: Box<[Node]>,
    pub(crate) domain_runs: Box<[DomainRun]>,
    pub(crate) ip_runs: Box<[IpRun]>,
}

impl Prog {
    pub(crate) fn heap_bytes(&self) -> usize {
        self.table.heap_bytes()
            + self.ops.len() * std::mem::size_of::<Op>()
            + self.nodes.len() * std::mem::size_of::<Node>()
            + self
                .domain_runs
                .iter()
                .map(DomainRun::heap_bytes)
                .sum::<usize>()
            + self.ip_runs.iter().map(IpRun::heap_bytes).sum::<usize>()
    }

    /// True when any rule of the list holds, evaluated in order.
    pub(crate) fn any_match(&self, ev: &mut Ev<'_>) -> EvResult {
        let mut unknown = false;
        for op in self.ops.iter() {
            match op {
                Op::Leaf { node, .. } => {
                    if let Some(node) = self.nodes.get(*node as usize) {
                        if ev.eval(node)? {
                            return Ok(true);
                        }
                        unknown |= ev.unknown;
                    }
                }
                Op::Host { idx, how } => {
                    if self
                        .table
                        .payload(*idx)
                        .is_some_and(|payload| how.matches(ev.host, payload))
                    {
                        return Ok(true);
                    }
                }
                Op::Domain(run) => {
                    if let Some(run) = self.domain_runs.get(*run as usize)
                        && run.next_from(ev.host, run.start, &self.table).is_some()
                    {
                        return Ok(true);
                    }
                }
                Op::Ip(run) => {
                    let Some(run) = self.ip_runs.get(*run as usize) else {
                        continue;
                    };
                    let ip = if run.src {
                        ev.src_ip()
                    } else {
                        ev.dst_ip(run.resolves)?
                    };
                    if ip.is_some_and(|ip| run.next_from(ip, run.start).is_some()) {
                        return Ok(true);
                    }
                }
            }
        }
        ev.unknown = unknown;
        Ok(false)
    }
}
