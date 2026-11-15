use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use concord_netstack::wire::DropReason;

#[derive(Default)]
pub struct StackStats {
    pub(crate) rx_packets: AtomicU64,
    pub(crate) rx_malformed: AtomicU64,
    pub(crate) rx_fragments: AtomicU64,
    pub(crate) rx_checksum: AtomicU64,
    pub(crate) rx_unsupported: AtomicU64,
    pub(crate) rx_martian: AtomicU64,
    pub(crate) rx_handoff: AtomicU64,
    pub(crate) tcp_active: AtomicUsize,
    pub(crate) tcp_accepted: AtomicU64,
    pub(crate) tcp_refused: AtomicU64,
    pub(crate) udp_packets: AtomicU64,
    pub(crate) udp_replies: AtomicU64,
    pub(crate) udp_oversize: AtomicU64,
    pub(crate) udp_sessions: AtomicUsize,
    pub(crate) dns_hijacked: AtomicU64,
    pub(crate) icmp_echo: AtomicU64,
    pub(crate) tx_errors: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub rx_packets: u64,
    pub rx_dropped: u64,
    pub tcp_active: usize,
    pub tcp_accepted: u64,
    pub tcp_refused: u64,
    pub udp_packets: u64,
    pub udp_replies: u64,
    pub udp_oversize: u64,
    pub udp_sessions: usize,
    pub dns_hijacked: u64,
    pub icmp_echo: u64,
    pub tx_errors: u64,
}

/// Adds one driver's change to a gauge every driver of a multi-queue device contributes to.
pub(crate) fn report(gauge: &AtomicUsize, last: &mut usize, now: usize) {
    if now > *last {
        gauge.fetch_add(now - *last, Ordering::Relaxed);
    } else {
        gauge.fetch_sub(*last - now, Ordering::Relaxed);
    }
    *last = now;
}

impl StackStats {
    pub(crate) fn count_drop(&self, reason: DropReason) {
        let counter = match reason {
            DropReason::Malformed => &self.rx_malformed,
            DropReason::Fragment => &self.rx_fragments,
            DropReason::Checksum => &self.rx_checksum,
            DropReason::Unsupported => &self.rx_unsupported,
            DropReason::Martian => &self.rx_martian,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        StatsSnapshot {
            rx_packets: load(&self.rx_packets),
            rx_dropped: load(&self.rx_malformed)
                + load(&self.rx_fragments)
                + load(&self.rx_checksum)
                + load(&self.rx_unsupported)
                + load(&self.rx_martian)
                + load(&self.rx_handoff),
            tcp_active: self.tcp_active.load(Ordering::Relaxed),
            tcp_accepted: load(&self.tcp_accepted),
            tcp_refused: load(&self.tcp_refused),
            udp_packets: load(&self.udp_packets),
            udp_replies: load(&self.udp_replies),
            udp_oversize: load(&self.udp_oversize),
            udp_sessions: self.udp_sessions.load(Ordering::Relaxed),
            dns_hijacked: load(&self.dns_hijacked),
            icmp_echo: load(&self.icmp_echo),
            tx_errors: load(&self.tx_errors),
        }
    }
}
