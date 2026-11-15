use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use concord_common::sync::lock;
use tokio::sync::Notify;

use concord_config::net::IpCidr;

use crate::DnsError;
use crate::lru::LruCache;

pub(crate) const STORE_SIZE: usize = 1000;
/// mihomo's cache file keeps every address of the range; a v6 range is too wide to
/// hold in memory, so a stored pool keeps at most this many.
pub(crate) const STORED_SIZE: usize = 1 << 16;
const SNAPSHOT_MAGIC: &[u8; 4] = b"CFI1";

fn to_bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn from_bits(bits: u128, v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::from(bits))
    } else {
        IpAddr::V4(Ipv4Addr::from(u32::try_from(bits).unwrap_or(u32::MAX)))
    }
}

struct PoolState {
    offset: u128,
    cycle: bool,
    by_host: LruCache<String, IpAddr>,
    by_ip: LruCache<IpAddr, String>,
    version: u64,
    saved: u64,
}

/// Fake addresses handed out in order from `network + 4`, recycling the oldest
/// when the range wraps.
pub struct FakeIpPool {
    v6: bool,
    network: IpCidr,
    gateway: u128,
    first: u128,
    last: u128,
    state: Mutex<PoolState>,
    changed: Notify,
}

impl FakeIpPool {
    pub fn new(network: IpCidr) -> Result<Self, DnsError> {
        Self::with_size(network, STORE_SIZE)
    }

    pub fn with_size(network: IpCidr, size: usize) -> Result<Self, DnsError> {
        let v6 = !network.is_ipv4();
        let width: u32 = if v6 { 128 } else { 32 };
        let prefix = u32::from(network.prefix).min(width);
        let host_bits = width - prefix;
        let span = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        let base = to_bits(network.addr) & !span;
        let gateway = base.saturating_add(1);
        let first = gateway.saturating_add(3);
        let last = base | span;
        if first >= last {
            return Err(DnsError::config("ipnet don't have valid ip"));
        }
        Ok(FakeIpPool {
            v6,
            network,
            gateway,
            first,
            last,
            state: Mutex::new(PoolState {
                offset: first - 1,
                cycle: false,
                by_host: LruCache::new(size),
                by_ip: LruCache::new(size),
                version: 0,
                saved: 0,
            }),
            changed: Notify::new(),
        })
    }

    pub fn gateway(&self) -> IpAddr {
        from_bits(self.gateway, self.v6)
    }

    pub fn broadcast(&self) -> IpAddr {
        from_bits(self.last, self.v6)
    }

    pub fn network(&self) -> IpCidr {
        self.network
    }

    pub fn lookup(&self, host: &str) -> Option<IpAddr> {
        let host = host.to_ascii_lowercase();
        let mut state = lock(&self.state);
        if let Some(ip) = state.by_host.get(&host).copied() {
            state.by_ip.get(&ip);
            return Some(ip);
        }
        state.offset += 1;
        if state.offset >= self.last {
            state.cycle = true;
            state.offset = self.first;
        }
        let ip = from_bits(state.offset, self.v6);
        if (state.cycle || state.by_ip.contains(&ip))
            && let Some(old_host) = state.by_ip.remove(&ip)
        {
            state.by_host.remove(&old_host);
        }
        state.by_ip.insert(ip, host.clone());
        state.by_host.insert(host, ip);
        self.mark_changed(&mut state);
        Some(ip)
    }

    pub fn look_back(&self, ip: IpAddr) -> Option<String> {
        let mut state = lock(&self.state);
        let host = state.by_ip.get(&ip).cloned()?;
        state.by_host.get(&host);
        Some(host)
    }

    pub fn exists(&self, ip: IpAddr) -> bool {
        lock(&self.state).by_ip.contains(&ip)
    }

    fn hands_out(&self, ip: IpAddr) -> bool {
        ip.is_ipv6() == self.v6 && (self.first..self.last).contains(&to_bits(ip))
    }

    /// In the range and neither the gateway nor the broadcast address.
    pub fn is_fake(&self, ip: IpAddr) -> bool {
        self.network.contains(ip) && to_bits(ip) != self.gateway && to_bits(ip) != self.last
    }

    pub fn is_broadcast(&self, ip: IpAddr) -> bool {
        to_bits(ip) == self.last && self.network.contains(ip)
    }

    pub fn flush(&self) {
        {
            let mut state = lock(&self.state);
            state.by_host.clear();
            state.by_ip.clear();
            state.cycle = false;
            state.offset = self.first - 1;
            self.mark_changed(&mut state);
        }
    }

    pub fn is_empty(&self) -> bool {
        lock(&self.state).by_ip.is_empty()
    }

    /// A snapshot with the change it includes, unless that change is already saved.
    pub fn pending(&self) -> Option<(u64, Vec<u8>)> {
        let state = lock(&self.state);
        (state.version > state.saved).then(|| (state.version, self.encode(&state)))
    }

    /// The change a snapshot from [`pending`](Self::pending) included is on disk.
    pub fn mark_saved(&self, version: u64) {
        {
            let mut state = lock(&self.state);
            state.saved = state.saved.max(version);
        }
    }

    /// Completes once after any number of changes made since the last time it completed.
    pub async fn changed(&self) {
        self.changed.notified().await;
    }

    fn mark_changed(&self, state: &mut PoolState) {
        state.version += 1;
        self.changed.notify_one();
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.encode(&lock(&self.state))
    }

    fn encode(&self, state: &PoolState) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        for bits in [self.first, self.last, state.offset] {
            out.extend_from_slice(&bits.to_le_bytes());
        }
        out.push(u8::from(state.cycle));
        for (ip, host) in state.by_ip.entries_oldest_first() {
            let Ok(len) = u16::try_from(host.len()) else {
                continue;
            };
            out.extend_from_slice(&to_bits(ip).to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(host.as_bytes());
        }
        out
    }

    /// Takes a snapshot of this same range only: mihomo flushes a store whose
    /// cursor lies outside the range, and a malformed one is no better.
    pub fn restore(&self, bytes: &[u8]) -> bool {
        let Some(entries) = self.parse(bytes) else {
            return false;
        };
        let mut state = lock(&self.state);
        (state.offset, state.cycle) = (entries.offset, entries.cycle);
        for (ip, host) in entries.mappings {
            state.by_host.insert(host.clone(), ip);
            state.by_ip.insert(ip, host);
        }
        true
    }

    fn parse(&self, bytes: &[u8]) -> Option<Snapshot> {
        let mut rest = bytes.strip_prefix(SNAPSHOT_MAGIC)?;
        let mut bits = || -> Option<u128> {
            let (head, tail) = rest.split_first_chunk::<16>()?;
            rest = tail;
            Some(u128::from_le_bytes(*head))
        };
        let (first, last, offset) = (bits()?, bits()?, bits()?);
        if first != self.first || last != self.last || offset < first - 1 || offset > last {
            return None;
        }
        let (&cycle, mut rest) = rest.split_first()?;
        let mut mappings = Vec::new();
        while !rest.is_empty() {
            let (ip, tail) = rest.split_first_chunk::<16>()?;
            let (len, tail) = tail.split_first_chunk::<2>()?;
            let (host, tail) = tail.split_at_checked(usize::from(u16::from_le_bytes(*len)))?;
            rest = tail;
            let ip = u128::from_le_bytes(*ip);
            if (self.first..self.last).contains(&ip) {
                mappings.push((
                    from_bits(ip, self.v6),
                    std::str::from_utf8(host).ok()?.to_owned(),
                ));
            }
        }
        Some(Snapshot {
            offset,
            cycle: cycle != 0,
            mappings,
        })
    }

    /// Carries over the mappings of the previous configuration's pool whose addresses this
    /// one hands out; the allocation cursor follows only for the same range.
    pub fn adopt(&self, old: &FakeIpPool) {
        if std::ptr::eq(self, old) {
            return;
        }
        let mut mine = lock(&self.state);
        let theirs = lock(&old.state);
        mine.by_host.clear();
        mine.by_ip.clear();
        for (host, ip) in theirs.by_host.entries_oldest_first() {
            if self.hands_out(*ip) {
                mine.by_host.insert(host, *ip);
            }
        }
        for (ip, host) in theirs.by_ip.entries_oldest_first() {
            if self.hands_out(ip) {
                mine.by_ip.insert(ip, host.clone());
            }
        }
        if old.first == self.first && old.last == self.last {
            mine.offset = theirs.offset;
            mine.cycle = theirs.cycle;
        }
        self.mark_changed(&mut mine);
    }
}

struct Snapshot {
    offset: u128,
    cycle: bool,
    mappings: Vec<(IpAddr, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(cidr: &str) -> FakeIpPool {
        FakeIpPool::new(IpCidr::parse(cidr).unwrap()).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn allocation_starts_at_network_plus_four_and_is_stable() {
        let pool = pool("192.168.0.1/29");
        assert_eq!(pool.gateway(), ip("192.168.0.1"));
        assert_eq!(pool.broadcast(), ip("192.168.0.7"));
        let first = pool.lookup("foo.com").unwrap();
        assert_eq!(first, ip("192.168.0.4"));
        assert_eq!(pool.lookup("foo.com"), Some(first));
        assert_eq!(pool.lookup("FOO.com"), Some(first));
        assert_eq!(pool.look_back(first).as_deref(), Some("foo.com"));
        assert!(pool.exists(first));
        assert_eq!(pool.lookup("bar.com").unwrap(), ip("192.168.0.5"));
    }

    #[test]
    fn the_range_wraps_and_recycles_the_oldest_address() {
        let pool = pool("192.168.0.1/29");
        let a = pool.lookup("a.com").unwrap();
        let b = pool.lookup("b.com").unwrap();
        let c = pool.lookup("c.com").unwrap();
        assert_eq!(
            (a, b, c),
            (ip("192.168.0.4"), ip("192.168.0.5"), ip("192.168.0.6"))
        );
        let d = pool.lookup("d.com").unwrap();
        assert_eq!(d, ip("192.168.0.4"));
        assert_eq!(pool.look_back(d).as_deref(), Some("d.com"));
        assert_ne!(pool.lookup("a.com"), Some(a));
    }

    #[test]
    fn cycling_reuses_the_first_address_for_the_next_host() {
        let pool = pool("192.168.0.16/28");
        let foo = pool.lookup("foo.com").unwrap();
        let bar = pool.lookup("bar.com").unwrap();
        for i in 0..9 {
            pool.lookup(&format!("{i}.com"));
        }
        let baz = pool.lookup("baz.com").unwrap();
        assert_eq!(baz, foo);
        assert_eq!(pool.lookup("foo.com"), Some(bar));
    }

    #[test]
    fn a_small_store_forgets_the_least_recent_host() {
        let pool = FakeIpPool::with_size(IpCidr::parse("192.168.0.1/24").unwrap(), 2).unwrap();
        let first = pool.lookup("foo.com").unwrap();
        pool.lookup("bar.com");
        pool.lookup("baz.com");
        assert_ne!(pool.lookup("foo.com"), Some(first));
    }

    #[test]
    fn a_hot_host_survives_a_small_store() {
        let pool = FakeIpPool::with_size(IpCidr::parse("192.168.0.1/24").unwrap(), 2).unwrap();
        let foo = pool.lookup("foo.com").unwrap();
        let baz = pool.lookup("baz.com").unwrap();
        pool.lookup("foo.com");
        let bar = pool.lookup("bar.com").unwrap();
        assert!(pool.look_back(foo).is_some());
        assert!(pool.look_back(baz).is_none());
        assert!(pool.look_back(bar).is_some());
        assert_ne!(pool.lookup("baz.com"), Some(baz));
    }

    #[test]
    fn a_fresh_allocation_does_not_overwrite_adopted_mappings() {
        let ipnet = IpCidr::parse("192.168.0.1/24").unwrap();
        let old = FakeIpPool::with_size(ipnet, 10).unwrap();
        let foo = old.lookup("foo.com").unwrap();
        let bar = old.lookup("bar.com").unwrap();
        let new = FakeIpPool::with_size(ipnet, 10).unwrap();
        new.adopt(&old);
        let baz = new.lookup("baz.com").unwrap();
        assert!(baz != foo && baz != bar);
        assert_eq!(new.lookup("foo.com"), Some(foo));
        assert_eq!(new.look_back(foo).as_deref(), Some("foo.com"));
    }

    #[test]
    fn too_small_a_range_is_refused() {
        assert!(FakeIpPool::new(IpCidr::parse("192.168.0.1/30").unwrap()).is_err());
        assert!(FakeIpPool::new(IpCidr::parse("192.168.0.1/29").unwrap()).is_ok());
    }

    #[test]
    fn fake_means_inside_the_range_but_not_gateway_or_broadcast() {
        let pool = pool("198.18.0.1/16");
        assert!(pool.is_fake(ip("198.18.0.4")));
        assert!(pool.is_fake(ip("198.18.5.5")));
        assert!(!pool.is_fake(ip("198.18.0.1")));
        assert!(!pool.is_fake(ip("198.18.255.255")));
        assert!(pool.is_broadcast(ip("198.18.255.255")));
        assert!(!pool.is_fake(ip("8.8.8.8")));
    }

    #[test]
    fn ipv6_pools_allocate_too() {
        let pool = pool("fdfe:dcba:9876::1/64");
        assert_eq!(pool.lookup("v6.com").unwrap(), ip("fdfe:dcba:9876::4"));
    }

    #[test]
    fn flush_restarts_the_allocation() {
        let pool = pool("198.18.0.1/16");
        let first = pool.lookup("a.com").unwrap();
        pool.lookup("b.com");
        pool.flush();
        assert!(pool.look_back(first).is_none());
        assert_eq!(pool.lookup("c.com"), Some(first));
    }

    #[test]
    fn a_snapshot_brings_back_the_mappings_and_the_cursor() {
        let old = pool("198.18.0.1/16");
        let a = old.lookup("a.com").unwrap();
        let b = old.lookup("b.com").unwrap();
        let (_, bytes) = old.pending().unwrap();

        let new = pool("198.18.0.1/16");
        assert!(new.restore(&bytes));
        assert!(new.pending().is_none());
        assert_eq!(new.look_back(a).as_deref(), Some("a.com"));
        assert_eq!(new.lookup("b.com"), Some(b));
        assert_eq!(new.lookup("c.com"), Some(ip("198.18.0.6")));
    }

    #[test]
    fn a_change_stays_pending_until_a_snapshot_that_includes_it_is_saved() {
        let pool = pool("198.18.0.1/16");
        assert!(pool.pending().is_none());
        pool.lookup("a.com");
        let (first, _) = pool.pending().unwrap();
        assert!(pool.pending().is_some());
        pool.lookup("b.com");
        pool.mark_saved(first);
        let (second, _) = pool.pending().unwrap();
        pool.mark_saved(second);
        pool.mark_saved(first);
        assert!(pool.pending().is_none());
        pool.flush();
        assert!(pool.pending().is_some());
    }

    #[test]
    fn a_snapshot_of_another_range_or_a_damaged_one_is_refused() {
        let old = pool("198.18.0.1/16");
        old.lookup("a.com");
        let bytes = old.snapshot();

        let other = pool("198.19.0.1/16");
        assert!(!other.restore(&bytes));
        assert_eq!(other.lookup("a.com"), Some(ip("198.19.0.4")));

        let same = pool("198.18.0.1/16");
        assert!(!same.restore(&bytes[..bytes.len() - 1]));
        assert!(!same.restore(b"CFI0"));
        assert!(same.restore(&pool("198.18.0.1/16").snapshot()));
    }

    #[test]
    fn adopting_from_another_range_keeps_only_the_addresses_this_one_hands_out() {
        let old = pool("198.18.1.0/24");
        let inside = old.lookup("inside.test").unwrap();
        let wider = pool("198.18.0.1/16");
        wider.adopt(&old);
        assert_eq!(wider.lookup("inside.test"), Some(inside));
        let moved = pool("198.19.0.1/16");
        moved.adopt(&old);
        assert!(moved.look_back(inside).is_none());
        let fresh = moved.lookup("inside.test").unwrap();
        assert!(moved.is_fake(fresh), "{fresh} is outside the new range");
    }

    #[test]
    fn adopt_keeps_the_mappings_and_the_cursor() {
        let old = pool("198.18.0.1/16");
        let a = old.lookup("a.com").unwrap();
        let new = pool("198.18.0.1/16");
        new.adopt(&old);
        assert_eq!(new.lookup("a.com"), Some(a));
        assert_eq!(new.lookup("b.com"), Some(ip("198.18.0.5")));
    }
}
