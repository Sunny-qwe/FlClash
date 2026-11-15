use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;

use tokio::time::Instant;

pub(super) type SkipKey = (Option<IpAddr>, u16);

const CAPACITY: usize = 128;
const MAX_AGE: Duration = Duration::from_secs(600);
pub(super) const FAILURES_BEFORE_SKIP: u8 = 5;

struct Entry {
    key: SkipKey,
    failures: u8,
    expires: Instant,
}

/// Destinations whose sniffing failed, as an LRU: 128 entries, 600 s age, the
/// least recently used at the front.
#[derive(Default)]
pub(super) struct SkipList {
    entries: VecDeque<Entry>,
}

impl SkipList {
    pub(super) fn get(&mut self, key: &SkipKey) -> Option<u8> {
        let now = Instant::now();
        let position = self.entries.iter().position(|e| e.key == *key)?;
        if self.entries.get(position)?.expires <= now {
            self.entries.remove(position);
            self.purge_expired(now);
            return None;
        }
        let entry = self.entries.remove(position)?;
        let failures = entry.failures;
        self.entries.push_back(entry);
        Some(failures)
    }

    pub(super) fn record_failure(&mut self, key: SkipKey) {
        let failures = self.get(&key).unwrap_or(0);
        let failures = if failures <= FAILURES_BEFORE_SKIP {
            failures + 1
        } else {
            failures
        };
        let now = Instant::now();
        let entry = Entry {
            key,
            failures,
            expires: now + MAX_AGE,
        };
        if let Some(position) = self.entries.iter().position(|e| e.key == entry.key) {
            self.entries.remove(position);
        }
        self.entries.push_back(entry);
        if self.entries.len() > CAPACITY {
            self.entries.pop_front();
        }
        self.purge_expired(now);
    }

    pub(super) fn delete(&mut self, key: &SkipKey) {
        if let Some(position) = self.entries.iter().position(|e| e.key == *key) {
            self.entries.remove(position);
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        while self.entries.front().is_some_and(|e| e.expires <= now) {
            self.entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn key(n: u8) -> SkipKey {
        (Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))), 443)
    }

    #[tokio::test(start_paused = true)]
    async fn failures_count_up_and_saturate_past_the_threshold() {
        let mut list = SkipList::default();
        assert_eq!(list.get(&key(1)), None);
        for expected in 1..=6 {
            list.record_failure(key(1));
            assert_eq!(list.get(&key(1)), Some(expected));
        }
        list.record_failure(key(1));
        assert_eq!(list.get(&key(1)), Some(6));
    }

    #[tokio::test(start_paused = true)]
    async fn delete_forgets_the_destination() {
        let mut list = SkipList::default();
        list.record_failure(key(1));
        list.delete(&key(1));
        assert_eq!(list.get(&key(1)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn entries_expire_after_ten_minutes() {
        let mut list = SkipList::default();
        list.record_failure(key(1));
        tokio::time::advance(Duration::from_secs(599)).await;
        assert_eq!(list.get(&key(1)), Some(1));
        tokio::time::advance(Duration::from_secs(601)).await;
        assert_eq!(list.get(&key(1)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_failure_renews_the_age() {
        let mut list = SkipList::default();
        list.record_failure(key(1));
        tokio::time::advance(Duration::from_secs(400)).await;
        list.record_failure(key(1));
        tokio::time::advance(Duration::from_secs(400)).await;
        assert_eq!(list.get(&key(1)), Some(2));
    }

    #[tokio::test(start_paused = true)]
    async fn the_least_recently_used_destination_is_evicted() {
        let mut list = SkipList::default();
        for n in 0..=127 {
            list.record_failure((Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))), 80));
        }
        assert_eq!(
            list.get(&(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))), 80)),
            Some(1)
        );
        list.record_failure(key(1));
        assert_eq!(
            list.get(&(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), 80)),
            None
        );
        assert_eq!(
            list.get(&(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))), 80)),
            Some(1)
        );
    }
}
