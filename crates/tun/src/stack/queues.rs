//! Which queue of a multi-queue device owns each TCP connection. The kernel picks a queue
//! from the socket's hash, which it changes after a timeout, so a connection's segments can
//! arrive on a queue whose stack does not hold it.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::task::Waker;

use concord_common::sync::lock;
use futures_util::task::AtomicWaker;

use super::udp::FxBuild;

const INBOX_LIMIT: usize = 256;

type Key = (SocketAddr, SocketAddr);

struct Inbox {
    packets: Mutex<VecDeque<Vec<u8>>>,
    waker: AtomicWaker,
}

pub(crate) struct Queues {
    owners: Mutex<Owners>,
    inboxes: Box<[Inbox]>,
}

struct Entry {
    queue: usize,
    epoch: u64,
}

struct Owners {
    flows: HashMap<Key, Entry, FxBuild>,
    next: u64,
    cursor: usize,
}

impl Owners {
    fn insert(&mut self, key: Key, queue: usize) -> u64 {
        let epoch = self.next;
        self.next = self.next.wrapping_add(1);
        self.flows.insert(key, Entry { queue, epoch });
        epoch
    }

    fn release(&mut self, key: &Key, queue: usize, epoch: Option<u64>) {
        if self.flows.get(key).is_some_and(|entry| {
            entry.queue == queue && epoch.is_none_or(|epoch| epoch == entry.epoch)
        }) {
            self.flows.remove(key);
        }
    }
}

struct Lease {
    queues: Weak<Queues>,
    key: Key,
    queue: usize,
    epoch: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(queues) = self.queues.upgrade() {
            lock(&queues.owners).release(&self.key, self.queue, Some(self.epoch));
        }
    }
}

struct Owner {
    queues: Arc<Queues>,
    queue: usize,
}

impl concord_netstack::FlowOwner for Owner {
    fn acquire(&self, local: SocketAddr, remote: SocketAddr) -> Option<Box<dyn Send + Sync>> {
        let key = (local, remote);
        let mut owners = lock(&self.queues.owners);
        let epoch = if let Some(entry) = owners.flows.get(&key) {
            if entry.queue != self.queue {
                return None;
            }
            entry.epoch
        } else {
            // A new SYN can replace a just-closed connection at the same address.
            owners.insert(key, self.queue)
        };
        Some(Box::new(Lease {
            queues: Arc::downgrade(&self.queues),
            key,
            queue: self.queue,
            epoch,
        }))
    }
}

impl Queues {
    pub fn new(count: usize) -> Self {
        Queues {
            owners: Mutex::new(Owners {
                flows: HashMap::default(),
                next: 0,
                cursor: 0,
            }),
            inboxes: (0..count)
                .map(|_| Inbox {
                    packets: Mutex::new(VecDeque::new()),
                    waker: AtomicWaker::new(),
                })
                .collect(),
        }
    }

    /// Keeps existing owners. New SYNs rotate independently of older idle connections;
    /// the first connection stays on its receiving queue.
    pub fn claim(&self, key: Key, me: usize) -> usize {
        let mut owners = lock(&self.owners);
        if let Some(entry) = owners.flows.get(&key) {
            return entry.queue;
        }
        let count = self.inboxes.len();
        if count == 0 {
            return me;
        }
        let queue = if owners.flows.is_empty() {
            me % count
        } else {
            owners.cursor
        };
        owners.cursor = (queue + 1) % count;
        owners.insert(key, queue);
        queue
    }

    pub fn owner(&self, key: &Key) -> Option<usize> {
        lock(&self.owners).flows.get(key).map(|entry| entry.queue)
    }

    pub fn flow_owner(self: &Arc<Self>, queue: usize) -> Arc<dyn concord_netstack::FlowOwner> {
        Arc::new(Owner {
            queues: Arc::clone(self),
            queue,
        })
    }

    pub fn release_unopened(&self, key: &Key, queue: usize) {
        lock(&self.owners).release(key, queue, None);
    }

    pub fn forward(&self, to: usize, packet: &[u8]) -> bool {
        let Some(inbox) = self.inboxes.get(to) else {
            return false;
        };
        {
            let mut packets = lock(&inbox.packets);
            if packets.len() >= INBOX_LIMIT {
                return false;
            }
            packets.push_back(packet.to_vec());
        }
        inbox.waker.wake();
        true
    }

    pub fn register(&self, me: usize, waker: &Waker) {
        if let Some(inbox) = self.inboxes.get(me) {
            inbox.waker.register(waker);
        }
    }

    pub fn take(&self, me: usize) -> VecDeque<Vec<u8>> {
        self.inboxes
            .get(me)
            .map(|inbox| std::mem::take(&mut *lock(&inbox.packets)))
            .unwrap_or_default()
    }

    /// Forgets the connections `me` owned and has since closed.
    pub fn retain(&self, me: usize, open: impl Fn(&Key) -> bool) {
        let mut owners = lock(&self.owners);
        owners
            .flows
            .retain(|key, entry| entry.queue != me || open(key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_queue_to_see_a_connection_keeps_it_until_it_closes() {
        let queues = Queues::new(2);
        let key = (
            "198.18.0.9:443".parse().unwrap(),
            "198.18.0.1:40000".parse().unwrap(),
        );
        assert_eq!(queues.claim(key, 1), 1);
        assert_eq!(queues.claim(key, 0), 1);
        assert!(queues.forward(1, b"segment"));
        assert_eq!(queues.take(1), [b"segment".to_vec()]);
        queues.retain(0, |_| false);
        assert_eq!(queues.owner(&key), Some(1));
        queues.retain(1, |_| false);
        assert_eq!(queues.owner(&key), None);
        for _ in 0..INBOX_LIMIT {
            assert!(queues.forward(0, b"x"));
        }
        assert!(!queues.forward(0, b"x"));
    }

    #[test]
    fn new_connections_balance_but_duplicate_syns_keep_their_owner() {
        let queues = Arc::new(Queues::new(4));
        let local = "198.18.0.9:443".parse().unwrap();
        let mut leases = Vec::new();
        let mut counts = [0; 4];
        for port in 40000..40008 {
            let remote = SocketAddr::from(([198, 18, 0, 1], port));
            let owner = queues.claim((local, remote), 3);
            *counts.get_mut(owner).unwrap() += 1;
            assert_eq!(queues.claim((local, remote), 1), owner);
            leases.push(queues.flow_owner(owner).acquire(local, remote).unwrap());
        }
        assert_eq!(counts, [2, 2, 2, 2]);
        drop(leases);
        assert!(lock(&queues.owners).flows.is_empty());
    }

    #[test]
    fn an_old_close_cannot_release_a_reused_address() {
        let queues = Arc::new(Queues::new(2));
        let local = "198.18.0.9:443".parse().unwrap();
        let remote = "198.18.0.1:40000".parse().unwrap();
        assert_eq!(queues.claim((local, remote), 1), 1);
        let old = queues.flow_owner(1).acquire(local, remote).unwrap();
        queues.retain(1, |_| false);
        assert_eq!(queues.claim((local, remote), 1), 1);
        let replacement = queues.flow_owner(1).acquire(local, remote).unwrap();
        drop(old);
        assert_eq!(queues.owner(&(local, remote)), Some(1));
        assert_eq!(lock(&queues.owners).flows.len(), 1);
        drop(replacement);
        assert_eq!(queues.owner(&(local, remote)), None);
    }

    #[test]
    fn a_reused_address_claimed_by_another_queue_refuses_the_old_queue() {
        let queues = Arc::new(Queues::new(2));
        let local = "198.18.0.9:443".parse().unwrap();
        let remote = "198.18.0.1:40000".parse().unwrap();
        let key = (local, remote);
        assert_eq!(queues.claim(key, 0), 0);
        let old = queues.flow_owner(0).acquire(local, remote).unwrap();
        // A removes its TIME_WAIT connection; B wins claim before A can acquire again.
        drop(old);
        assert_eq!(queues.claim(key, 1), 1);
        let replacement = queues.flow_owner(1).acquire(local, remote).unwrap();
        assert!(queues.flow_owner(0).acquire(local, remote).is_none());
        queues.release_unopened(&key, 0);
        assert_eq!(queues.owner(&key), Some(1));
        assert!(queues.forward(1, b"retried SYN"));
        assert_eq!(queues.take(1), [b"retried SYN".to_vec()]);
        drop(replacement);
        assert_eq!(queues.owner(&key), None);
    }

    #[test]
    fn idle_owners_on_uneven_queues_do_not_bias_a_new_burst() {
        let queues = Arc::new(Queues::new(4));
        let local = "198.18.0.9:443".parse().unwrap();
        let remote = "198.18.0.1:40000".parse().unwrap();
        assert_eq!(queues.claim((local, remote), 2), 2);
        let _existing = queues.flow_owner(2).acquire(local, remote).unwrap();
        let transient = "198.18.0.1:39999".parse().unwrap();
        assert_eq!(queues.claim((local, transient), 0), 3);
        drop(queues.flow_owner(3).acquire(local, transient).unwrap());
        let second = "198.18.0.1:39998".parse().unwrap();
        assert_eq!(queues.claim((local, second), 0), 0);
        let _second = queues.flow_owner(0).acquire(local, second).unwrap();
        let mut counts = [0; 4];
        let mut leases = Vec::new();
        for port in 40001..40009 {
            let remote = SocketAddr::from(([198, 18, 0, 1], port));
            let owner = queues.claim((local, remote), 0);
            *counts.get_mut(owner).unwrap() += 1;
            leases.push(queues.flow_owner(owner).acquire(local, remote).unwrap());
        }
        assert_eq!(counts, [2, 2, 2, 2]);
    }

    #[test]
    fn rejected_syns_do_not_keep_an_owner_reservation() {
        let queues = Queues::new(2);
        let key = (
            "198.18.0.9:443".parse().unwrap(),
            "198.18.0.1:40000".parse().unwrap(),
        );
        assert_eq!(queues.claim(key, 1), 1);
        queues.release_unopened(&key, 1);
        assert_eq!(queues.owner(&key), None);
        assert!(lock(&queues.owners).flows.is_empty());
    }
}
