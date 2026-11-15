use std::io;
use std::sync::{Arc, Mutex};

use crate::util::lock;

/// Counts the resets of a node's shared connections, so that a dial can tell whether one ran
/// while it was under way: what it made then went out on the network the reset left.
#[derive(Default)]
pub(crate) struct Resets(u64);

/// The resets a dial started after.
#[derive(Clone, Copy)]
pub(crate) struct Ticket(u64);

impl Resets {
    pub(crate) fn ticket(&self) -> Ticket {
        Ticket(self.0)
    }

    pub(crate) fn bump(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    pub(crate) fn none_since(&self, ticket: Ticket) -> bool {
        self.0 == ticket.0
    }
}

/// What a dial that a reset overtook fails with, as sing-quic fails the callers waiting on a
/// handshake its reset discards.
pub(crate) fn overtaken() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the network changed while connecting",
    )
}

/// A node's one shared connection.
pub(crate) struct SessionSlot<T> {
    held: Mutex<Held<T>>,
}

struct Held<T> {
    resets: Resets,
    conn: Option<Arc<T>>,
}

impl<T> Default for SessionSlot<T> {
    fn default() -> Self {
        SessionSlot {
            held: Mutex::new(Held {
                resets: Resets::default(),
                conn: None,
            }),
        }
    }
}

impl<T> SessionSlot<T> {
    /// The held connection if `usable` says it still is, and the ticket a dial for a new one
    /// starts with.
    pub(crate) fn get(&self, usable: impl Fn(&T) -> bool) -> (Option<Arc<T>>, Ticket) {
        let held = lock(&self.held);
        let conn = held.conn.as_ref().filter(|conn| usable(conn)).cloned();
        (conn, held.resets.ticket())
    }

    /// Holds `conn` unless a reset ran since `ticket`. On false the caller tears `conn` down.
    pub(crate) fn keep(&self, ticket: Ticket, conn: &Arc<T>) -> bool {
        let mut held = lock(&self.held);
        if !held.resets.none_since(ticket) {
            return false;
        }
        held.conn = Some(conn.clone());
        true
    }

    pub(crate) fn reset(&self) -> Option<Arc<T>> {
        let mut held = lock(&self.held);
        held.resets.bump();
        held.conn.take()
    }

    pub(crate) fn forget(&self, conn: &Arc<T>) {
        let mut held = lock(&self.held);
        if held
            .conn
            .as_ref()
            .is_some_and(|kept| Arc::ptr_eq(kept, conn))
        {
            held.conn = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_dialled_before_a_reset_is_not_kept() {
        let slot = SessionSlot::default();
        let (_, before) = slot.get(|_: &u8| true);
        assert!(slot.reset().is_none());
        assert!(!slot.keep(before, &Arc::new(1)));
        assert!(slot.get(|_| true).0.is_none());
        let (_, after) = slot.get(|_| true);
        assert!(slot.keep(after, &Arc::new(2)));
        assert_eq!(slot.get(|_| true).0.as_deref(), Some(&2));
        assert!(slot.get(|value| *value != 2).0.is_none());
    }

    #[test]
    fn forgetting_takes_out_only_the_connection_named() {
        let slot = SessionSlot::default();
        let (first, second) = (Arc::new(1u8), Arc::new(1u8));
        assert!(slot.keep(slot.get(|_| true).1, &first));
        slot.forget(&second);
        assert!(slot.get(|_| true).0.is_some());
        slot.forget(&first);
        assert!(slot.get(|_| true).0.is_none());
    }
}
