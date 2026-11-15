use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use concord_common::RawSocket;
use concord_platform::{Platform, SocketIdentity, with_same_socket};

/// Sockets whose `protect` is owed: Android routes every socket of the VPN app into its VPN once
/// it is established, sockets opened before then included, and protects one only while it is.
/// Each is protected on the next activation, unless it closed in between.
///
/// `activations` counts activations, each taken with the list in one critical section: a socket
/// held under the count it saw before its `protect` failed cannot miss the activation that would
/// have let it succeed. No lock is held while the host answers.
#[derive(Default)]
pub(crate) struct Held {
    activations: AtomicU64,
    state: Mutex<State>,
    pub(crate) identity: OnceLock<SocketIdentity>,
}

#[derive(Default)]
struct State {
    sockets: Vec<Entry>,
    limit: usize,
}

#[derive(Clone, Copy)]
struct Entry {
    socket: RawSocket,
    identity: u64,
}

impl Held {
    /// Protects a socket the caller owns, or holds it for the next activation.
    pub(crate) fn guard(&self, platform: &dyn Platform, socket: RawSocket) {
        let seen = self.activations.load(Ordering::Acquire);
        if platform.protect(socket) {
            return;
        }
        let kind = *self.identity.get_or_init(|| SocketIdentity::probe(socket));
        let Some(identity) = kind.of(socket) else {
            tracing::warn!("protect: socket {} has no identity; not held", socket.0);
            return;
        };
        self.hold(Entry { socket, identity }, seen, |entry| {
            Some(platform.protect(entry.socket))
        });
    }

    /// Protects every held socket that is still open, through a duplicate of its descriptor so a
    /// number reused by an unrelated socket is never touched.
    pub(crate) fn activate(&self, platform: &dyn Platform) {
        let (taken, seen) = {
            let mut state = self.lock();
            let seen = self.activations.fetch_add(1, Ordering::AcqRel) + 1;
            state.limit = 0;
            (std::mem::take(&mut state.sockets), seen)
        };
        let Some(&kind) = self.identity.get() else {
            return;
        };
        let protect = |entry: &Entry| {
            with_same_socket(entry.socket, kind, entry.identity, |dup| {
                platform.protect(dup)
            })
        };
        for entry in taken {
            if protect(&entry) == Some(false) {
                self.hold(entry, seen, protect);
            }
        }
    }

    /// Holds `entry`, refused under `seen` activations, unless an activation came in between:
    /// then it tries again. `protect` answers `None` for a socket that is gone.
    fn hold(&self, entry: Entry, mut seen: u64, protect: impl Fn(&Entry) -> Option<bool>) {
        loop {
            {
                let mut state = self.lock();
                let now = self.activations.load(Ordering::Acquire);
                if now == seen {
                    self.push(&mut state, entry);
                    return;
                }
                seen = now;
            }
            if protect(&entry) != Some(false) {
                return;
            }
        }
    }

    fn push(&self, state: &mut State, entry: Entry) {
        if state.sockets.len() >= state.limit
            && let Some(&kind) = self.identity.get()
        {
            state
                .sockets
                .retain(|held| kind.of(held.socket) == Some(held.identity));
            state.limit = 2 * state.sockets.len();
        }
        state.sockets.push(entry);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        concord_common::sync::lock(&self.state)
    }

    #[cfg(all(test, any(target_os = "linux", target_os = "android")))]
    pub(crate) fn len(&self) -> usize {
        self.lock().sockets.len()
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::test_support::FakePlatform;
    use concord_common::sync::lock;

    #[allow(
        clippy::disallowed_methods,
        reason = "the registry is tested on bare loopback sockets"
    )]
    fn udp() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    fn raw(socket: &impl AsRawFd) -> RawSocket {
        RawSocket(i64::from(socket.as_raw_fd()))
    }

    fn inode(socket: &impl AsRawFd) -> Option<u64> {
        SocketIdentity::Inode.of(raw(socket))
    }

    fn refusing() -> FakePlatform {
        let platform = FakePlatform::default();
        platform.refuse.store(true, Ordering::SeqCst);
        platform
    }

    fn kinds() -> [SocketIdentity; 2] {
        [SocketIdentity::Inode, SocketIdentity::Cookie]
    }

    fn held(kind: SocketIdentity) -> Held {
        let held = Held::default();
        held.identity.set(kind).unwrap();
        held
    }

    #[test]
    fn a_socket_protected_at_once_is_not_held() {
        let (platform, held, socket) = (FakePlatform::default(), Held::default(), udp());
        held.guard(&platform, raw(&socket));
        assert_eq!(held.len(), 0);
        assert_eq!(*lock(&platform.protected_inodes), [inode(&socket)]);
    }

    #[test]
    fn a_held_socket_is_protected_on_activation() {
        for kind in kinds() {
            let (platform, held, socket) = (refusing(), self::held(kind), udp());
            held.guard(&platform, raw(&socket));
            assert_eq!(held.len(), 1);
            assert!(lock(&platform.protected).is_empty());

            platform.refuse.store(false, Ordering::SeqCst);
            held.activate(&platform);
            assert_eq!(held.len(), 0);
            assert_eq!(
                *lock(&platform.protected_inodes),
                [inode(&socket)],
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_closed_socket_is_dropped_and_its_reused_number_untouched() {
        for kind in kinds() {
            let (platform, held) = (refusing(), self::held(kind));
            let first = udp();
            held.guard(&platform, raw(&first));
            drop(first);
            let reuser = udp();

            platform.refuse.store(false, Ordering::SeqCst);
            held.activate(&platform);
            assert_eq!(held.len(), 0);
            assert!(
                lock(&platform.protected).is_empty(),
                "{kind:?}: protected {:?}, the reuser is {:?}",
                lock(&platform.protected_inodes),
                inode(&reuser)
            );
        }
    }

    #[test]
    fn a_socket_refused_on_activation_waits_for_the_next() {
        let (platform, held, socket) = (refusing(), Held::default(), udp());
        held.guard(&platform, raw(&socket));
        held.activate(&platform);
        assert_eq!(held.len(), 1);
        assert!(lock(&platform.protected).is_empty());

        platform.refuse.store(false, Ordering::SeqCst);
        held.activate(&platform);
        assert_eq!(held.len(), 0);
        assert_eq!(*lock(&platform.protected_inodes), [inode(&socket)]);
    }

    #[test]
    fn a_full_list_drops_its_closed_sockets_first() {
        let (platform, held) = (refusing(), held(SocketIdentity::Inode));
        let mut open: Vec<_> = (0..64).map(|_| udp()).collect();
        for socket in &open {
            held.guard(&platform, raw(socket));
        }
        open.truncate(4);
        let last = udp();
        held.guard(&platform, raw(&last));
        assert_eq!(held.len(), 5);
        assert_eq!(held.lock().limit, 8);

        platform.refuse.store(false, Ordering::SeqCst);
        held.activate(&platform);
        let mut protected = lock(&platform.protected_inodes).clone();
        let mut expected: Vec<_> = open.iter().chain([&last]).map(inode).collect();
        protected.sort_unstable();
        expected.sort_unstable();
        assert_eq!(protected, expected);
    }

    #[test]
    fn sockets_created_around_an_activation_are_all_protected() {
        const THREADS: usize = 4;
        const PER_THREAD: usize = 24;
        let platform = Arc::new(refusing());
        let held = Arc::new(Held::default());
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let (platform, held) = (Arc::clone(&platform), Arc::clone(&held));
                std::thread::spawn(move || {
                    (0..PER_THREAD)
                        .map(|_| {
                            let socket = udp();
                            held.guard(&*platform, raw(&socket));
                            std::thread::yield_now();
                            socket
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        std::thread::sleep(std::time::Duration::from_millis(2));
        platform.refuse.store(false, Ordering::SeqCst);
        held.activate(&*platform);
        let sockets: Vec<_> = workers
            .into_iter()
            .flat_map(|worker| worker.join().unwrap())
            .collect();

        assert_eq!(held.len(), 0);
        let protected = lock(&platform.protected_inodes);
        for socket in &sockets {
            assert!(protected.contains(&inode(socket)), "a socket was missed");
        }
        assert_eq!(protected.len(), THREADS * PER_THREAD);
    }
}
