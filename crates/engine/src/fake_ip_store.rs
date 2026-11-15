use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use concord_common::sync::lock;
use concord_dns::{FakeIpPool, Resolver};
use concord_platform::HomeDir;
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The `store-fake-ip` files of the engine, written by every config's saver in turn. A write
/// holds the store from its snapshot to the rename, so the snapshot that lands last is the
/// newest. A change counts as saved only once its write succeeds; a failed one is written
/// again with the next change or the stop. A config never rewrites a file a later config has
/// written, and still writes a file the later config does not keep. A config reads the files
/// back only after the latest saver has committed what it holds.
#[derive(Default)]
pub(crate) struct FakeIpStore {
    generation: AtomicU64,
    files: Mutex<Files>,
}

#[derive(Default)]
struct Files {
    written_by: HashMap<&'static str, u64>,
    saver: Option<(u64, Weak<Resolver>)>,
}

impl Files {
    fn commit<'a>(
        &mut self,
        generation: u64,
        pools: impl IntoIterator<Item = (&'static str, &'a FakeIpPool)>,
        mut write: impl FnMut(&str, &[u8]) -> io::Result<()>,
    ) {
        for (name, pool) in pools {
            if self.written_by.get(name).is_some_and(|&by| by > generation) {
                continue;
            }
            let Some((version, bytes)) = pool.pending() else {
                continue;
            };
            match write(name, &bytes) {
                Ok(()) => {
                    pool.mark_saved(version);
                    self.written_by.insert(name, generation);
                }
                Err(err) => tracing::warn!("[FakeIP] save {name} failed: {err}"),
            }
        }
    }
}

impl FakeIpStore {
    pub(crate) fn begin(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(crate) fn commit<'a>(
        &self,
        generation: u64,
        pools: impl IntoIterator<Item = (&'static str, &'a FakeIpPool)>,
        write: impl FnMut(&str, &[u8]) -> io::Result<()>,
    ) {
        lock(&self.files).commit(generation, pools, write);
    }

    fn restore_after_saving<'a>(
        &self,
        saver: Option<(
            u64,
            impl IntoIterator<Item = (&'static str, &'a FakeIpPool)>,
        )>,
        write: impl FnMut(&str, &[u8]) -> io::Result<()>,
        read_back: impl FnOnce(),
    ) {
        let mut files = lock(&self.files);
        if let Some((generation, pools)) = saver {
            files.commit(generation, pools, write);
        }
        read_back();
    }

    pub(crate) fn restore(&self, home: &HomeDir, dns: &Resolver) {
        let saver = lock(&self.files)
            .saver
            .as_ref()
            .and_then(|(generation, saver)| Some((*generation, saver.upgrade()?)));
        self.restore_after_saving(
            saver
                .as_ref()
                .map(|(generation, saver)| (*generation, saver.fake_ip_pools())),
            |name, bytes| home.write_atomic(home.join(name), bytes),
            || dns.restore_fake_ip(|name| home.read(home.join(name)).ok()),
        );
    }

    fn save(&self, generation: u64, home: &HomeDir, dns: &Resolver) {
        self.commit(generation, dns.fake_ip_pools(), |name, bytes| {
            home.write_atomic(home.join(name), bytes)
        });
    }
}

pub(crate) fn start(
    store: Arc<FakeIpStore>,
    tasks: &TaskTracker,
    handle: &Handle,
    home: Arc<HomeDir>,
    dns: Arc<Resolver>,
    stop: CancellationToken,
) {
    let generation = store.begin();
    lock(&store.files).saver = Some((generation, Arc::downgrade(&dns)));
    // mihomo writes each mapping as it is made. One write at a time takes in every mapping made
    // while the last one ran, so a burst costs as many writes as the disk can take.
    let saver = async move {
        loop {
            let stopped = tokio::select! {
                () = stop.cancelled() => true,
                () = dns.fake_ip_changed() => false,
            };
            let (store, home, dns) = (store.clone(), home.clone(), dns.clone());
            let _ = tokio::task::spawn_blocking(move || store.save(generation, &home, &dns)).await;
            if stopped {
                return;
            }
        }
    };
    tasks.spawn_on(saver, handle);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;

    use concord_config::net::IpCidr;

    use super::*;

    const V4: &str = "fake-ip.cache";
    const V6: &str = "fake-ip6.cache";

    fn pool(cidr: &str) -> FakeIpPool {
        FakeIpPool::new(IpCidr::parse(cidr).unwrap()).unwrap()
    }

    #[derive(Clone, Default)]
    struct Disk(Arc<Mutex<HashMap<String, Vec<u8>>>>);

    impl Disk {
        fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
            lock(&self.0).insert(name.into(), bytes.to_vec());
            Ok(())
        }

        fn read(&self, name: &str) -> Option<Vec<u8>> {
            lock(&self.0).get(name).cloned()
        }

        fn maps(&self, name: &str, range: &str, ip: IpAddr, host: &str) -> bool {
            let restored = pool(range);
            lock(&self.0)
                .get(name)
                .is_some_and(|bytes| restored.restore(bytes))
                && restored.look_back(ip).as_deref() == Some(host)
        }
    }

    #[test]
    fn a_write_that_failed_is_made_by_the_next_commit() {
        let store = FakeIpStore::default();
        let generation = store.begin();
        let pool = pool("198.18.0.1/16");
        let ip = pool.lookup("kept.test").unwrap();
        store.commit(generation, [(V4, &pool)], |_, _| {
            Err(io::Error::other("disk full"))
        });
        let disk = Disk::default();
        store.commit(generation, [(V4, &pool)], |name, bytes| {
            disk.write(name, bytes)
        });
        assert!(disk.maps(V4, "198.18.0.1/16", ip, "kept.test"));
    }

    #[test]
    fn a_snapshot_never_lands_after_a_newer_one() {
        let store = Arc::new(FakeIpStore::default());
        let generation = store.begin();
        let pool = Arc::new(pool("198.18.0.1/16"));
        pool.lookup("first.test");
        let disk = Disk::default();
        let (entered, writing) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let slow = {
            let (store, pool, disk) = (store.clone(), pool.clone(), disk.clone());
            std::thread::spawn(move || {
                store.commit(generation, [(V4, &*pool)], |name, bytes| {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    disk.write(name, bytes)
                });
            })
        };
        writing.recv().unwrap();
        let newer = pool.lookup("newer.test").unwrap();
        let (done, finished) = mpsc::channel();
        let fast = {
            let (store, pool, disk) = (store.clone(), pool.clone(), disk.clone());
            std::thread::spawn(move || {
                store.commit(generation, [(V4, &*pool)], |name, bytes| {
                    disk.write(name, bytes)
                });
                done.send(()).unwrap();
            })
        };
        // A store that lets the second commit overtake the first finishes it within this wait,
        // and the first one's older bytes then land last.
        let _ = finished.recv_timeout(Duration::from_millis(200));
        release.send(()).unwrap();
        slow.join().unwrap();
        fast.join().unwrap();
        assert!(disk.maps(V4, "198.18.0.1/16", newer, "newer.test"));
    }

    #[test]
    fn a_config_reads_back_what_the_saving_config_holds_now() {
        let store = FakeIpStore::default();
        let generation = store.begin();
        let old = pool("198.18.0.1/16");
        old.lookup("flushed.test");
        let disk = Disk::default();
        store.commit(generation, [(V4, &old)], |name, bytes| {
            disk.write(name, bytes)
        });
        old.flush();
        let new = pool("198.18.0.1/16");
        store.restore_after_saving(
            Some((generation, [(V4, &old)])),
            |name, bytes| disk.write(name, bytes),
            || {
                if let Some(bytes) = disk.read(V4) {
                    new.restore(&bytes);
                }
            },
        );
        assert!(new.is_empty(), "a flushed mapping came back from the file");
    }

    #[test]
    fn a_newer_config_supersedes_only_the_files_it_has_written() {
        let store = FakeIpStore::default();
        let old = store.begin();
        let (old4, old6) = (pool("198.18.0.1/16"), pool("fdfe:dcba:9876::1/64"));
        old4.lookup("old.test");
        let kept = old6.lookup("old.test").unwrap();
        let new = store.begin();
        let new4 = pool("198.19.0.1/16");
        let moved = new4.lookup("new.test").unwrap();
        let disk = Disk::default();
        let write = |name: &str, bytes: &[u8]| disk.write(name, bytes);
        store.commit(new, [(V4, &new4)], write);
        store.commit(old, [(V4, &old4), (V6, &old6)], write);
        assert!(disk.maps(V4, "198.19.0.1/16", moved, "new.test"));
        assert!(disk.maps(V6, "fdfe:dcba:9876::1/64", kept, "old.test"));
    }
}
