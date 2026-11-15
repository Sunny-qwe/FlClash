use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use concord_common::sync;

use super::select::{Subnet, by_addr};
use crate::InterfaceInfo;

/// mihomo keeps its interface table this long (`component/iface/iface.go`), a bound for
/// changes no monitor reports.
const MAX_AGE: Duration = Duration::from_secs(20);

/// One reading of the interfaces and the default route. A dial answers from it: reading
/// them live dumps the kernel's interface, address and route tables on every connection.
pub struct Tables {
    subnets: Vec<Subnet>,
    interfaces: Vec<InterfaceInfo>,
    local: Vec<IpAddr>,
    default: Option<InterfaceInfo>,
    excluded: Vec<String>,
}

impl Tables {
    #[cfg(unix)]
    pub fn read(excluded: &[String]) -> Self {
        let mut subnets = Vec::new();
        let mut local = Vec::new();
        let mut named: Vec<(String, Vec<IpAddr>)> = Vec::new();
        super::ifaces::walk(|name, flags, addr, prefix| {
            let name = name.to_string_lossy();
            if flags & libc::IFF_UP as u32 != 0 {
                subnets.push(Subnet {
                    name: name.to_string(),
                    addr,
                    prefix,
                });
            }
            local.push(addr);
            match named.iter_mut().find(|(known, _)| *known == name) {
                Some((_, addrs)) => addrs.push(addr),
                None => named.push((name.into_owned(), vec![addr])),
            }
        });
        let interfaces = named
            .into_iter()
            .filter_map(|(name, addrs)| {
                Some(InterfaceInfo {
                    index: super::ifaces::index_of(&name)?,
                    name: name.into(),
                    addrs,
                })
            })
            .collect();
        Self {
            subnets,
            interfaces,
            local,
            default: super::default_interface(excluded),
            excluded: excluded.to_vec(),
        }
    }

    #[cfg(windows)]
    pub fn read(excluded: &[String]) -> Self {
        let adapters = super::win::adapters();
        Self {
            subnets: super::win::subnets(&adapters),
            interfaces: adapters.into_iter().map(|adapter| adapter.info).collect(),
            local: super::win::local_addrs(),
            default: super::default_interface(excluded),
            excluded: excluded.to_vec(),
        }
    }

    #[cfg(not(any(unix, windows)))]
    pub fn read(excluded: &[String]) -> Self {
        Self {
            subnets: Vec::new(),
            interfaces: Vec::new(),
            local: Vec::new(),
            default: None,
            excluded: excluded.to_vec(),
        }
    }

    /// An interface without an address is missing from the table, so it is looked up live.
    pub fn by_name(&self, name: &str) -> Option<InterfaceInfo> {
        self.interfaces
            .iter()
            .find(|info| &*info.name == name)
            .cloned()
            .or_else(|| super::interface_by_name(name))
    }

    pub fn default_interface(&self) -> Option<InterfaceInfo> {
        self.default.clone()
    }

    pub fn interface_for(&self, dest: IpAddr) -> Option<InterfaceInfo> {
        by_addr(&self.subnets, dest)
            .filter(|found| !self.excluded.contains(&found.name))
            .and_then(|found| self.by_name(&found.name))
            .or_else(|| self.default_interface())
    }

    pub fn is_local_ip(&self, ip: IpAddr) -> bool {
        self.local.contains(&ip)
    }
}

/// The last `Tables`, read again by the first lookup after a change or `MAX_AGE`, so a
/// burst of route events costs one reading.
#[derive(Default)]
pub struct Cache {
    held: RwLock<Option<Held>>,
    changed: AtomicU64,
}

struct Held {
    tables: Arc<Tables>,
    epoch: (u64, u64),
    at: Instant,
}

impl Cache {
    pub fn invalidate(&self) {
        self.changed.fetch_add(1, Ordering::Release);
    }

    pub fn get(&self, read: impl FnOnce() -> Tables) -> Arc<Tables> {
        self.get_at(Instant::now(), super::watch::epoch(), read)
    }

    fn get_at(&self, now: Instant, network: u64, read: impl FnOnce() -> Tables) -> Arc<Tables> {
        let epoch = (network, self.changed.load(Ordering::Acquire));
        let fresh = |held: &Option<Held>| {
            held.as_ref()
                .filter(|held| held.epoch == epoch && now.duration_since(held.at) < MAX_AGE)
                .map(|held| Arc::clone(&held.tables))
        };
        if let Some(tables) = fresh(&sync::read(&self.held)) {
            return tables;
        }
        let mut held = sync::write(&self.held);
        if let Some(tables) = fresh(&held) {
            return tables;
        }
        let tables = Arc::new(read());
        *held = Some(Held {
            tables: Arc::clone(&tables),
            epoch,
            at: now,
        });
        tables
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn info(name: &str, index: u32, addr: &str) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            index,
            addrs: vec![addr.parse().unwrap()],
        }
    }

    fn sample(excluded: &[&str]) -> Tables {
        Tables {
            subnets: vec![Subnet {
                name: "eth0".into(),
                addr: "192.168.1.5".parse().unwrap(),
                prefix: 24,
            }],
            interfaces: vec![info("eth0", 2, "192.168.1.5"), info("wlan0", 3, "10.0.0.7")],
            local: vec!["192.168.1.5".parse().unwrap(), "10.0.0.7".parse().unwrap()],
            default: Some(info("wlan0", 3, "10.0.0.7")),
            excluded: excluded.iter().map(|name| name.to_string()).collect(),
        }
    }

    #[test]
    fn a_destination_off_every_subnet_takes_the_default_interface() {
        let tables = sample(&[]);
        let on = tables
            .interface_for("192.168.1.80".parse().unwrap())
            .unwrap();
        assert_eq!((&*on.name, on.index), ("eth0", 2));
        let off = tables.interface_for("10.211.1.2".parse().unwrap()).unwrap();
        assert_eq!(&*off.name, "wlan0");
        let excluded = sample(&["eth0"]);
        let on = excluded
            .interface_for("192.168.1.80".parse().unwrap())
            .unwrap();
        assert_eq!(&*on.name, "wlan0");
        assert!(tables.is_local_ip("10.0.0.7".parse().unwrap()));
        assert!(!tables.is_local_ip("10.0.0.8".parse().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn the_loopback_subnet_is_read_with_its_mask() {
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let read = Tables::read(&[]);
        assert!(read.subnets.iter().any(|subnet| subnet.name == loopback
            && subnet.addr == IpAddr::from([127, 0, 0, 1])
            && subnet.prefix == 8));
        assert!(read.is_local_ip(IpAddr::from([127, 0, 0, 1])));
        assert_eq!(
            read.by_name(loopback).map(|info| info.name),
            Some(loopback.into())
        );
    }

    fn counted(cache: &Cache, reads: &Cell<u32>, now: Instant, network: u64) -> Arc<Tables> {
        cache.get_at(now, network, || {
            reads.set(reads.get() + 1);
            sample(&[])
        })
    }

    #[test]
    fn the_tables_are_read_again_only_after_a_change_or_their_age() {
        let cache = Cache::default();
        let reads = Cell::new(0);
        let start = Instant::now();
        for _ in 0..3 {
            counted(&cache, &reads, start, 0);
        }
        assert_eq!(reads.get(), 1);
        counted(&cache, &reads, start, 1);
        assert_eq!(reads.get(), 2);
        cache.invalidate();
        cache.invalidate();
        counted(&cache, &reads, start, 1);
        counted(&cache, &reads, start + MAX_AGE / 2, 1);
        assert_eq!(reads.get(), 3);
        counted(&cache, &reads, start + MAX_AGE, 1);
        assert_eq!(reads.get(), 4);
    }
}
