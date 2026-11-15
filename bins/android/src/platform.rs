use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use concord_common::{FlowKey, Network, ProcessInfo, RawSocket};
use concord_platform::owner::procnet::{self, Match};
use concord_platform::{FdPressure, InterfaceInfo, Platform};

const PROCFS_FROM_SDK: i32 = 29;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;

/// What the `VpnService` answers. Every call may block, so none of them is made while a lock of the core is held.
pub trait PlatformHost: Send + Sync + 'static {
    /// `false` when the service refused, as while its VPN is not established.
    fn protect(&self, fd: i32) -> bool;
    fn resolve_uid(&self, protocol: i32, source: &str, target: &str) -> i32;
    fn resolve_package(&self, uid: i32) -> String;
}

type SdkSource = Box<dyn Fn() -> i32 + Send + Sync>;
type ProcfsLookup = fn(Network, SocketAddr) -> Option<u32>;

pub struct AndroidPlatform<C> {
    host: ArcSwapOption<C>,
    sdk_version: OnceLock<SdkSource>,
    pressure: FdPressure,
    procfs: ProcfsLookup,
}

impl<C: PlatformHost> Default for AndroidPlatform<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: PlatformHost> AndroidPlatform<C> {
    pub fn new() -> Self {
        Self::with_procfs(procfs_uid)
    }

    fn with_procfs(procfs: ProcfsLookup) -> Self {
        AndroidPlatform {
            host: ArcSwapOption::empty(),
            sdk_version: OnceLock::new(),
            pressure: FdPressure::new(),
            procfs,
        }
    }

    /// The engine owns the SDK level `core.init` reports, and is built after the platform.
    pub fn bind_sdk_version(&self, source: impl Fn() -> i32 + Send + Sync + 'static) {
        let _ = self.sdk_version.set(Box::new(source));
    }

    pub fn set_host(&self, host: Option<Arc<C>>) {
        self.host.store(host);
    }

    pub fn has_host(&self) -> bool {
        self.host.load().is_some()
    }

    fn sdk_version(&self) -> i32 {
        self.sdk_version.get().map_or(0, |source| source())
    }
}

#[async_trait]
impl<C: PlatformHost> Platform for AndroidPlatform<C> {
    fn protect(&self, socket: RawSocket) -> bool {
        let Some(host) = self.host.load_full() else {
            return false;
        };
        i32::try_from(socket.0).is_ok_and(|fd| host.protect(fd))
    }

    async fn find_owner(&self, flow: &FlowKey) -> Option<ProcessInfo> {
        let host = self.host.load_full()?;
        let flow = *flow;
        let procfs = (self.sdk_version() < PROCFS_FROM_SDK).then_some(self.procfs);
        let lookup = tokio::task::spawn_blocking(move || resolve_owner(&*host, procfs, &flow));
        match lookup.await {
            Ok(owner) => owner,
            Err(err) => {
                tracing::warn!("process lookup task failed: {err}");
                None
            }
        }
    }

    fn default_interface(&self) -> Option<InterfaceInfo> {
        None
    }

    fn system_dns(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    fn fd_pressure(&self) -> bool {
        self.pressure.should_block()
    }
}

fn resolve_owner<C: PlatformHost>(
    host: &C,
    procfs: Option<ProcfsLookup>,
    flow: &FlowKey,
) -> Option<ProcessInfo> {
    let uid = match procfs {
        Some(lookup) => lookup(flow.network, flow.src).map_or(-1, |uid| uid as i32),
        None => host.resolve_uid(
            protocol_of(flow.network),
            &flow.src.to_string(),
            &flow.dst.to_string(),
        ),
    };
    let unsigned = u32::try_from(uid).ok()?;
    Some(ProcessInfo {
        uid: Some(unsigned),
        name: host.resolve_package(uid),
        path: String::new(),
    })
}

fn protocol_of(network: Network) -> i32 {
    match network {
        Network::Tcp => IPPROTO_TCP,
        Network::Udp => IPPROTO_UDP,
    }
}

fn procfs_uid(network: Network, src: SocketAddr) -> Option<u32> {
    procnet::lookup(network, src, Match::Exact).map(|entry| entry.uid)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    use concord_common::sync::lock;

    #[derive(Default)]
    struct Recorder {
        protected: Mutex<Vec<i32>>,
        refuse: std::sync::atomic::AtomicBool,
        uid_calls: Mutex<Vec<(i32, String, String)>>,
        uid: i32,
        package: String,
    }

    impl PlatformHost for Recorder {
        fn protect(&self, fd: i32) -> bool {
            if self.refuse.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            lock(&self.protected).push(fd);
            true
        }

        fn resolve_uid(&self, protocol: i32, source: &str, target: &str) -> i32 {
            lock(&self.uid_calls).push((protocol, source.to_string(), target.to_string()));
            self.uid
        }

        fn resolve_package(&self, uid: i32) -> String {
            format!("{}:{uid}", self.package)
        }
    }

    fn flow(network: Network) -> FlowKey {
        FlowKey {
            network,
            src: "10.0.0.2:41000".parse().unwrap(),
            dst: "[2001:db8::1]:443".parse().unwrap(),
        }
    }

    fn platform(recorder: Recorder, sdk: i32) -> (AndroidPlatform<Recorder>, Arc<Recorder>) {
        let platform =
            AndroidPlatform::with_procfs(|_, src| (src.port() == 41000).then_some(10_123));
        platform.bind_sdk_version(move || sdk);
        let recorder = Arc::new(recorder);
        platform.set_host(Some(recorder.clone()));
        (platform, recorder)
    }

    #[test]
    fn protect_reaches_the_host_only_while_it_is_set_and_reports_its_answer() {
        let (platform, recorder) = platform(Recorder::default(), 34);
        assert!(platform.protect(RawSocket(7)));
        recorder
            .refuse
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!platform.protect(RawSocket(9)));
        recorder
            .refuse
            .store(false, std::sync::atomic::Ordering::Relaxed);
        platform.set_host(None);
        assert!(!platform.protect(RawSocket(8)));
        assert_eq!(*lock(&recorder.protected), vec![7]);
        assert!(!platform.has_host());
    }

    #[tokio::test]
    async fn from_sdk_29_the_uid_comes_from_the_service() {
        let recorder = Recorder {
            uid: 10_050,
            package: "app".into(),
            ..Recorder::default()
        };
        let (platform, recorder) = platform(recorder, 29);
        let owner = platform.find_owner(&flow(Network::Udp)).await.unwrap();
        assert_eq!(owner.uid, Some(10_050));
        assert_eq!(owner.name, "app:10050");
        assert!(owner.path.is_empty());
        assert_eq!(
            *lock(&recorder.uid_calls),
            vec![(
                17,
                "10.0.0.2:41000".to_string(),
                "[2001:db8::1]:443".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn below_sdk_29_procfs_answers_and_the_service_only_names_the_package() {
        let recorder = Recorder {
            uid: 1,
            package: "app".into(),
            ..Recorder::default()
        };
        let (platform, recorder) = platform(recorder, 28);
        let owner = platform.find_owner(&flow(Network::Tcp)).await.unwrap();
        assert_eq!(owner.uid, Some(10_123));
        assert_eq!(owner.name, "app:10123");
        assert!(lock(&recorder.uid_calls).is_empty());
    }

    #[tokio::test]
    async fn an_unknown_uid_is_no_owner() {
        let recorder = Recorder {
            uid: -1,
            ..Recorder::default()
        };
        let (platform, _) = platform(recorder, 34);
        assert!(platform.find_owner(&flow(Network::Tcp)).await.is_none());

        let (platform, _) = self::platform(Recorder::default(), 28);
        let mut other = flow(Network::Tcp);
        other.src.set_port(1);
        assert!(platform.find_owner(&other).await.is_none());
    }

    #[tokio::test]
    async fn without_a_host_nothing_is_asked() {
        let (platform, _) = platform(Recorder::default(), 34);
        platform.set_host(None);
        assert!(platform.find_owner(&flow(Network::Tcp)).await.is_none());
    }

    #[test]
    fn the_unbound_sdk_level_reads_as_unknown() {
        let platform = AndroidPlatform::<Recorder>::new();
        assert_eq!(platform.sdk_version(), 0);
    }

    #[test]
    fn the_platform_has_no_default_interface_no_system_dns_and_no_pressure() {
        let platform = AndroidPlatform::<Recorder>::new();
        assert!(platform.default_interface().is_none());
        assert!(platform.system_dns().is_empty());
        assert!(!platform.fd_pressure());
    }
}
