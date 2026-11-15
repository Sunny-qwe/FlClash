use std::collections::BTreeMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use concord_common::sync::lock;
use concord_common::{
    Change, ClockOffset, ConnRecord, CoreEvent, CoreOptions, DelayResult, EventSink,
    FindProcessMode, GeneralChange, LogLevel, Origin, RouteStamp, RouteView, StateChange,
    TunnelMode,
};
use concord_config::Profile;
use concord_config::tun::TunConfig;
use concord_dns::{QueryError, QueryView, Resolver};
use concord_group::{NodeStateView, Outbounds, ProxyViews, SelectionStore, StatusRanges};
use concord_inbound::{ListenSpec, Listeners};
use concord_net::{LoopbackGuard, Sockets};
use concord_platform::{HomeDir, Platform, mmap};
use concord_rules::compile_rule_set;
use concord_rules::geo::GeoStore;
use concord_tls::TrustStore;
use concord_tun::{Congestion, DeviceSource, Prefix, TunRunner};
use concord_tunnel::{ConnTable, LiveOptions, Tunnel, TunnelStatus};
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;

use crate::apply::{self, Applied, Options, Shared, TrustCache, TunnelUpstream, listen_spec};
use crate::dns_server::DnsServer;
use crate::error::Failure;
use crate::fake_ip_store;
use crate::faults::{Faults, Service, ServiceFault};
use crate::ntp::{self, NtpSettings};
use crate::ops;
use crate::probe::{Prober, RouteHit};
use crate::probe_env::TunnelProbes;
use crate::resources::{self, GeoUpdater, GeoUrls, TunnelFetcher};
use crate::route::RouteCounters;
use crate::tun::{KeepOffDevice, congestion_of, options_of, start_runner, stop_runner};
#[cfg(unix)]
use crate::tun::{VpnTunRequest, vpn_options};
use crate::views::*;

#[cfg_attr(not(feature = "mitm"), path = "engine/mitm_disabled.rs")]
mod mitm;
mod providers;
#[cfg(test)]
mod tests;

pub use mitm::MitmService;
pub use providers::Providers;
use providers::request_failure;

pub struct EngineConfig {
    pub sink: Arc<dyn EventSink>,
    pub android: bool,
    pub platform: Arc<dyn Platform>,
}

pub struct SetupRequest {
    pub base: Option<(String, String)>,
    pub selected: BTreeMap<String, String>,
    pub options: CoreOptions,
}

pub struct TunPatch {
    pub enable: bool,
    pub device: Option<String>,
    pub stack: Option<String>,
    pub auto_route: Option<bool>,
}

pub struct UpdateRequest {
    pub tun: Option<TunPatch>,
    pub allow_lan: Option<bool>,
    pub mixed_port: Option<u16>,
    pub find_process_mode: Option<String>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    pub tcp_concurrent: Option<bool>,
    pub unified_delay: Option<bool>,
    pub authentication: Option<Vec<String>>,
    pub geo_auto_update: Option<bool>,
    pub geo_update_interval: Option<i64>,
    pub geox_url: BTreeMap<String, String>,
    pub options: Option<CoreOptions>,
}

pub struct Engine {
    home: ArcSwapOption<HomeDir>,
    initialized: AtomicBool,
    running: AtomicBool,
    sdk_version: AtomicI32,
    route: Arc<RouteCounters>,
    android: bool,
    shared: Shared,
    table: Arc<ConnTable>,
    listeners: Listeners,
    /// `configMu`: one apply or update at a time, with what is in force.
    state: AsyncMutex<Option<Applied>>,
    /// Taken after `state`, never the other way round.
    tun: AsyncMutex<Option<TunRunner>>,
    tun_config: StdMutex<Option<(TunConfig, Option<Prefix>, bool)>>,
    dns_server: AsyncMutex<Option<DnsServer>>,
    faults: Faults,
    warnings: ArcSwap<Vec<WarningView>>,
    system_dns: StdMutex<Option<Vec<SocketAddr>>>,
    dns_update_seq: AtomicU64,
    mitm: MitmService,
    handle: Handle,
    prober: Prober,
    /// What a config's `stop` ends; shutdown waits for it, so nothing outlives the engine.
    tasks: TaskTracker,
    /// The last change of state a host keeps. Taken after `state`; held only to
    /// set a value and publish its change, never across a probe or a load.
    intent: Arc<AsyncMutex<u64>>,
    /// Whether the profile's `external-controller` and `secret` count, as they do
    /// when the core runs on its own; a host sets them through `config.patch`.
    profile_controller: AtomicBool,
    /// Released once the apply in progress has answered; until then each
    /// provider's first load keeps its outcome to itself. Released when no
    /// apply holds it.
    answered: StdMutex<CancellationToken>,
}

const NOT_INITIALIZED: &str = "not initialized";
const DEFAULT_DELAY_TIMEOUT: Duration = Duration::from_secs(5);

impl Engine {
    /// Call inside the runtime that should carry the flows.
    pub fn new(config: EngineConfig) -> Arc<Self> {
        let events = config.sink;
        let route = Arc::new(RouteCounters::new(events.clone()));
        let loopback_guard = LoopbackGuard::new(!config.android);
        let loopback = (!config.android).then(|| loopback_guard.clone());
        let sockets = Arc::new(Sockets::new(config.platform.clone()));
        let table = ConnTable::new(events.clone());
        let tunnel = Tunnel::new(table.clone(), loopback_guard);
        let options = Arc::new(ArcSwap::from_pointee(CoreOptions::default()));
        let fetcher = Arc::new(TunnelFetcher {
            tunnel: tunnel.clone(),
            trust: ArcSwap::new(TrustStore::from_parts(Vec::new(), &[], Vec::new())),
            options: options.clone(),
            user_agent: ArcSwap::from_pointee("clash.meta".to_string()),
        });
        let geo_store = Arc::new(GeoStore::new(".").with_opener(mmap::open_read_only));
        let prober = Prober::new(Arc::new(TunnelProbes {
            tunnel: tunnel.clone(),
            route: route.clone(),
            fetcher: fetcher.clone(),
        }));
        let clock = Arc::new(ClockOffset::default());
        let shared = Shared {
            platform: config.platform,
            sockets,
            loopback,
            upstream: Arc::new(TunnelUpstream {
                tunnel: tunnel.clone(),
            }),
            tunnel,
            route: route.clone(),
            options: Arc::new(Options {
                current: options,
                unified_delay: AtomicBool::new(false),
            }),
            trust: TrustCache::new(clock.clone()),
            clock,
            geo: GeoUpdater::new(geo_store, events.clone(), route.clone()),
            events,
            fetcher,
            rule_providers: ArcSwapOption::empty(),
            fake_ip_store: Arc::default(),
            android: config.android,
        };
        Arc::new(Engine {
            home: ArcSwapOption::empty(),
            initialized: AtomicBool::new(false),
            running: AtomicBool::new(false),
            sdk_version: AtomicI32::new(0),
            route,
            android: config.android,
            shared,
            table: table.clone(),
            listeners: Listeners::native(),
            state: AsyncMutex::new(None),
            tun: AsyncMutex::new(None),
            tun_config: StdMutex::new(None),
            dns_server: AsyncMutex::new(None),
            faults: Faults::default(),
            warnings: ArcSwap::from_pointee(Vec::new()),
            system_dns: StdMutex::new(None),
            dns_update_seq: AtomicU64::new(0),
            mitm: MitmService::new(table.clone()),
            handle: Handle::current(),
            prober,
            tasks: TaskTracker::new(),
            intent: Arc::new(AsyncMutex::new(0)),
            profile_controller: AtomicBool::new(false),
            answered: StdMutex::new(released()),
        })
    }

    pub fn home(&self) -> Option<Arc<HomeDir>> {
        self.home.load_full()
    }

    pub fn is_android(&self) -> bool {
        self.android
    }

    fn runtime(&self) -> Option<Arc<concord_tunnel::Runtime>> {
        self.shared.tunnel.runtime()
    }

    fn outbounds(&self) -> Option<Arc<Outbounds>> {
        self.runtime().map(|runtime| runtime.outbounds.clone())
    }

    pub fn init(&self, home_dir: &str, sdk_version: i32) -> Result<(), Failure> {
        self.sdk_version.store(sdk_version, Ordering::SeqCst);
        let home = Arc::new(HomeDir::new(home_dir));
        self.shared.geo.set_home(home.clone());
        self.shared.geo.store.set_dir(home.root());
        #[cfg(unix)]
        home.reclaim();
        self.start_mitm(&home);
        self.home.store(Some(home));
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// The CA and the script store live under the home directory, so this waits for
    /// `core.init`; a repeat with the same directory keeps the engine and its captures.
    fn start_mitm(&self, home: &Arc<HomeDir>) {
        let same_home = self
            .home
            .load()
            .as_ref()
            .is_some_and(|current| current.root() == home.root());
        if same_home && self.mitm.is_started() {
            return;
        }
        self.mitm
            .start(home, &self.shared.tunnel, self.is_running());
    }

    pub fn mitm(&self) -> &MitmService {
        &self.mitm
    }

    fn set_running(&self, running: bool) {
        self.running.store(running, Ordering::SeqCst);
        self.mitm.set_running(running);
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn sdk_version(&self) -> i32 {
        self.sdk_version.load(Ordering::SeqCst)
    }

    pub fn release_memory(&self) {
        if let Some(outbounds) = self.outbounds() {
            outbounds.reset_sessions();
        }
        concord_platform::release_free_memory();
    }

    pub fn memory_stats(&self) -> MemoryStats {
        MemoryStats {
            rss: concord_platform::resident_memory(),
            ..Default::default()
        }
    }

    pub fn capabilities(&self) -> Capabilities {
        let config = apply::capabilities();
        Capabilities {
            implementation: concord_common::CORE_NAME,
            version: env!("CARGO_PKG_VERSION"),
            proxy_types: config.proxy_types,
            transports: config.transports,
            rule_types: config.rule_types,
            ss_plugins: config.ss_plugins,
            congestion_controllers: Congestion::NAMES.to_vec(),
            features: Features {
                mitm: MitmService::ENABLED,
                ech: config.ech,
                system_stack: false,
            },
        }
    }

    fn apply_options(&self, options: &CoreOptions) {
        let mut current = (**self.shared.options.current.load()).clone();
        if !options.test_url.is_empty() {
            current.test_url.clone_from(&options.test_url);
        }
        if options.delay_test_timeout != 0 {
            current.delay_test_timeout = options.delay_test_timeout;
        }
        current.skip_cert_verify = options.skip_cert_verify;
        current.mitm_capture = options.mitm_capture;
        self.mitm.set_capture(options.mitm_capture);
        self.shared.options.current.store(Arc::new(current));
    }

    /// The first download a config needs goes through the tunnel, so there must be
    /// a route before the first config is in force.
    async fn ensure_bootstrap(&self, home: &Arc<HomeDir>) -> Result<(), Failure> {
        if self.runtime().is_some() {
            return Ok(());
        }
        let built = apply::build(
            &self.shared,
            home,
            Profile::rejected_empty(),
            Arc::new(SelectionStore::new()),
        )
        .await
        .map_err(|err| Failure::core(err.to_string()))?;
        self.shared.tunnel.install(built.runtime);
        self.shared.tunnel.set_status(TunnelStatus::Inner);
        Ok(())
    }

    pub async fn setup(self: &Arc<Self>, request: SetupRequest) -> Result<(), Failure> {
        self.setup_as(Origin::Host, request).await
    }

    pub async fn setup_as(
        self: &Arc<Self>,
        origin: Origin,
        request: SetupRequest,
    ) -> Result<(), Failure> {
        if !self.is_initialized() {
            return Err(Failure::core(NOT_INITIALIZED));
        }
        let mut state = self.state.lock().await;
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        self.apply_options(&request.options);
        self.ensure_bootstrap(&home).await?;

        let selections = Arc::new(SelectionStore::new());
        selections.replace_all(request.selected);
        let built = match apply::load_profile(&self.shared, &home, request.base).await {
            Ok(profile) => apply::build(&self.shared, &home, profile, selections.clone()).await,
            Err(err) => Err(err),
        };
        let (built, rejected) = self.built_or_default(&home, built, &selections).await?;
        let apply::Built {
            runtime,
            mut applied,
            outbounds,
            rule_providers,
            deferred_geo,
            mut warnings,
            mitm,
            trust,
        } = built;
        if !self.profile_controller.load(Ordering::Relaxed) {
            host_owns_controller(&mut applied.general, &mut warnings);
        }

        if let Some(old) = state.take() {
            old.stop.cancel();
        }
        self.warnings.store(Arc::new(warnings));
        self.shared.tunnel.set_live(LiveOptions {
            mode: applied.general.mode,
            find_process_mode: applied.general.find_process_mode,
            ..LiveOptions::default()
        });
        let resolver = runtime.dns.clone();
        let system_dns = lock(&self.system_dns).clone();
        if let Some(servers) = system_dns {
            resolver.set_system_servers(servers);
        }
        {
            let mut seq = self.intent.lock().await;
            self.shared.tunnel.install(runtime);
            self.publish_change(&mut seq, origin, Change::Applied);
        }
        self.shared.tunnel.set_status(TunnelStatus::Running);
        self.mitm.apply(&mitm, trust);
        if applied.store_fake_ip {
            fake_ip_store::start(
                self.shared.fake_ip_store.clone(),
                &self.tasks,
                &self.handle,
                home.clone(),
                resolver.clone(),
                applied.stop.clone(),
            );
        }
        self.sync_dns_server(&applied.dns_listen, applied.dns_listen_mark, resolver)
            .await;
        self.start_ntp(&applied, &outbounds);
        let answered = lock(&self.answered).clone();
        outbounds.start_background(applied.stop.clone(), answered.clone());
        self.tasks.spawn_on(
            report_revoked(
                selections,
                self.intent.clone(),
                self.shared.events.clone(),
                applied.stop.clone(),
            ),
            &self.handle,
        );
        self.shared.geo.fetch_deferred(
            &deferred_geo,
            self.shared.fetcher.clone(),
            &applied.stop,
            &answered,
            &self.tasks,
        );
        rule_providers.start(applied.stop.clone(), answered, &self.tasks);
        self.shared.rule_providers.store(Some(rule_providers));
        self.reconcile_listeners(&applied).await;
        self.route.reset(self.is_running());
        self.shared.geo.sync_auto(
            applied.general.geo_auto_update,
            applied.general.geo_update_interval,
            self.shared.fetcher.clone(),
        );
        *state = Some(applied);
        drop(state);
        self.handle
            .spawn_blocking(concord_platform::release_free_memory);
        match rejected {
            Some(message) => Err(Failure::new("config_rejected", message)),
            None => Ok(()),
        }
    }

    async fn built_or_default(
        &self,
        home: &Arc<HomeDir>,
        built: Result<apply::Built, apply::ApplyError>,
        selections: &Arc<SelectionStore>,
    ) -> Result<(apply::Built, Option<String>), Failure> {
        match built {
            Ok(built) => Ok((built, None)),
            Err(err) => {
                tracing::error!(
                    "config apply failed, falling back to the built-in default - no proxies will be available: {err}"
                );
                match apply::build(
                    &self.shared,
                    home,
                    Profile::rejected_empty(),
                    selections.clone(),
                )
                .await
                {
                    Ok(built) => Ok((built, Some(err.to_string()))),
                    Err(_) => Err(Failure::core(err.to_string())),
                }
            }
        }
    }

    pub fn clock_offset_nanos(&self) -> i64 {
        self.shared.clock.nanos()
    }

    fn start_ntp(&self, applied: &Applied, outbounds: &Outbounds) {
        let ntp = &applied.ntp;
        if !ntp.enable || ntp.server.is_empty() || ntp.interval == 0 {
            return;
        }
        let mut write_to_system = ntp.write_to_system;
        if write_to_system && self.android {
            tracing::warn!(
                "ntp write-to-system ignored: Android does not let apps set the system time"
            );
            write_to_system = false;
        }
        ntp::start(
            &self.tasks,
            &self.handle,
            NtpSettings {
                server: ntp.server.clone(),
                port: ntp.port,
                interval: Duration::from_secs(u64::from(ntp.interval) * 60),
                dialer_proxy: ntp.dialer_proxy.clone(),
                write_to_system,
            },
            outbounds.env(),
            self.shared.clock.clone(),
            applied.stop.clone(),
        );
    }

    pub async fn log_level(&self) -> Option<LogLevel> {
        self.state
            .lock()
            .await
            .as_ref()
            .map(|applied| applied.general.log_level)
    }

    async fn sync_dns_server(&self, address: &str, mark: u32, resolver: Arc<Resolver>) {
        let mut server = self.dns_server.lock().await;
        if let Some(running) = server.as_ref() {
            if running.address() == address && running.mark() == mark {
                running.set_resolver(resolver);
                return;
            }
            *server = None;
        }
        self.faults.set_dns(None);
        if address.is_empty() {
            return;
        }
        match DnsServer::start(address, mark, resolver) {
            Ok(started) => {
                tracing::info!("DNS server listening at: {address}");
                *server = Some(started);
            }
            Err(err) => {
                let message = format!("Start DNS server error: {err}");
                tracing::error!("{message}");
                self.faults.set_dns(Some(ServiceFault {
                    service: Service::Dns,
                    address: address.to_string(),
                    kind: err.kind(),
                    message,
                }));
            }
        }
    }

    /// `updateListeners`: nothing happens until the host has asked the core to run.
    async fn reconcile_listeners(&self, applied: &Applied) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }
        let spec: ListenSpec = listen_spec(&applied.general, applied.lan_refused);
        let handler = Arc::new(self.shared.tunnel.clone());
        let errors = self.listeners.reconcile(&spec, handler).await;
        for error in &errors {
            tracing::error!("{error}");
        }
        self.faults
            .set_listeners(errors.iter().map(ServiceFault::listener).collect());
        if !self.android {
            self.reconcile_tun(applied).await;
        }
    }

    /// `listener.ReCreateTun`: a running device with the same settings is left alone,
    /// and a start that failed is tried again by the next call.
    async fn reconcile_tun(&self, applied: &Applied) {
        let desired = (applied.tun.clone(), applied.tun_inet4, applied.general.ipv6);
        let mut slot = self.tun.lock().await;
        let same = lock(&self.tun_config).as_ref() == Some(&desired);
        if same && slot.as_ref().is_some_and(|runner| !runner.is_finished()) {
            return;
        }
        self.close_tun(&mut slot).await;
        self.faults.set_tun(None);
        {
            let mut held = lock(&self.tun_config);
            *held = Some(desired);
        }
        if !applied.tun.enable {
            return;
        }
        let options = options_of(&applied.tun, applied.tun_inet4, applied.general.ipv6);
        let congestion = congestion_of(&applied.tun.congestion_controller);
        let exclusion = Arc::new(KeepOffDevice {
            platform: self.shared.platform.clone(),
            sockets: self.shared.sockets.clone(),
            tunnel: self.shared.tunnel.clone(),
            auto_detect: applied.tun.auto_detect_interface,
        });
        match start_runner(
            &self.shared.tunnel,
            &self.shared.sockets,
            &options,
            DeviceSource::Create,
            congestion,
            Some(exclusion),
        )
        .await
        {
            Ok(runner) => *slot = Some(runner),
            Err(err) => {
                let message = format!("Start TUN listening error: {err}");
                tracing::error!("{message}");
                self.faults.set_tun(Some(ServiceFault {
                    service: Service::Tun,
                    address: applied.tun.device.clone(),
                    kind: err.kind,
                    message,
                }));
            }
        }
    }

    async fn close_tun(&self, slot: &mut Option<TunRunner>) {
        if let Some(runner) = slot.take() {
            stop_runner(runner).await;
        }
    }

    /// `handleStartTun`. Takes the descriptor: it is closed on every failing path.
    #[cfg(unix)]
    pub async fn start_vpn_tun(&self, fd: OwnedFd, request: VpnTunRequest) -> bool {
        self.shared.sockets.protect_held().await;
        let started = {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
            let built = vpn_options(&request);
            match built {
                Ok((options, congestion)) => {
                    match start_runner(
                        &self.shared.tunnel,
                        &self.shared.sockets,
                        &options,
                        DeviceSource::Adopt(fd),
                        congestion,
                        None,
                    )
                    .await
                    {
                        Ok(runner) => {
                            *slot = Some(runner);
                            true
                        }
                        Err(err) => {
                            tracing::error!("TUN: {err}");
                            false
                        }
                    }
                }
                Err(err) => {
                    tracing::error!("TUN: {err}");
                    false
                }
            }
        };
        if !started {
            return false;
        }
        if self.running.load(Ordering::SeqCst) {
            self.reset_resolver_connections();
            self.route.reset(self.is_running());
        } else if let Err(err) = self.start_listeners().await {
            tracing::error!("start listeners: {err:?}");
        }
        true
    }

    /// `StopTun`.
    pub async fn stop_vpn_tun(&self) {
        {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
        }
        if self.running.load(Ordering::SeqCst)
            && let Err(err) = self.stop_listeners().await
        {
            tracing::error!("stop listeners: {err:?}");
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// `handleUpdateDns`: the newest value wins however the tasks interleave.
    pub fn update_system_dns(self: &Arc<Self>, value: String) {
        let seq = self.dns_update_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let engine = self.clone();
        self.handle.spawn(async move {
            if engine.dns_update_seq.load(Ordering::SeqCst) != seq {
                return;
            }
            tracing::info!("[DNS] updateDns {value}");
            let servers: Vec<SocketAddr> = value
                .split(',')
                .filter(|server| !server.is_empty())
                .filter_map(|server| {
                    let parsed = server.parse().ok();
                    if parsed.is_none() {
                        tracing::warn!("[DNS] updateDns: invalid address {server}");
                    }
                    parsed
                })
                .collect();
            {
                let mut held = lock(&engine.system_dns);
                *held = Some(servers.clone());
            }
            if let Some(runtime) = engine.runtime() {
                runtime.dns.set_system_servers(servers);
            }
        });
    }

    pub async fn update(&self, request: UpdateRequest) -> Result<(), Failure> {
        self.update_as(Origin::Host, request).await.map(|_| ())
    }

    /// Returns the change it made, or the last change when it made none.
    pub async fn update_as(&self, origin: Origin, request: UpdateRequest) -> Result<u64, Failure> {
        let mut state = self.state.lock().await;
        let Some(applied) = state.as_mut() else {
            return Err(Failure::core("config is not applied"));
        };
        let before = Settled::of(applied, &self.shared.geo.urls.load());
        let general = &mut applied.general;
        if let Some(port) = request.mixed_port {
            general.mixed_port = port;
        }
        if let Some(allow) = request.allow_lan {
            general.allow_lan = allow;
        }
        let mut live = self.shared.tunnel.live();
        if let Some(mode) = request
            .find_process_mode
            .as_deref()
            .and_then(FindProcessMode::parse)
        {
            general.find_process_mode = mode;
            live.find_process_mode = mode;
        }
        if let Some(enabled) = request.tcp_concurrent {
            general.tcp_concurrent = enabled;
        }
        if let Some(enabled) = request.unified_delay {
            general.unified_delay = enabled;
            self.shared
                .options
                .unified_delay
                .store(enabled, Ordering::Relaxed);
        }
        let (mut moved, mut reset) = (false, false);
        if let Some(mode) = request.mode.as_deref().and_then(TunnelMode::parse) {
            moved = general.mode != mode;
            general.mode = mode;
            live.mode = mode;
        }
        if let Some(level) = request
            .log_level
            .as_deref()
            .and_then(concord_common::LogLevel::parse)
        {
            general.log_level = level;
        }
        if let Some(enabled) = request.ipv6 {
            reset = general.ipv6 != enabled;
            general.ipv6 = enabled;
        }
        self.shared.tunnel.set_live(live);
        if let Some(runtime) = self.runtime() {
            runtime.dns.set_ipv6(general.ipv6);
            runtime
                .outbounds
                .set_dial_flags(general.tcp_concurrent, general.ipv6);
        }
        if let Some(patch) = request.tun {
            applied.tun.enable = patch.enable;
            if let Some(auto_route) = patch.auto_route {
                applied.tun.auto_route = auto_route;
            }
            if let Some(device) = patch.device {
                applied.tun.device = device;
            }
            if let Some(stack) = patch.stack {
                applied.tun.stack_name = stack;
            }
        }
        let general = &mut applied.general;
        if let Some(lines) = request.authentication {
            general.authentication = lines
                .iter()
                .filter_map(|line| line.split_once(':'))
                .map(|(user, pass)| concord_config::general::Credential {
                    user: user.to_string(),
                    pass: pass.to_string(),
                })
                .collect();
        }
        if let Some(options) = &request.options {
            self.apply_options(options);
        }
        self.reconcile_listeners(applied).await;
        let general = &mut applied.general;
        let mut urls = (**self.shared.geo.urls.load()).clone();
        for (kind, link) in request.geox_url {
            if !urls.set(&kind, link) {
                tracing::warn!("geox-url: unknown geo resource {kind:?}");
            }
        }
        self.shared.geo.urls.store(Arc::new(urls));
        if let Some(enabled) = request.geo_auto_update {
            general.geo_auto_update = enabled;
        }
        if let Some(hours) = request
            .geo_update_interval
            .and_then(|hours| u32::try_from(hours).ok())
        {
            general.geo_update_interval = hours;
        }
        self.shared.geo.sync_auto(
            general.geo_auto_update,
            general.geo_update_interval,
            self.shared.fetcher.clone(),
        );
        if reset {
            self.route.reset(self.is_running());
        } else if moved {
            self.route.moved();
        }
        let change = before.change_to(&Settled::of(applied, &self.shared.geo.urls.load()));
        let mut seq = self.intent.lock().await;
        if !change.is_empty() {
            self.publish_change(&mut seq, origin, Change::General(change));
        }
        Ok(*seq)
    }

    fn publish_change(&self, seq: &mut u64, origin: Origin, change: Change) {
        publish_change(&*self.shared.events, seq, origin, change);
    }

    /// Holds back the outcome of the first load of every provider the next
    /// apply makes until the guard drops, so a host that answers its own caller
    /// after the apply hears of a provider only once it knows of it.
    pub fn hold_first_loads(&self) -> DropGuard {
        let token = CancellationToken::new();
        {
            let mut answered = lock(&self.answered);
            answered.cancel();
            *answered = token.clone();
        }
        token.drop_guard()
    }

    pub fn selections(&self) -> BTreeMap<String, String> {
        self.outbounds()
            .map(|outbounds| outbounds.selections().into_iter().collect())
            .unwrap_or_default()
    }

    pub fn set_profile_controller(&self, owned: bool) {
        self.profile_controller.store(owned, Ordering::Relaxed);
    }

    /// The profile's `external-controller` and `secret`; empty while a host owns them.
    pub async fn profile_controller(&self) -> (String, String) {
        self.state
            .lock()
            .await
            .as_ref()
            .map(|applied| {
                (
                    applied.general.external_controller.clone(),
                    applied.general.secret.clone(),
                )
            })
            .unwrap_or_default()
    }

    pub async fn general(&self) -> Option<GeneralView> {
        let state = self.state.lock().await;
        let applied = state.as_ref()?;
        let seq = *self.intent.lock().await;
        let general = &applied.general;
        let urls = self.shared.geo.urls.load();
        Some(GeneralView {
            seq,
            port: general.port,
            socks_port: general.socks_port,
            redir_port: general.redir_port,
            tproxy_port: general.tproxy_port,
            mixed_port: general.mixed_port,
            allow_lan: general.allow_lan,
            users: users_of(general),
            skip_auth_prefixes: general
                .skip_auth_prefixes
                .iter()
                .map(ToString::to_string)
                .collect(),
            mode: general.mode,
            log_level: general.log_level,
            ipv6: general.ipv6,
            tcp_concurrent: general.tcp_concurrent,
            unified_delay: general.unified_delay,
            find_process_mode: general.find_process_mode,
            interface_name: general.interface_name.clone(),
            routing_mark: general.routing_mark,
            sniffing: applied.sniffing,
            global_ua: general.global_ua.clone(),
            keep_alive_idle: general.keep_alive_idle,
            keep_alive_interval: general.keep_alive_interval,
            disable_keep_alive: general.disable_keep_alive,
            geo_auto_update: general.geo_auto_update,
            geo_update_interval: general.geo_update_interval,
            geox_url: vec![
                ("mmdb", urls.mmdb.clone()),
                ("asn", urls.asn.clone()),
                ("geosite", urls.geosite.clone()),
            ],
            tun: TunView {
                enable: applied.tun.enable,
                device: applied.tun.device.clone(),
                stack: applied.tun.stack_name.clone(),
                auto_route: applied.tun.auto_route,
                auto_detect_interface: applied.tun.auto_detect_interface,
                dns_hijack: applied.tun.dns_hijack.clone(),
                mtu: applied.tun.mtu,
            },
            selections: self
                .outbounds()
                .map(|outbounds| outbounds.selections())
                .unwrap_or_default(),
        })
    }

    pub fn node_states(&self, names: Option<&[String]>) -> Vec<NodeStateView> {
        self.outbounds()
            .map(|outbounds| outbounds.node_states(names))
            .unwrap_or_default()
    }

    pub fn rules(&self) -> Vec<RuleView> {
        let Some(runtime) = self.runtime() else {
            return Vec::new();
        };
        runtime
            .program
            .rules()
            .map(|(rule, target)| RuleView {
                kind: rule.type_name.to_string(),
                payload: rule.payload.to_string(),
                target: target.to_string(),
            })
            .collect()
    }

    pub async fn dns_query(&self, name: &str, qtype: &str) -> Result<QueryView, Failure> {
        let runtime = self
            .runtime()
            .ok_or_else(|| Failure::core("config is not applied"))?;
        runtime
            .dns
            .query(name, qtype)
            .await
            .map_err(|err| match err {
                QueryError::Exchange(err) => Failure::core(err.to_string()),
                other => Failure::new("invalid_query", other.to_string()),
            })
    }

    pub fn flush_fake_ip(&self) {
        if let Some(runtime) = self.runtime() {
            runtime.dns.flush_fake_ip();
        }
    }

    pub fn warnings(&self) -> Vec<WarningView> {
        (**self.warnings.load()).clone()
    }

    pub fn clear_effect(&self, profile_id: i64) -> Result<(), Failure> {
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        ops::clear_effect(&home, profile_id)
    }

    pub fn proxy_views(&self) -> ProxyViews {
        self.outbounds()
            .map(|outbounds| outbounds.views())
            .unwrap_or_default()
    }

    pub fn route_view(&self) -> RouteView {
        self.route.view()
    }

    pub async fn select(&self, group: &str, proxy: &str) -> SelectOutcome {
        self.select_as(Origin::Host, group, proxy).await
    }

    pub async fn select_as(&self, origin: Origin, group: &str, proxy: &str) -> SelectOutcome {
        let mut seq = self.intent.lock().await;
        let Some(outbounds) = self.outbounds() else {
            return SelectOutcome {
                message: "Not found group".to_string(),
                changed: false,
                seq: *seq,
            };
        };
        let before = outbounds.selection(group);
        let staged = match outbounds.stage_selection(group, proxy) {
            Ok(staged) => staged,
            Err(failed) => {
                return SelectOutcome {
                    message: failed.message,
                    changed: false,
                    seq: *seq,
                };
            }
        };
        let after = outbounds.selection(group);
        if after != before {
            let group = group.to_string();
            self.publish_change(
                &mut seq,
                origin,
                Change::Selected {
                    group,
                    proxy: after,
                },
            );
        }
        let made = *seq;
        drop(seq);
        outbounds.probe_selection(&staged).await;
        let outcome = outbounds.settle_selection(staged);
        SelectOutcome {
            message: outcome.message,
            changed: outcome.changed,
            seq: made,
        }
    }

    pub async fn proxy_definition(&self, name: String) -> Result<Option<Value>, Failure> {
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        if let Some(outbounds) = self.outbounds()
            && let Some(definition) = outbounds.definition(&name).await
        {
            return Ok(Some(Value::Object(definition)));
        }
        let path = home.join("config.yaml");
        ops::on_parse_stack(move || ops::configured_proxy(&path, &name))
            .await?
            .map(|mapping| mapping.map(Value::Object))
    }

    pub async fn test_delay(&self, name: &str, url: &str, timeout: i64) -> DelayResult {
        self.test_delay_expecting(name, url, &StatusRanges::default(), timeout)
            .await
    }

    pub async fn test_delay_expecting(
        &self,
        name: &str,
        url: &str,
        expected: &StatusRanges,
        timeout: i64,
    ) -> DelayResult {
        let url = if url.is_empty() {
            let current = self.shared.options.current.load();
            if current.test_url.is_empty() {
                concord_group::DEFAULT_TEST_URL.to_string()
            } else {
                current.test_url.clone()
            }
        } else {
            url.to_string()
        };
        let Some(outbounds) = self.outbounds() else {
            return DelayResult {
                url,
                name: name.to_string(),
                value: -2,
            };
        };
        let timeout = u64::try_from(timeout)
            .ok()
            .filter(|millis| *millis > 0)
            .map_or(DEFAULT_DELAY_TIMEOUT, Duration::from_millis);
        outbounds
            .test_delay_expecting(name, &url, expected, timeout)
            .await
    }

    pub fn providers(&self) -> Providers<'_> {
        Providers { engine: self }
    }

    pub async fn compile_rule_set(&self, name: &str, url: &str) -> Result<RuleSetInfo, Failure> {
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        let valid = !name.is_empty()
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !valid {
            return Err(Failure::new("invalid_arguments", "invalid rule set name"));
        }
        let source = home.join("providers").join("rules").join(name);
        let downloaded = !url.is_empty();
        let bytes = if downloaded {
            resources::download(&*self.shared.fetcher, resources::rule_set_request(url))
                .await
                .map_err(|err| request_failure(&err, json!({})))?
        } else {
            std::fs::read(&source).map_err(Failure::from)?
        };
        let allow_empty = !downloaded;
        let (bytes, compiled) = ops::on_parse_stack(move || {
            let compiled = compile_rule_set(&bytes, allow_empty);
            (bytes, compiled)
        })
        .await?;
        let compiled = compiled.map_err(|err| Failure::new(err.code(), err.to_string()))?;
        if downloaded {
            home.write_atomic(&source, &bytes)?;
        }
        if let Some(mrs) = &compiled.mrs {
            let mut target = source.clone().into_os_string();
            target.push(".mrs");
            home.write_atomic(std::path::PathBuf::from(target), mrs)?;
        }
        Ok(RuleSetInfo {
            behavior: compiled.info.behavior.name(),
            format: compiled.info.format.name(),
        })
    }

    pub fn geo_update(self: &Arc<Self>, kind: &str) -> Result<(), Failure> {
        let file = resources::geo_file_of(kind)
            .ok_or_else(|| Failure::core(format!("unknown geo resource: {kind}")))?;
        if !self.shared.geo.claim(resources::geo_kind_of(file)) {
            return Err(Failure::core(format!(
                "geo update already in progress: {kind}"
            )));
        }
        let engine = self.clone();
        tokio::spawn(async move {
            engine
                .shared
                .geo
                .update(file, &*engine.shared.fetcher)
                .await;
        });
        Ok(())
    }

    pub fn traffic_now(&self, only_proxy: bool) -> (i64, i64) {
        as_signed(self.table.now(only_proxy))
    }

    pub fn traffic_total(&self, only_proxy: bool) -> (i64, i64) {
        as_signed(self.table.total(only_proxy))
    }

    pub fn traffic_reset(&self) {
        self.table.reset();
    }

    pub fn connections(&self) -> Vec<Arc<ConnRecord>> {
        self.table.snapshot()
    }

    pub fn connection_id(&self, seq: u64) -> Option<String> {
        self.table.id_of(seq)
    }

    pub fn connection_count(&self) -> usize {
        self.table.len()
    }

    pub fn close_all_connections(&self) {
        self.table.close_all();
    }

    pub fn reset_resolver_connections(&self) {
        if let Some(runtime) = self.runtime() {
            runtime.dns.reset_connections();
        }
    }

    pub fn clear_dns_cache(&self) {
        if let Some(runtime) = self.runtime() {
            runtime.dns.clear_cache();
        }
    }

    pub fn network_changed(&self) {
        self.shared.platform.network_changed();
        self.clear_dns_cache();
        self.mitm.network_changed();
    }

    /// `handleResetNetwork`: connections over a network the device has left would
    /// hang until TCP gives up on them, the probes among them, so the epoch moves.
    pub fn reset_network(&self) {
        self.close_all_connections();
        self.network_changed();
        if let Some(outbounds) = self.outbounds() {
            outbounds.reset_sessions();
        }
        self.route.reset(self.is_running());
    }

    /// Services asked to run that did not start, as of the last apply, update, start or stop.
    pub fn faults(&self) -> Vec<ServiceFault> {
        self.faults.list()
    }

    pub fn tun_fault(&self) -> Option<ServiceFault> {
        self.faults.tun()
    }

    pub async fn start_listeners(&self) -> Result<(), Failure> {
        let state = self.state.lock().await;
        self.set_running(true);
        if let Some(applied) = state.as_ref() {
            self.reconcile_listeners(applied).await;
        }
        self.reset_resolver_connections();
        self.route.reset(self.is_running());
        Ok(())
    }

    pub async fn stop_listeners(&self) -> Result<(), Failure> {
        let _state = self.state.lock().await;
        self.set_running(false);
        self.listeners.stop_all().await;
        self.faults.set_listeners(Vec::new());
        if !self.android {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
            self.faults.set_tun(None);
        }
        self.reset_resolver_connections();
        self.route.reset(self.is_running());
        Ok(())
    }

    pub fn watch_route(&self, watched: bool) -> RouteView {
        self.route.watch(watched)
    }

    pub async fn check_routes(&self, routes: Vec<Vec<RouteHit>>) -> (RouteStamp, Vec<bool>) {
        self.prober.check_routes(&routes).await
    }

    pub async fn probe_outbound_ip(&self, proxy: String, urls: Vec<String>, timeout: i64) -> Value {
        self.prober.outbound_ip(&proxy, &urls, timeout).await
    }

    pub async fn probe_services(&self, proxy: String, names: Vec<String>, timeout: i64) -> Value {
        self.prober.services(&proxy, &names, timeout).await
    }

    pub async fn shutdown(&self) {
        let mut state = self.state.lock().await;
        self.set_running(false);
        self.mitm.shutdown();
        self.route.watch(false);
        self.listeners.stop_all().await;
        {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
        }
        *self.dns_server.lock().await = None;
        self.shared.geo.stop_auto();
        self.shared.rule_providers.store(None);
        if let Some(applied) = state.take() {
            applied.stop.cancel();
        }
        self.tasks.close();
        self.tasks.wait().await;
        self.tasks.reopen();
        self.shared.tunnel.set_status(TunnelStatus::Suspended);
        self.shared.tunnel.clear();
        self.table.close_all();
        self.initialized.store(false, Ordering::SeqCst);
    }
}

fn as_signed((up, down): (u64, u64)) -> (i64, i64) {
    (
        i64::try_from(up).unwrap_or(i64::MAX),
        i64::try_from(down).unwrap_or(i64::MAX),
    )
}

/// What `update` can change that a host keeps, so a patch reports only what moved.
struct Settled {
    mode: TunnelMode,
    log_level: LogLevel,
    allow_lan: bool,
    ipv6: bool,
    mixed_port: u16,
    tcp_concurrent: bool,
    find_process_mode: FindProcessMode,
    unified_delay: bool,
    users: Vec<String>,
    geo_auto_update: bool,
    geo_update_interval: u32,
    geox_url: BTreeMap<String, String>,
    tun_enable: bool,
    tun_device: String,
    tun_stack: String,
    tun_auto_route: bool,
}

impl Settled {
    fn of(applied: &Applied, urls: &GeoUrls) -> Self {
        let general = &applied.general;
        Settled {
            mode: general.mode,
            log_level: general.log_level,
            allow_lan: general.allow_lan,
            ipv6: general.ipv6,
            mixed_port: general.mixed_port,
            tcp_concurrent: general.tcp_concurrent,
            find_process_mode: general.find_process_mode,
            unified_delay: general.unified_delay,
            users: users_of(general),
            geo_auto_update: general.geo_auto_update,
            geo_update_interval: general.geo_update_interval,
            geox_url: geox_url_of(urls),
            tun_enable: applied.tun.enable,
            tun_device: applied.tun.device.clone(),
            tun_stack: applied.tun.stack_name.clone(),
            tun_auto_route: applied.tun.auto_route,
        }
    }

    fn change_to(&self, after: &Settled) -> GeneralChange {
        fn moved<T: PartialEq + Clone>(before: &T, after: &T) -> Option<T> {
            (before != after).then(|| after.clone())
        }
        GeneralChange {
            mode: moved(&self.mode, &after.mode),
            log_level: moved(&self.log_level, &after.log_level),
            allow_lan: moved(&self.allow_lan, &after.allow_lan),
            ipv6: moved(&self.ipv6, &after.ipv6),
            mixed_port: moved(&self.mixed_port, &after.mixed_port),
            tcp_concurrent: moved(&self.tcp_concurrent, &after.tcp_concurrent),
            find_process_mode: moved(&self.find_process_mode, &after.find_process_mode),
            unified_delay: moved(&self.unified_delay, &after.unified_delay),
            authentication: moved(&self.users, &after.users),
            geo_auto_update: moved(&self.geo_auto_update, &after.geo_auto_update),
            geo_update_interval: moved(&self.geo_update_interval, &after.geo_update_interval),
            geox_url: moved(&self.geox_url, &after.geox_url),
            tun_enable: moved(&self.tun_enable, &after.tun_enable),
            tun_device: moved(&self.tun_device, &after.tun_device),
            tun_stack: moved(&self.tun_stack, &after.tun_stack),
            tun_auto_route: moved(&self.tun_auto_route, &after.tun_auto_route),
        }
    }
}

fn users_of(general: &concord_config::general::General) -> Vec<String> {
    general
        .authentication
        .iter()
        .map(|credential| credential.user.clone())
        .collect()
}

fn geox_url_of(urls: &GeoUrls) -> BTreeMap<String, String> {
    [
        ("mmdb", urls.mmdb.clone()),
        ("asn", urls.asn.clone()),
        ("geosite", urls.geosite.clone()),
    ]
    .into_iter()
    .map(|(kind, url)| (kind.to_string(), url))
    .collect()
}

fn host_owns_controller(
    general: &mut concord_config::general::General,
    warnings: &mut Vec<WarningView>,
) {
    const MESSAGE: &str = "the host sets this; the profile's value is ignored";
    for (key, value) in [
        ("external-controller", &mut general.external_controller),
        ("secret", &mut general.secret),
    ] {
        if value.is_empty() {
            continue;
        }
        value.clear();
        tracing::warn!("[Config] {key}: {MESSAGE}");
        warnings.push(WarningView {
            level: "warning",
            code: "host_owned_key",
            path: key.to_string(),
            message: MESSAGE.to_string(),
        });
    }
}

fn publish_change(events: &dyn EventSink, seq: &mut u64, origin: Origin, change: Change) {
    *seq += 1;
    if events.enabled() {
        events.publish(CoreEvent::State(StateChange {
            seq: *seq,
            origin,
            change,
        }));
    }
}

/// Reports each pick a fallback group dropped because its node died. A pick
/// set again before the report is taken was already reported by its caller.
async fn report_revoked(
    selections: Arc<SelectionStore>,
    intent: Arc<AsyncMutex<u64>>,
    events: Arc<dyn EventSink>,
    stop: CancellationToken,
) {
    loop {
        let groups = tokio::select! {
            () = stop.cancelled() => return,
            groups = selections.take_revoked() => groups,
        };
        let mut seq = intent.lock().await;
        for group in groups {
            if selections.get(&group).is_none() {
                let change = Change::Selected {
                    group: group.to_string(),
                    proxy: String::new(),
                };
                publish_change(&*events, &mut seq, Origin::Core, change);
            }
        }
    }
}

fn released() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}
