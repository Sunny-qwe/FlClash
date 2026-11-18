use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::Tasks;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::device::{Device, TunDevice};
use crate::dns::{DnsHijack, DnsMatcher};
use crate::options::TunOptions;
use crate::route::{self, IfaceInfo, Op, Os, RouteBackend, RouteError, RouteSession, Step};
use crate::stack::{Congestion, DnsConfig, FlowSink, NetStack, StackOptions, StackStats};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartStep {
    DnsRules,
    Device,
    Routes,
}

impl fmt::Display for StartStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StartStep::DnsRules => "dns-hijack rules",
            StartStep::Device => "tun device",
            StartStep::Routes => "routes",
        })
    }
}

/// Which step of `start` failed. By the time this is returned everything done before the
/// failing step has been undone; `undo_failures` counts the parts that could not be.
#[derive(Debug, thiserror::Error)]
#[error("tun start failed at {step}: {detail}")]
pub struct StartError {
    pub step: StartStep,
    pub kind: io::ErrorKind,
    pub detail: String,
    pub undo_failures: usize,
}

pub enum DeviceSource {
    Create,
    /// The descriptor of an Android `VpnService` interface.
    #[cfg(unix)]
    Adopt(std::os::fd::OwnedFd),
}

pub struct TunDeps {
    pub sink: Arc<dyn FlowSink>,
    pub dns: Option<Arc<dyn DnsHijack>>,
    pub congestion: Congestion,
    pub exclusion: Option<Arc<dyn SelfExclusion>>,
    /// Where the stack, its DNS answers and a dropped runner's route teardown run.
    pub tasks: Tasks,
}

/// Keeps the core's own sockets off the device while the device's routes are in place.
pub trait SelfExclusion: Send + Sync {
    /// The device is open and no route leads to it yet.
    fn exclude(&self, device: &str);

    /// The device's routes are gone, or never went in.
    fn release(&self);
}

pub struct StopReport {
    pub route_failures: Vec<RouteError>,
    pub stack: io::Result<()>,
}

type BoxedBackend = Box<dyn RouteBackend>;

#[async_trait]
impl RouteBackend for BoxedBackend {
    async fn apply(&mut self, op: Op, step: &Step) -> io::Result<()> {
        (**self).apply(op, step).await
    }

    async fn clean_stale(&mut self, priorities: (u32, u32)) -> io::Result<usize> {
        (**self).clean_stale(priorities).await
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
struct NullBackend;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[async_trait]
impl RouteBackend for NullBackend {
    async fn apply(&mut self, _op: Op, _step: &Step) -> io::Result<()> {
        Ok(())
    }

    async fn clean_stale(&mut self, _priorities: (u32, u32)) -> io::Result<usize> {
        Ok(0)
    }
}

#[cfg_attr(
    not(target_os = "linux"),
    allow(unused_variables, reason = "only netlink drives a connection")
)]
fn platform_backend(tasks: &Tasks) -> io::Result<BoxedBackend> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(route::NetlinkBackend::connect(tasks)?))
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        Ok(Box::new(route::ManagerBackend::default()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(Box::new(NullBackend))
    }
}

pub(crate) struct Platform {
    pub iface: IfaceInfo,
    pub os: Os,
    pub backend: BoxedBackend,
}

pub struct TunRunner {
    device_name: String,
    stop: CancellationToken,
    task: Option<JoinHandle<Option<io::Result<()>>>>,
    tasks: Tasks,
    session: Option<RouteSession<BoxedBackend>>,
    exclusion: Option<Arc<dyn SelfExclusion>>,
    stats: Arc<StackStats>,
    notes: Vec<String>,
}

impl TunRunner {
    /// Opens the device, starts the stack and installs the platform's routes.
    pub async fn start(
        options: &TunOptions,
        source: DeviceSource,
        deps: TunDeps,
    ) -> Result<Self, StartError> {
        let dns = dns_config(options, &deps)?;
        let device = match source {
            DeviceSource::Create => TunDevice::create(options),
            #[cfg(unix)]
            DeviceSource::Adopt(fd) => TunDevice::adopt(fd),
        }
        .map_err(|err| StartError {
            step: StartStep::Device,
            kind: err.kind(),
            detail: err.to_string(),
            undo_failures: 0,
        })?;
        let iface = IfaceInfo {
            name: device.name().to_owned(),
            index: device.index().unwrap_or(0),
        };
        let backend = platform_backend(&deps.tasks).map_err(|err| StartError {
            step: StartStep::Routes,
            kind: err.kind(),
            detail: err.to_string(),
            undo_failures: 0,
        })?;
        let platform = Platform {
            iface,
            os: Os::current(),
            backend,
        };
        Self::start_with(options, device, platform, deps, dns).await
    }

    pub(crate) async fn start_with<D: Device>(
        options: &TunOptions,
        device: D,
        platform: Platform,
        deps: TunDeps,
        dns: Option<Arc<DnsConfig>>,
    ) -> Result<Self, StartError> {
        let TunDeps {
            sink,
            congestion,
            exclusion,
            tasks,
            ..
        } = deps;
        let stats = Arc::new(StackStats::default());
        let stack_options = StackOptions {
            mtu: options.effective_mtu(),
            max_tcp_flows: options.max_tcp_flows,
            broadcast: options.inet4_broadcast(),
            udp_timeout: options.udp_timeout,
            disable_icmp_forwarding: options.disable_icmp_forwarding,
            congestion,
            dns,
            stats: Arc::clone(&stats),
            tasks: tasks.clone(),
            ..StackOptions::default()
        };
        let stop = CancellationToken::new();
        let startup = stop.clone().drop_guard();
        let (work, ready) = NetStack::new(stack_options)
            .prepare(device, sink, stop.clone())
            .map_err(|err| StartError {
                step: StartStep::Device,
                kind: err.kind(),
                detail: err.to_string(),
                undo_failures: 0,
            })?;
        let task = tasks.spawn_returning(work);
        if let Err(error) = ready.await {
            stop.cancel();
            let failure = match task.await {
                Ok(Some(Err(failure))) => failure,
                Err(failure) => io::Error::other(failure),
                Ok(Some(Ok(())) | None) => error,
            };
            return Err(StartError {
                step: StartStep::Device,
                kind: failure.kind(),
                detail: failure.to_string(),
                undo_failures: 0,
            });
        }

        let Platform { iface, os, backend } = platform;
        let plan = route::plan(os, options, &iface);
        let device_name = iface.name.clone();
        if let Some(exclusion) = &exclusion {
            exclusion.exclude(&device_name);
        }
        match RouteSession::install(backend, &plan).await {
            Ok((session, notes)) => {
                let _ = startup.disarm();
                Ok(TunRunner {
                    device_name,
                    stop,
                    task: Some(task),
                    tasks,
                    session: Some(session),
                    exclusion,
                    stats,
                    notes,
                })
            }
            Err(err) => {
                stop.cancel();
                let _ = task.await;
                if let Some(exclusion) = &exclusion {
                    exclusion.release();
                }
                Err(StartError {
                    step: StartStep::Routes,
                    kind: io::ErrorKind::Other,
                    detail: err.to_string(),
                    undo_failures: err.undo_failures,
                })
            }
        }
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn stats(&self) -> &Arc<StackStats> {
        &self.stats
    }

    /// Non-fatal observations from start: stale rules removed, options the platform ignores.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// True once the stack has stopped on its own, for instance after the device failed.
    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Restores the routes first so the system stops sending traffic into the tunnel, then
    /// stops the stack.
    pub async fn stop(mut self) -> StopReport {
        let route_failures = match self.session.take() {
            Some(mut session) => session.teardown().await,
            None => Vec::new(),
        };
        if let Some(exclusion) = self.exclusion.take() {
            exclusion.release();
        }
        self.stop.cancel();
        let stack = match self.task.take() {
            Some(task) => match task.await {
                Ok(outcome) => outcome.unwrap_or(Ok(())),
                Err(err) => Err(io::Error::other(err)),
            },
            None => Ok(()),
        };
        StopReport {
            route_failures,
            stack,
        }
    }
}

impl Drop for TunRunner {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(mut session) = self.session.take() {
            let exclusion = self.exclusion.take();
            let teardown = self.tasks.spawn_to_end(async move {
                let failures = session.teardown().await;
                for failure in failures {
                    tracing::warn!(%failure, "route teardown failed");
                }
                if let Some(exclusion) = exclusion {
                    exclusion.release();
                }
            });
            if !teardown {
                tracing::warn!("tun routes left in place: no runtime to undo them");
            }
        }
    }
}

fn dns_config(options: &TunOptions, deps: &TunDeps) -> Result<Option<Arc<DnsConfig>>, StartError> {
    let Some(handler) = deps.dns.clone() else {
        return Ok(None);
    };
    let matcher = DnsMatcher::parse(options.dns_hijack.iter().map(String::as_str))
        .map_err(|err| StartError {
            step: StartStep::DnsRules,
            kind: io::ErrorKind::InvalidInput,
            detail: err.to_string(),
            undo_failures: 0,
        })?
        .with_interface_addresses(&options.inet4_address)
        .with_interface_addresses(&options.inet6_address);
    Ok((!matcher.is_empty()).then(|| Arc::new(DnsConfig { matcher, handler })))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use concord_common::{BoxStream, FlowKey, UdpReply};

    use super::*;

    use crate::options::Prefix;
    use crate::route::fake::Recorder;
    use crate::testing::fake_device;
    use concord_common::sync::lock;

    struct Null;

    impl FlowSink for Null {
        fn tcp(&self, _flow: FlowKey, _stream: BoxStream) {}

        fn udp(&self, _flow: FlowKey, _payload: &[u8], _reply: &Arc<dyn UdpReply>) {}
    }

    fn options() -> TunOptions {
        TunOptions {
            auto_route: true,
            inet4_address: vec![Prefix::parse("198.18.0.1/30").unwrap()],
            ..TunOptions::default()
        }
    }

    fn deps(exclusion: Option<Arc<dyn SelfExclusion>>) -> TunDeps {
        TunDeps {
            sink: Arc::new(Null),
            dns: None,
            congestion: Congestion::Cubic,
            exclusion,
            tasks: Tasks::default(),
        }
    }

    fn platform(os: Os, recorder: Recorder) -> Platform {
        Platform {
            iface: IfaceInfo {
                name: "tun0".into(),
                index: 3,
            },
            os,
            backend: Box::new(recorder),
        }
    }

    async fn start(options: &TunOptions, recorder: Recorder) -> Result<TunRunner, StartError> {
        let (device, _net) = fake_device(8, 2048);
        TunRunner::start_with(
            options,
            device,
            platform(Os::Linux, recorder),
            deps(None),
            None,
        )
        .await
    }

    fn count(recorder: &Recorder, op: Op) -> usize {
        lock(&recorder.log).iter().filter(|(o, _)| *o == op).count()
    }

    #[tokio::test]
    async fn start_installs_the_plan_and_stop_undoes_it_in_reverse() {
        let recorder = Recorder::default();
        let runner = start(&options(), recorder.clone()).await.unwrap();
        let installed = count(&recorder, Op::Add);
        assert!(installed > 5);
        assert_eq!(*lock(&recorder.stale), [(9000, 9010)]);
        assert!(!runner.is_finished());
        let report = runner.stop().await;
        assert!(report.route_failures.is_empty());
        assert!(report.stack.is_ok());
        let log = lock(&recorder.log);
        let adds: Vec<_> = log
            .iter()
            .filter(|(o, _)| *o == Op::Add)
            .map(|(_, d)| d.clone())
            .collect();
        let mut deletes: Vec<_> = log
            .iter()
            .filter(|(o, _)| *o == Op::Delete)
            .map(|(_, d)| d.clone())
            .collect();
        deletes.reverse();
        assert_eq!(adds, deletes);
    }

    #[tokio::test]
    async fn a_failing_route_step_reports_routes_and_leaves_nothing_behind() {
        let recorder = Recorder {
            fail_add_at: Some(3),
            ..Recorder::default()
        };
        let err = match start(&options(), recorder.clone()).await {
            Ok(_) => panic!("start should fail"),
            Err(err) => err,
        };
        assert_eq!(err.step, StartStep::Routes);
        assert_eq!(err.undo_failures, 0);
        assert_eq!(count(&recorder, Op::Add), 4);
        assert_eq!(count(&recorder, Op::Delete), 3);
    }

    #[tokio::test]
    async fn dropping_the_runner_still_removes_the_routes() {
        let recorder = Recorder::default();
        let runner = start(&options(), recorder.clone()).await.unwrap();
        let installed = count(&recorder, Op::Add);
        drop(runner);
        for _ in 0..50 {
            if count(&recorder, Op::Delete) == installed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(count(&recorder, Op::Delete), installed);
    }

    #[tokio::test]
    async fn a_bad_dns_hijack_entry_fails_before_anything_is_touched() {
        struct Echo;

        #[async_trait]
        impl DnsHijack for Echo {
            async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
                Some(query.to_vec())
            }
        }

        let mut o = options();
        o.dns_hijack = vec!["not an address".into()];
        let deps = TunDeps {
            dns: Some(Arc::new(Echo)),
            ..deps(None)
        };
        let err = match dns_config(&o, &deps) {
            Ok(_) => panic!("rule should be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.step, StartStep::DnsRules);
        o.dns_hijack = vec!["any:53".into()];
        assert!(dns_config(&o, &deps).unwrap().is_some());
    }

    /// The route operations the recorder had seen at each exclude and release.
    struct Excluded {
        routes: Recorder,
        seen: Mutex<Vec<(&'static str, usize)>>,
    }

    impl SelfExclusion for Excluded {
        fn exclude(&self, device: &str) {
            assert_eq!(device, "tun0");
            let done = lock(&self.routes.log).len();
            lock(&self.seen).push(("exclude", done));
        }

        fn release(&self) {
            let done = lock(&self.routes.log).len();
            lock(&self.seen).push(("release", done));
        }
    }

    async fn start_excluded(recorder: Recorder) -> (Result<TunRunner, StartError>, Arc<Excluded>) {
        let excluded = Arc::new(Excluded {
            routes: recorder.clone(),
            seen: Mutex::default(),
        });
        let (device, _net) = fake_device(8, 2048);
        let started = TunRunner::start_with(
            &options(),
            device,
            platform(Os::Linux, recorder),
            deps(Some(excluded.clone())),
            None,
        )
        .await;
        (started, excluded)
    }

    #[tokio::test]
    async fn the_core_is_kept_off_the_device_while_any_route_leads_to_it() {
        let recorder = Recorder::default();
        let (started, excluded) = start_excluded(recorder.clone()).await;
        let runner = started.unwrap();
        assert_eq!(*lock(&excluded.seen), [("exclude", 0)]);
        assert!(runner.stop().await.route_failures.is_empty());
        let applied = lock(&recorder.log).len();
        assert_eq!(
            *lock(&excluded.seen),
            [("exclude", 0), ("release", applied)]
        );

        let failing = Recorder {
            fail_add_at: Some(2),
            ..Recorder::default()
        };
        let (started, excluded) = start_excluded(failing.clone()).await;
        assert_eq!(started.err().map(|err| err.step), Some(StartStep::Routes));
        let undone = lock(&failing.log).len();
        assert_eq!(*lock(&excluded.seen), [("exclude", 0), ("release", undone)]);
    }

    #[tokio::test]
    async fn restarting_with_changed_options_installs_the_new_plan() {
        let recorder = Recorder::default();
        let first = start(&options(), recorder.clone()).await.unwrap();
        assert!(first.stop().await.route_failures.is_empty());
        let mut changed = options();
        changed.auto_route = false;
        let before = count(&recorder, Op::Add);
        let second = start(&changed, recorder.clone()).await.unwrap();
        assert_eq!(count(&recorder, Op::Add), before);
        assert!(second.stop().await.stack.is_ok());
    }

    #[tokio::test]
    async fn android_style_platforms_install_no_routes() {
        let recorder = Recorder::default();
        let (device, _net) = fake_device(8, 2048);
        let runner = TunRunner::start_with(
            &options(),
            device,
            platform(Os::Other, recorder.clone()),
            deps(None),
            None,
        )
        .await
        .unwrap();
        assert_eq!(count(&recorder, Op::Add), 0);
        assert!(runner.stop().await.stack.is_ok());
    }
}
