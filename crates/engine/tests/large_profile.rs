//! Live and peak heap per stage of applying a large profile, which RSS cannot tell
//! apart: CONCORD_LARGE_PROFILE=<yaml> cargo test --release -p concord-engine --test large_profile -- --ignored --nocapture
#![allow(
    unsafe_code,
    reason = "a counting allocator is the whole point of this test"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use concord_common::{CoreEvent, EventSink};
use concord_engine::{Engine, EngineConfig, SetupRequest};
use concord_platform::NativePlatform;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every method hands its arguments to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        COUNT.fetch_add(1, Ordering::Relaxed);
        // SAFETY: as above.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        COUNT.fetch_sub(1, Ordering::Relaxed);
        // SAFETY: as above.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if size >= layout.size() {
            grew(size - layout.size());
        } else {
            LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
        }
        // SAFETY: as above.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn report(stage: &str) {
    let mib = |bytes: usize| bytes as f64 / f64::from(1 << 20);
    println!(
        "{stage:32} live {:8.1} MiB  peak {:8.1} MiB  objects {}",
        mib(LIVE.load(Ordering::Relaxed)),
        mib(PEAK.load(Ordering::Relaxed)),
        COUNT.load(Ordering::Relaxed),
    );
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

struct NoEvents;

impl EventSink for NoEvents {
    fn enabled(&self) -> bool {
        false
    }

    fn publish(&self, _event: CoreEvent) {}
}

#[test]
#[ignore = "needs CONCORD_LARGE_PROFILE"]
fn stages_of_a_large_profile() {
    let path = std::env::var("CONCORD_LARGE_PROFILE").expect("CONCORD_LARGE_PROFILE");
    report("start");

    let bytes = std::fs::read(&path).unwrap();
    report("read");
    let raw = concord_config::parse_raw(&bytes).unwrap();
    drop(bytes);
    report("parse_raw");
    let profile = concord_config::load_raw(raw, &concord_config::LoadOptions::default()).unwrap();
    report("load_raw");
    println!(
        "  {} proxies, {} rules",
        profile.proxies.len(),
        profile.rules.len()
    );
    let env = concord_rules::CompileEnv::new(
        Arc::new(concord_rules::geo::GeoStore::new(std::env::temp_dir())),
        Arc::new(concord_rules::RuleSetStore::new()),
    );
    let program =
        concord_rules::RouteProgram::compile_lines(&profile.rules, &profile.sub_rules, &env)
            .unwrap();
    report("compile, with the profile");
    drop(profile);
    report("the program alone");
    drop(program);
    report("dropped");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let home = tempfile::tempdir().unwrap();
    runtime.block_on(async {
        let engine = Engine::new(EngineConfig {
            sink: Arc::new(NoEvents),
            android: false,
            platform: Arc::new(NativePlatform::new()),
        });
        engine.init(home.path().to_str().unwrap(), 0).unwrap();
        report("engine");
        engine
            .setup(SetupRequest {
                base: Some((path.clone(), "mixed-port: 0\n".to_string())),
                selected: Default::default(),
                options: Default::default(),
            })
            .await
            .unwrap();
        report("setup");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        report("settled");
        let listed = engine.proxy_views();
        report("proxy.list view");
        drop(listed);
        engine.shutdown().await;
        drop(engine);
        report("shut down");
    });
}
