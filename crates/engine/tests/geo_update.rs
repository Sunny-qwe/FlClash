#![allow(
    clippy::disallowed_methods,
    reason = "the peers here stand for the outside world, not the core's own sockets"
)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{
    CoreEvent, CoreOptions, EventSink, ResourceKind, ResourcePhase, ResourceUpdate, RouteStamp,
};
use concord_engine::{Engine, EngineConfig, SetupRequest};
use concord_platform::NativePlatform;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Events {
    geo: std::sync::Mutex<Vec<(String, ResourcePhase)>>,
    routes: std::sync::Mutex<Vec<RouteStamp>>,
}

impl EventSink for Events {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        match event {
            CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::Geo,
                name,
                phase,
            }) => lock(&self.geo).push((name.to_string(), phase)),
            CoreEvent::RouteChanged(view) => lock(&self.routes).push(view.stamp),
            _ => {}
        }
    }
}

struct Rig {
    engine: Arc<Engine>,
    events: Arc<Events>,
    home: tempfile::TempDir,
}

impl Rig {
    fn new() -> Rig {
        let events = Arc::new(Events::default());
        let engine = Engine::new(EngineConfig {
            sink: events.clone(),
            android: false,
            platform: Arc::new(NativePlatform::new()),
        });
        let home = tempfile::tempdir().unwrap();
        engine.init(home.path().to_str().unwrap(), 0).unwrap();
        Rig {
            engine,
            events,
            home,
        }
    }

    async fn apply(&self, config: &str) {
        std::fs::write(self.home.path().join("config.yaml"), config).unwrap();
        self.engine
            .setup(SetupRequest {
                base: None,
                selected: BTreeMap::new(),
                options: CoreOptions::default(),
            })
            .await
            .unwrap();
    }

    fn geo_events(&self, kind: &str) -> Vec<ResourcePhase> {
        lock(&self.events.geo)
            .iter()
            .filter(|(seen, _)| seen == kind)
            .map(|(_, phase)| phase.clone())
            .collect()
    }
}

async fn serve(body: Option<&'static [u8]>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            let Some(body) = body else {
                held.push(stream);
                continue;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_resource_is_refused() {
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await;

    let failure = rig.engine.geo_update("GEOFOO").unwrap_err();

    assert!(failure.message.contains("unknown geo resource"));
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_update_per_resource_runs_at_a_time() {
    let stuck = serve(None).await;
    let rig = Rig::new();
    rig.apply(&format!(
        "geox-url:\n  mmdb: http://{stuck}/m\n  asn: http://{stuck}/a\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;

    rig.engine.geo_update("MMDB").unwrap();
    let second = rig.engine.geo_update("MMDB").unwrap_err();

    assert!(second.message.contains("already in progress"), "{second:?}");
    rig.engine.geo_update("ASN").unwrap();
    assert!(eventually(|| rig.geo_events("MMDB").first() == Some(&ResourcePhase::Updating)).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_download_ends_the_update_with_an_error_and_frees_the_resource() {
    let server = serve(Some(b"")).await;
    let rig = Rig::new();
    rig.apply(&format!(
        "geox-url:\n  mmdb: http://{server}/m\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;

    rig.engine.geo_update("MMDB").unwrap();

    assert!(
        eventually(|| rig.geo_events("MMDB").iter().any(
            |phase| matches!(phase, ResourcePhase::Failed(error) if error.contains("no data"))
        ))
        .await,
        "{:?}",
        rig.geo_events("MMDB")
    );
    assert!(rig.engine.geo_update("MMDB").is_ok());
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_equal_to_the_file_on_disk_is_skipped_and_does_not_move_the_route() {
    let server = serve(Some(b"same bytes")).await;
    let rig = Rig::new();
    std::fs::write(rig.home.path().join("geoip.metadb"), b"same bytes").unwrap();
    rig.apply(&format!(
        "geox-url:\n  mmdb: http://{server}/m\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await;
    let before = rig.engine.watch_route(false);

    rig.engine.geo_update("MMDB").unwrap();

    assert!(
        eventually(|| rig.geo_events("MMDB").contains(&ResourcePhase::Unchanged)).await,
        "{:?}",
        rig.geo_events("MMDB")
    );
    assert_eq!(rig.engine.watch_route(false), before);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_the_profile_needs_and_lacks_is_fetched_and_reported() {
    let server = serve(Some(b"not a database")).await;
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("config.yaml"),
        format!(
            "geox-url:\n  mmdb: http://{server}/m\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,DIRECT\n"
        ),
    )
    .unwrap();
    let _ = rig
        .engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await;

    let seen = rig.geo_events("MMDB");
    assert!(
        matches!(
            seen.as_slice(),
            [ResourcePhase::Updating, ResourcePhase::Failed(_), ..]
        ),
        "{seen:?}"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_asn_database_the_rules_lack_is_fetched_after_the_apply() {
    let server = serve(Some(b"not a database")).await;
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("config.yaml"),
        format!("geox-url:\n  asn: http://{server}/a\nrules:\n  - IP-ASN,13335,DIRECT\n  - MATCH,DIRECT\n"),
    )
    .unwrap();
    let applied = rig
        .engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await;

    assert!(applied.is_ok(), "{applied:?}");
    assert!(
        eventually(|| matches!(
            rig.geo_events("ASN").as_slice(),
            [ResourcePhase::Updating, ResourcePhase::Failed(_), ..]
        ))
        .await,
        "{:?}",
        rig.geo_events("ASN")
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_database_dns_needs_and_lacks_is_fetched_and_reported() {
    let server = serve(Some(b"not a database")).await;
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("config.yaml"),
        format!(
            "geox-url:\n  mmdb: http://{server}/m\ndns:\n  enable: true\n  nameserver:\n    - 127.0.0.1\n  \
             fallback:\n    - 127.0.0.2\n  fallback-filter:\n    geoip: true\n    geoip-code: CN\n\
             rules:\n  - MATCH,DIRECT\n"
        ),
    )
    .unwrap();
    let _ = rig
        .engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await;

    let seen = rig.geo_events("MMDB");
    assert!(
        matches!(
            seen.as_slice(),
            [ResourcePhase::Updating, ResourcePhase::Failed(_), ..]
        ),
        "{seen:?}"
    );
    rig.engine.shutdown().await;
}
