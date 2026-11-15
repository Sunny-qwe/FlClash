use std::collections::BTreeMap;
use std::time::Duration;

use concord_common::{CoreEvent, CoreOptions};
use concord_platform::NativePlatform;

use super::*;

struct NoEvents;

impl EventSink for NoEvents {
    fn enabled(&self) -> bool {
        false
    }

    fn publish(&self, _event: CoreEvent) {}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_applies_release_the_runtimes_they_replace() {
    let home = tempfile::tempdir().unwrap();
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    engine.init(home.path().to_str().unwrap(), 0).unwrap();
    let mut replaced = Vec::new();
    for round in 0..3 {
        let config = format!(
            "proxies:\n  - {{name: n{round}, type: socks5, server: 127.0.0.1, port: 1}}\n\
             rules:\n  - MATCH,n{round}\n"
        );
        std::fs::write(home.path().join("config.yaml"), config).unwrap();
        engine
            .setup(SetupRequest {
                base: None,
                selected: BTreeMap::new(),
                options: CoreOptions::default(),
            })
            .await
            .unwrap();
        replaced.push(Arc::downgrade(&engine.runtime().unwrap()));
    }
    let current = replaced.pop().unwrap();
    let released = tokio::time::timeout(Duration::from_secs(10), async {
        while replaced.iter().any(|old| old.upgrade().is_some()) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        released.is_ok(),
        "a runtime an apply replaced is still held after ten seconds"
    );
    assert!(current.upgrade().is_some());
    engine.shutdown().await;
}

#[tokio::test]
async fn a_panicked_holder_of_the_answer_token_still_lets_first_loads_wait() {
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(NoEvents),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    concord_test_support::poison(&engine.answered);
    let answering = engine.hold_first_loads();
    let held = lock(&engine.answered).clone();
    assert!(!held.is_cancelled(), "the next apply's first loads wait");
    drop(answering);
    assert!(held.is_cancelled());
}
