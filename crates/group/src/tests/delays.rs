use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::*;
use crate::StatusRanges;
use crate::check::Supervisor;

const CONFIG: &str = "proxies:
  - {name: a, type: direct}
  - {name: b, type: direct}
";

fn url_test(extra: &str) -> String {
    format!(
        "{CONFIG}proxy-groups:\n  - {{name: u, type: url-test, proxies: [a, b], url: '{TEST_URL}', interval: 60{extra}}}\n"
    )
}

fn connects(rig: &Rig, name: &str) -> usize {
    rig.book.get(name).connects.load(Ordering::SeqCst)
}

#[tokio::test(start_paused = true)]
async fn a_delay_is_the_virtual_time_the_node_took_and_goes_out_as_an_event() {
    let rig = Rig::new(CONFIG);
    rig.book.get("a").set_delay(120);
    assert_eq!(rig.test("a").await, 120);
    assert_eq!(
        rig.events.delays(),
        [("a".to_string(), TEST_URL.to_string(), 120)]
    );
    let node = rig.out.node("a").unwrap();
    assert_eq!(node.health().last_delay_for(TEST_URL), 120);
}

#[tokio::test(start_paused = true)]
async fn an_instant_answer_counts_as_one_millisecond() {
    let rig = Rig::new(CONFIG);
    rig.book.get("a").set_delay(0);
    assert_eq!(rig.test("a").await, 1);
}

#[tokio::test(start_paused = true)]
async fn a_timeout_is_minus_one_and_a_failure_minus_two() {
    let rig = Rig::new(CONFIG);
    rig.book.get("a").set_delay(10_000);
    let slow = rig
        .out
        .test_delay("a", TEST_URL, Duration::from_secs(2))
        .await;
    assert_eq!(slow.value, -1);
    rig.book.get("b").fail.store(true, Ordering::SeqCst);
    assert_eq!(rig.test("b").await, -2);
    assert!(!rig.out.node("b").unwrap().health().alive_for(TEST_URL));
}

#[tokio::test(start_paused = true)]
async fn an_unknown_node_fails_at_once_with_no_event() {
    let rig = Rig::new(CONFIG);
    let result = rig.out.test_delay("nope", "", Duration::from_secs(5)).await;
    assert_eq!(result.value, -2);
    assert_eq!(result.url, crate::DEFAULT_TEST_URL);
    assert!(rig.events.delays().is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_longest_configured_timeout_beats_the_requested_one() {
    let rig = Rig::new(&url_test(", timeout: 8000"));
    rig.book.get("a").set_delay(6_000);
    let result = rig
        .out
        .test_delay("a", TEST_URL, Duration::from_secs(2))
        .await;
    assert_eq!(result.value, 6_000);
}

#[tokio::test(start_paused = true)]
async fn the_probe_carries_gos_default_headers() {
    let rig = Rig::new(CONFIG);
    rig.test("a").await;
    let request = lock(&rig.book.get("a").last_request).to_lowercase();
    assert!(request.starts_with("head "), "{request}");
    assert!(
        request.contains("\r\nuser-agent: go-http-client/1.1\r\n"),
        "{request}"
    );
    assert!(!request.contains("accept-encoding"), "{request}");
}

#[tokio::test(start_paused = true)]
async fn unified_delay_times_the_second_request_on_the_same_connection() {
    let rig = Rig::new(CONFIG);
    rig.test("a").await;
    assert_eq!(rig.book.get("a").requests.load(Ordering::SeqCst), 1);
    rig.defaults.unified.store(true, Ordering::SeqCst);
    rig.test("a").await;
    assert_eq!(rig.book.get("a").requests.load(Ordering::SeqCst), 3);
    assert_eq!(connects(&rig, "a"), 2);
}

#[tokio::test(start_paused = true)]
async fn an_unexpected_status_leaves_the_node_dead_for_that_url_only() {
    let rig = Rig::new(CONFIG);
    rig.book.get("a").status.store(500, Ordering::SeqCst);
    let node = rig.out.node("a").unwrap();
    let expected = StatusRanges::parse("200-299").unwrap();
    rig.out
        .url_test_node(&node, TEST_URL, &expected, Duration::from_secs(5))
        .await;
    assert!(!node.health().alive_for(TEST_URL));
    assert!(node.health().alive_for("http://other.test/"));
}

#[tokio::test(start_paused = true)]
async fn single_tests_are_not_queued_behind_each_other() {
    let rig = Rig::new(CONFIG);
    rig.book.get("a").set_delay(3_000);
    let handles: Vec<_> = (0..64)
        .map(|_| {
            let out = rig.out.clone();
            tokio::spawn(
                async move { out.test_delay("a", TEST_URL, Duration::from_secs(10)).await },
            )
        })
        .collect();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 64);
    for handle in handles {
        assert_eq!(handle.await.unwrap().value, 3_000);
    }
}

#[tokio::test(start_paused = true)]
async fn a_round_tests_every_member_and_shares_the_result_for_a_second() {
    let rig = Rig::new(&url_test(""));
    let group = rig.out.group("u").unwrap();
    let check = group.checks().next().unwrap().clone();
    check.check(&rig.out).await;
    assert_eq!((connects(&rig, "a"), connects(&rig, "b")), (1, 1));
    check.check(&rig.out).await;
    assert_eq!(connects(&rig, "a"), 1);
    tokio::time::sleep(Duration::from_secs(2)).await;
    check.check(&rig.out).await;
    assert_eq!(connects(&rig, "a"), 2);
}

#[tokio::test(start_paused = true)]
async fn a_lazy_schedule_sleeps_until_a_flow_touches_it() {
    let rig = Rig::new(&url_test(", lazy: true"));
    let (stop, answered) = (CancellationToken::new(), CancellationToken::new());
    answered.cancel();
    rig.out.start_background(stop.clone(), answered);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects(&rig, "a"), 1);
    let flow = Rig::flow("example.com");
    rig.out.resolve("u", &flow, None, Touch::No);
    tokio::time::sleep(Duration::from_secs(121)).await;
    assert_eq!(connects(&rig, "a"), 1);
    rig.out.resolve("u", &flow, None, Touch::Yes);
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert_eq!(connects(&rig, "a"), 2);
    stop.cancel();
}

#[tokio::test(start_paused = true)]
async fn the_supervisor_restarts_only_a_schedule_whose_spec_changed() {
    let rig = Rig::new(&url_test(""));
    let mut supervisor = Supervisor::default();
    let stop = CancellationToken::new();
    let weak = Arc::downgrade(&rig.out);
    supervisor.reconcile(rig.out.checks(), &weak, &stop);
    assert_eq!((supervisor.running(), supervisor.restarts()), (1, 0));
    supervisor.reconcile(rig.out.checks(), &weak, &stop);
    assert_eq!(supervisor.restarts(), 0);
    let check = rig.out.group("u").unwrap().checks().next().unwrap().clone();
    check.register_extra("http://extra.test/", &StatusRanges::default(), "", 60);
    supervisor.reconcile(rig.out.checks(), &weak, &stop);
    assert_eq!(supervisor.restarts(), 1);
    stop.cancel();
}
