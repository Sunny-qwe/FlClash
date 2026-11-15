#![cfg(windows)]

use std::time::{Duration, Instant};

const WAITS: usize = 200;
/// Half the default 15.6 ms tick: a wait that ends on the tick cannot pass.
const BOUND: Duration = Duration::from_millis(8);

fn median(mut took: Vec<Duration>) -> Duration {
    took.sort();
    took[took.len() / 2]
}

#[test]
fn a_timed_poll_ends_before_the_tick_without_an_event() {
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(16);
    let mut took = Vec::with_capacity(WAITS);
    for _ in 0..WAITS {
        let start = Instant::now();
        poll.poll(&mut events, Some(Duration::from_millis(1)))
            .unwrap();
        took.push(start.elapsed());
        assert!(
            events.is_empty(),
            "the timer's completion packet surfaced as an event"
        );
    }
    let median = median(took);
    assert!(median < BOUND, "a 1 ms poll took {median:?} at the median");
}

#[test]
fn a_tokio_sleep_ends_before_the_tick() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let took = runtime.block_on(async {
        let mut took = Vec::with_capacity(WAITS);
        for _ in 0..WAITS {
            let start = Instant::now();
            tokio::time::sleep(Duration::from_millis(1)).await;
            took.push(start.elapsed());
        }
        took
    });
    let median = median(took);
    assert!(median < BOUND, "a 1 ms sleep took {median:?} at the median");
}
