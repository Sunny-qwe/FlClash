use std::sync::Arc;
use std::sync::Mutex;

use concord_common::sync::lock;
use concord_common::{CoreEvent, EventSink, RouteStamp, RouteView};

#[derive(Default)]
struct State {
    view: RouteView,
    watched: bool,
}

/// The route model: Reset voids every earlier probe answer, Moved says a pick may
/// have changed. Counters always advance; events go out only while watched, under
/// the lock, because Dart overwrites its state blindly and so same-class events
/// must stay in order.
pub struct RouteCounters {
    state: Mutex<State>,
    sink: Arc<dyn EventSink>,
}

impl RouteCounters {
    pub fn new(sink: Arc<dyn EventSink>) -> Self {
        RouteCounters {
            state: Mutex::new(State::default()),
            sink,
        }
    }

    pub fn stamp(&self) -> RouteStamp {
        self.view().stamp
    }

    pub fn view(&self) -> RouteView {
        lock(&self.state).view
    }

    pub fn reset(&self, running: bool) {
        self.advance(Some(running));
    }

    pub fn moved(&self) {
        self.advance(None);
    }

    fn advance(&self, reset: Option<bool>) {
        let mut state = lock(&self.state);
        if let Some(running) = reset {
            state.view.stamp.epoch += 1;
            state.view.running = running;
        }
        state.view.stamp.version += 1;
        if state.watched {
            self.sink.publish(CoreEvent::RouteChanged(state.view));
        }
    }

    pub fn watch(&self, watched: bool) -> RouteView {
        let mut state = lock(&self.state);
        state.watched = watched;
        state.view
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;

    #[derive(Default)]
    struct Collect(StdMutex<Vec<RouteView>>);

    impl EventSink for Collect {
        fn enabled(&self) -> bool {
            true
        }

        fn publish(&self, event: CoreEvent) {
            if let CoreEvent::RouteChanged(view) = event {
                lock(&self.0).push(view);
            }
        }
    }

    #[test]
    fn counters_always_advance_and_events_only_flow_while_watched() {
        let sink = Arc::new(Collect::default());
        let route = RouteCounters::new(sink.clone());
        route.moved();
        assert_eq!(
            route.stamp(),
            RouteStamp {
                epoch: 0,
                version: 1
            }
        );
        assert!(lock(&sink.0).is_empty());

        assert_eq!(
            route.watch(true).stamp,
            RouteStamp {
                epoch: 0,
                version: 1
            }
        );
        route.reset(false);
        assert_eq!(
            lock(&sink.0).as_slice(),
            [RouteView {
                stamp: RouteStamp {
                    epoch: 1,
                    version: 2
                },
                running: false,
            }]
        );

        route.watch(false);
        route.moved();
        assert_eq!(lock(&sink.0).len(), 1);
        assert_eq!(
            route.stamp(),
            RouteStamp {
                epoch: 1,
                version: 3
            }
        );
    }

    #[test]
    fn concurrent_advances_are_published_in_stamp_order() {
        let sink = Arc::new(Collect::default());
        let route = Arc::new(RouteCounters::new(sink.clone()));
        route.watch(true);

        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let route = route.clone();
                std::thread::spawn(move || {
                    for step in 0..100 {
                        if (worker + step) % 10 == 0 {
                            route.reset(true);
                        } else {
                            route.moved();
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        let seen = lock(&sink.0);
        assert_eq!(seen.len(), 800);
        assert!(
            seen.windows(2)
                .all(|pair| pair[0].stamp.version + 1 == pair[1].stamp.version
                    && pair[0].stamp.epoch <= pair[1].stamp.epoch)
        );
    }

    #[test]
    fn the_listeners_state_travels_with_the_epoch() {
        let sink = Arc::new(Collect::default());
        let route = RouteCounters::new(sink.clone());
        route.watch(true);

        route.reset(true);
        route.moved();
        route.reset(false);

        let running: Vec<_> = lock(&sink.0)
            .iter()
            .map(|view| (view.stamp.epoch, view.running))
            .collect();
        assert_eq!(running, [(1, true), (1, true), (2, false)]);
        assert_eq!(route.view().running, route.watch(true).running);
    }
}
