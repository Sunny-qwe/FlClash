//! The driver's waker while it drains its own poller. Draining marks descriptors ready and wakes
//! whoever waits on them, and for the TUN and the sockets the driver reads itself that is the
//! driver, in the middle of its own poll. Tokio sends a task woken while it runs back through
//! the scheduler and wakes an idle worker for it (`schedule_local` and `yield_now` in its
//! multi-thread worker), although the pass that follows the drain is about to look at
//! everything the wake announced.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Wake, Waker};

use futures_util::task::AtomicWaker;

#[derive(Default)]
pub(super) struct OwnWake {
    task: AtomicWaker,
    before_pass: AtomicBool,
}

impl OwnWake {
    pub(super) fn new() -> (Arc<Self>, Waker) {
        let own = Arc::new(Self::default());
        let waker = Waker::from(Arc::clone(&own));
        (own, waker)
    }

    /// Runs `drain` for the poll of `task`; it must come before the driver's pass in that
    /// poll: a wake that arrives meanwhile, from the drain or from another thread, is one the
    /// pass answers.
    pub(super) fn before_pass<T>(&self, task: &Waker, drain: impl FnOnce() -> T) -> T {
        self.task.register(task);
        self.before_pass.store(true, Ordering::SeqCst);
        let out = drain();
        self.before_pass.store(false, Ordering::SeqCst);
        out
    }
}

impl Wake for OwnWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.before_pass.load(Ordering::SeqCst) {
            self.task.wake();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn task() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        (count, waker)
    }

    #[test]
    fn a_wake_from_the_drain_before_the_pass_does_not_reach_the_task() {
        let (count, task) = task();
        let (own, waker) = OwnWake::new();

        own.before_pass(&task, || waker.wake_by_ref());

        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_wake_at_any_other_time_reaches_the_task() {
        let (count, task) = task();
        let (own, waker) = OwnWake::new();

        own.before_pass(&task, || ());
        waker.wake_by_ref();
        own.before_pass(&task, || ());
        waker.wake();

        assert_eq!(count.0.load(Ordering::SeqCst), 2);
    }
}
