//! Background tasks of the crates below the engine (nodes, the resolver, groups, the tunnel), owned
//! by the engine: every one is registered with the engine's tracker, so shutdown can stop them and
//! wait until they are gone.

use std::future::Future;

use tokio::runtime::{EnterGuard, Handle};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tokio_util::task::TaskTracker;

#[derive(Clone, Default)]
pub struct Tasks {
    tracker: TaskTracker,
    stop: CancellationToken,
    handle: Option<Handle>,
}

impl std::fmt::Debug for Tasks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tasks")
            .field("running", &self.tracker.len())
            .finish_non_exhaustive()
    }
}

impl Tasks {
    /// Tasks spawned through this run on `handle`, also when spawned from a `Drop` outside it.
    pub fn new(tracker: TaskTracker, stop: CancellationToken, handle: Handle) -> Self {
        Tasks {
            tracker,
            stop,
            handle: Some(handle),
        }
    }

    /// On the runtime this is called from. Panics outside one, like `Handle::current`.
    pub fn current(tracker: TaskTracker, stop: CancellationToken) -> Self {
        Self::new(tracker, stop, Handle::current())
    }

    /// The same tracker and runtime, watching `stop` instead.
    pub fn with_stop(&self, stop: CancellationToken) -> Self {
        Tasks {
            tracker: self.tracker.clone(),
            stop,
            handle: self.handle.clone(),
        }
    }

    /// Enters the runtime the tasks run on, for building what needs one (a socket taken from
    /// std) where the caller may be off it.
    pub fn enter(&self) -> Option<EnterGuard<'_>> {
        self.handle.as_ref().map(Handle::enter)
    }

    /// Runs `work` on the blocking pool, tracked like the rest. The stop cannot cancel it, so a
    /// long one holds shutdown up to its grace. Panics outside a runtime.
    pub fn spawn_blocking<F, R>(&self, work: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let handle = self.handle();
        self.tracker.spawn_blocking_on(work, &handle)
    }

    /// Runs `task` until it ends or the owner stops. Panics outside a runtime, like
    /// `tokio::spawn`.
    pub fn spawn<F>(&self, task: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let handle = self.handle();
        self.tracker.spawn_on(self.until_stopped(task), &handle)
    }

    /// Like `spawn`, for a caller that awaits the output: `None` when the owner stopped first.
    pub fn spawn_returning<F>(&self, task: F) -> JoinHandle<Option<F::Output>>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let handle = self.handle();
        let stop = self.stop.clone();
        self.tracker.spawn_on(
            async move { stop.run_until_cancelled_owned(task).await },
            &handle,
        )
    }

    /// A teardown nothing waits for, started where there may be no runtime (a `Drop`); without
    /// one it is skipped and this returns false. It ends when the owner stops, like `spawn`.
    pub fn spawn_detached<F>(&self, task: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(handle) = self.runtime() else {
            return false;
        };
        self.tracker.spawn_on(self.until_stopped(task), &handle);
        true
    }

    /// Runs `task` to its end even after the owner stops, or skips it and returns false without a
    /// runtime. Only for a task something else bounds: a QUIC connection draining after its close,
    /// a device that aborts and joins its own tasks, a flow the connection table closes.
    pub fn spawn_to_end<F>(&self, task: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let Some(handle) = self.runtime() else {
            return false;
        };
        self.tracker.spawn_on(task, &handle);
        true
    }

    pub fn stopped(&self) -> WaitForCancellationFuture<'_> {
        self.stop.cancelled()
    }

    pub fn child_token(&self) -> CancellationToken {
        self.stop.child_token()
    }

    fn runtime(&self) -> Option<Handle> {
        self.handle.clone().or_else(|| Handle::try_current().ok())
    }

    fn handle(&self) -> Handle {
        self.runtime().unwrap_or_else(Handle::current)
    }

    fn until_stopped<F>(&self, task: F) -> impl Future<Output = ()> + Send + 'static
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let stop = self.stop.clone();
        async move {
            let _ = stop.run_until_cancelled_owned(task).await;
        }
    }
}

/// Whether this thread is in a runtime, for code that may not wait and must not start one.
pub fn in_runtime() -> bool {
    Handle::try_current().is_ok()
}

/// The worker threads of the runtime this thread is in, if it is in one.
pub fn runtime_workers() -> Option<usize> {
    Handle::try_current()
        .ok()
        .map(|runtime| runtime.metrics().num_workers())
}

/// hyper's HTTP/2 connections start a task per request body through their executor.
#[cfg(feature = "hyper")]
impl<F> hyper::rt::Executor<F> for Tasks
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        self.spawn(async move {
            future.await;
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn tasks() -> (Tasks, TaskTracker, CancellationToken) {
        let tracker = TaskTracker::new();
        let stop = CancellationToken::new();
        let tasks = Tasks::new(tracker.clone(), stop.clone(), Handle::current());
        (tasks, tracker, stop)
    }

    #[tokio::test]
    async fn stopping_ends_spawned_and_detached_tasks_but_not_one_run_to_its_end() {
        let (tasks, tracker, stop) = tasks();
        let (finish, finished) = tokio::sync::oneshot::channel::<()>();
        let ended = Arc::new(AtomicBool::new(false));
        tasks.spawn(std::future::pending());
        tasks.spawn_detached(std::future::pending());
        tasks.spawn_to_end({
            let ended = ended.clone();
            async move {
                let _ = finished.await;
                ended.store(true, Ordering::SeqCst);
            }
        });
        assert_eq!(tracker.len(), 3);
        stop.cancel();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(tracker.len(), 1);
        finish.send(()).unwrap();
        tracker.close();
        tracker.wait().await;
        assert!(ended.load(Ordering::SeqCst));
    }

    #[test]
    fn a_detached_teardown_without_a_runtime_is_skipped() {
        let tasks = Tasks::default();
        tasks.spawn_detached(async {});
        tasks.spawn_to_end(async {});
        assert!(tasks.tracker.is_empty());
    }
}
