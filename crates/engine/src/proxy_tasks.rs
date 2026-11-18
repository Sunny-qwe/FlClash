use std::sync::Mutex;

use concord_common::Tasks;
use concord_common::sync::lock;
use tokio_util::sync::CancellationToken;

/// The share of the engine's tracker that a config's work runs on, and the stop it watches.
/// Shutdown stops them; what starts after it gets a fresh stop, so a long-lived part takes these
/// each time it starts rather than once.
pub(crate) struct ProxyTasks {
    base: Tasks,
    stop: Mutex<CancellationToken>,
}

impl ProxyTasks {
    pub(crate) fn new(base: Tasks) -> Self {
        ProxyTasks {
            base,
            stop: Mutex::new(CancellationToken::new()),
        }
    }

    pub(crate) fn tasks(&self) -> Tasks {
        self.base.with_stop(lock(&self.stop).clone())
    }

    pub(crate) fn stop(&self) {
        let stopped = std::mem::take(&mut *lock(&self.stop));
        stopped.cancel();
    }
}
