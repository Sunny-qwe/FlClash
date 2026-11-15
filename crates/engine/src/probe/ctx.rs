use std::time::Duration;

use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError {
    Timeout,
    Failed,
}

impl ProbeError {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeError::Timeout => "timeout",
            ProbeError::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Cancelled,
    Deadline,
}

impl Stop {
    pub fn kind(self) -> ProbeError {
        match self {
            Stop::Cancelled => ProbeError::Failed,
            Stop::Deadline => ProbeError::Timeout,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Stop::Cancelled => "context canceled",
            Stop::Deadline => "context deadline exceeded",
        }
    }
}

/// A cancellation token with a deadline, the two ways a probe is told to stop.
#[derive(Clone)]
pub struct Ctx {
    token: CancellationToken,
    deadline: Instant,
}

impl Ctx {
    pub fn new(timeout: Duration) -> Self {
        Self {
            token: CancellationToken::new(),
            deadline: Instant::now() + timeout,
        }
    }

    /// Ends with the parent, or after `timeout`, whichever is first.
    pub fn child(&self, timeout: Duration) -> Self {
        Self {
            token: self.token.child_token(),
            deadline: self.deadline.min(Instant::now() + timeout),
        }
    }

    pub fn fork(&self) -> Self {
        Self {
            token: self.token.child_token(),
            deadline: self.deadline,
        }
    }

    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    pub fn cancel(&self) {
        self.token.cancel();
    }

    pub fn err(&self) -> Option<Stop> {
        if self.token.is_cancelled() {
            Some(Stop::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(Stop::Deadline)
        } else {
            None
        }
    }

    pub async fn done(&self) -> Stop {
        tokio::select! {
            biased;
            () = self.token.cancelled() => Stop::Cancelled,
            () = sleep_until(self.deadline) => Stop::Deadline,
        }
    }

    pub fn has_budget(&self, timeout: Duration) -> bool {
        self.deadline.saturating_duration_since(Instant::now()) >= timeout
    }
}
