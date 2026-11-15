// The excluded vendor crate shares the workspace test gate and target through its actual source.
pub use quinn_proto::congestion;
pub use std::time::{Duration, Instant};

#[path = "../../../vendor/quinn-proto/src/connection/pacing.rs"]
mod pacing;
