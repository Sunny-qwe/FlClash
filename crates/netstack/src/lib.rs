#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod attach;
mod buffer;
mod cc;
mod engine;
pub mod frag;
mod readiness;
mod seq;
mod stream;
mod tcp;
pub mod wire;

pub use attach::Gather;
pub use cc::Congestion;
pub use engine::{Accepted, Admit, FlowOwner, StackConfig, TcpInput, TcpStack};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use readiness::SocketSource;
pub use readiness::{SocketOwner, SocketReady};
pub use stream::{NetReadHalf, NetStream, NetWriteHalf};
pub use tcp::{Egress, TcpConfig};

#[cfg(test)]
mod tests;
