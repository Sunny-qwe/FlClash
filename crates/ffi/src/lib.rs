//! The C ABI an in-process host reaches the core through. A host opens sessions
//! of the JSON-RPC server, sends one message per call and gets messages back
//! through a receiver: a Dart isolate's posts to its `ReceivePort`, any other host's is a pair of
//! C callbacks.

#![allow(
    unsafe_code,
    reason = "the exported C functions and the Dart native API table are raw pointers by definition"
)]

mod abi;
mod callback;
mod dart;
mod hub;

#[cfg(unix)]
pub use abi::concord_adopt_fd;
pub use abi::{
    concord_close, concord_init_dart_api, concord_open, concord_open_callback, concord_send,
};
pub use callback::{Deliver, Release};
pub use hub::{Hub, Receiver, hub, install, set_notice};

#[cfg(test)]
mod tests;
