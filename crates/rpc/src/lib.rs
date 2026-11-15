//! JSON-RPC 2.0 for the core: envelopes, dispatch by execution class, `core.hello`,
//! cancellation, and subscriptions with credit. It sees a transport only as a
//! `MessageChannel`.

mod channel;
mod dispatch;
mod envelope;
mod pump;
mod server;
mod session;

pub use channel::{
    Incoming, MemoryChannel, MemoryReader, MemoryWriter, MessageChannel, MessageReader,
    MessageWriter, SendError,
};
pub use envelope::{error_response, notification, response};
pub use server::{Server, ServerConfig};
