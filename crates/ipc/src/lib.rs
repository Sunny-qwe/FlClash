//! Length-prefixed frames over a Unix socket, a named pipe or a loopback port,
//! and the handshake that proves both ends hold the session token first.

mod auth;
mod frame;

pub use auth::{AuthError, HANDSHAKE_TIMEOUT, TOKEN_LEN, Token, initiate, respond};
pub use frame::{Connection, FramedChannel, FramedReader, FramedWriter, Socket, dial};
