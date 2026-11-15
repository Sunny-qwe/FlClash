//! The wire protocol of the core: payload types, errors and the registry of
//! methods. It knows no runtime, transport or engine.

mod error;
mod registry;
mod schema;
pub mod types;

pub use error::{
    ApiError, ERROR_KINDS, ErrorData, ErrorObject, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST,
    METHOD_NOT_FOUND, PARSE_ERROR,
};
pub use registry::{Cap, Exec, Kind, METHODS, MethodSpec, StreamPolicy, method};
pub use schema::api_schema;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_MESSAGE: u64 = 64 * 1024 * 1024;
pub const MAX_BATCH_BYTES: u32 = 51_200;
pub const DEFAULT_CREDIT: u32 = 4;
pub const DEFAULT_BATCH_MS: u32 = 16;

#[cfg(test)]
mod tests;
