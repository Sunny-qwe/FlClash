use std::future::Future;

use concord_proto::ApiError;
use concord_proto::types::*;

use crate::stream::Subscription;

/// What the RPC layer needs to know about the server for `core.hello`.
#[derive(Clone, Debug)]
pub struct ServiceInfo {
    pub server: ServerInfo,
    pub platform: PlatformInfo,
    pub features: Features,
    pub engine: EngineStatus,
    /// Whether the build answers `debug.*`.
    pub debug: bool,
}

macro_rules! service_fn {
    (rpc, $fun:ident, $name:literal, $params:ty, $result:ty, $event:ty) => {};
    (unary, $fun:ident, $name:literal, $params:ty, $result:ty, $event:ty) => {
        fn $fun(&self, params: $params) -> impl Future<Output = Result<$result, ApiError>> + Send {
            let _ = params;
            async { Err(ApiError::unsupported_method($name)) }
        }
    };
    (stream, $fun:ident, $name:literal, $params:ty, $result:ty, $event:ty) => {
        fn $fun(
            &self,
            params: $params,
        ) -> impl Future<Output = Result<Subscription<$result, $event>, ApiError>> + Send {
            let _ = params;
            async { Err(ApiError::unsupported_method($name)) }
        }
    };
}

macro_rules! service_trait {
    ($({ kind: $kind:ident, fun: $fun:ident, name: $name:literal, exec: $exec:ident, params: $params:ty, result: $result:ty, event: $event:ty, policy: $policy:ident, cap: $cap:ident })*) => {
        /// One typed async function per method of the registry. A method a service
        /// does not override answers `unsupported`, which is how a partial service,
        /// such as a test double, stays small.
        pub trait ControlService: Send + Sync + 'static {
            fn info(&self) -> ServiceInfo;

            $( service_fn!($kind, $fun, $name, $params, $result, $event); )*
        }
    };
}

concord_proto::with_methods!(service_trait);
