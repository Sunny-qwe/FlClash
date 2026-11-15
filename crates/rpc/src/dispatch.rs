use std::sync::Arc;

use concord_api::{ControlService, Delivery};
use concord_proto::ApiError;
use concord_proto::types::WatchOptions;
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;

/// An event as it goes on the wire. Encoding happens when the stream is polled,
/// so a subscription nobody pulls from encodes nothing.
pub type Encoded = Delivery<Vec<u8>>;

pub struct StreamReply {
    pub options: WatchOptions,
    pub snapshot: Option<Vec<u8>>,
    pub events: BoxStream<'static, Encoded>,
}

pub enum Reply {
    Unary(Vec<u8>),
    Stream(StreamReply),
}

pub type Call = BoxFuture<'static, Result<Reply, ApiError>>;

fn path_of(message: &str) -> Option<String> {
    let start = message.find('`')? + 1;
    let end = start + message[start..].find('`')?;
    Some(message[start..end].to_string())
}

pub(crate) fn decode<P: DeserializeOwned>(raw: Option<&RawValue>) -> Result<P, ApiError> {
    let text = match raw.map(|raw| raw.get().trim()) {
        None | Some("null") => "{}",
        Some(text) if text.starts_with('{') => text,
        Some(_) => return Err(ApiError::invalid_params("params must be an object")),
    };
    serde_json::from_str(text).map_err(|err| {
        let message = err.to_string();
        match path_of(&message) {
            Some(path) => ApiError::invalid_field(path, message),
            None => ApiError::invalid_params(message),
        }
    })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(value).map_err(|err| ApiError::internal(format!("encode result: {err}")))
}

fn encode_events<E: Serialize + Send + 'static>(
    events: BoxStream<'static, Delivery<E>>,
) -> BoxStream<'static, Encoded> {
    events
        .filter_map(|delivery| {
            std::future::ready(match delivery {
                Delivery::Event { data, dropped } => match serde_json::to_vec(&data) {
                    Ok(data) => Some(Delivery::Event { data, dropped }),
                    Err(err) => {
                        tracing::warn!("stream event dropped, it does not encode: {err}");
                        None
                    }
                },
                Delivery::Resync => Some(Delivery::Resync),
            })
        })
        .boxed()
}

macro_rules! invoke_one {
    (rpc, $service:ident, $fun:ident, $params:ty, $raw:ident) => {
        Box::pin(async move { Err(ApiError::internal("answered by the RPC layer")) })
    };
    (unary, $service:ident, $fun:ident, $params:ty, $raw:ident) => {
        Box::pin(async move {
            let params: $params = decode($raw.as_deref())?;
            let result = $service.$fun(params).await?;
            Ok(Reply::Unary(encode(&result)?))
        })
    };
    (stream, $service:ident, $fun:ident, $params:ty, $raw:ident) => {
        Box::pin(async move {
            let params: $params = decode($raw.as_deref())?;
            let options = params.watch.clone();
            let subscription = $service.$fun(params).await?;
            let snapshot = match &subscription.snapshot {
                Some(snapshot) => Some(encode(snapshot)?),
                None => None,
            };
            Ok(Reply::Stream(StreamReply {
                options,
                snapshot,
                events: encode_events(subscription.events),
            }))
        })
    };
}

macro_rules! invoke_table {
    ($({ kind: $kind:ident, fun: $fun:ident, name: $name:literal, exec: $exec:ident, params: $params:ty, result: $result:ty, event: $event:ty, policy: $policy:ident, cap: $cap:ident })*) => {
        /// The typed call behind a method name, ready to run: it decodes the
        /// parameters, calls the service and encodes the result.
        pub fn invoke<S: ControlService>(
            service: Arc<S>,
            name: &str,
            raw: Option<Box<RawValue>>,
        ) -> Option<Call> {
            match name {
                $($name => Some(invoke_one!($kind, service, $fun, $params, raw)),)*
                _ => None,
            }
        }
    };
}

concord_proto::with_methods!(invoke_table);
