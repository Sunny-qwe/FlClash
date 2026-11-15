use concord_proto::ApiError;
use serde::Deserialize;
use serde_json::value::RawValue;

/// Any message from the peer. `result` and `error` are accepted and ignored, so a
/// response to something the server never asked is not a parse failure.
#[derive(Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub id: Option<Box<RawValue>>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Box<RawValue>>,
}

pub fn id_key(id: &RawValue) -> String {
    id.get().trim().to_string()
}

fn start(id: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(br#"{"jsonrpc":"2.0","id":"#);
    out.extend_from_slice(id.unwrap_or("null").as_bytes());
    out
}

/// Assembled by hand because `result` is already JSON, and decoding a megabyte
/// payload only to wrap it would double the cost.
pub fn response(id: &str, result: &[u8]) -> Vec<u8> {
    let mut out = start(Some(id));
    out.reserve(result.len() + 12);
    out.extend_from_slice(br#","result":"#);
    out.extend_from_slice(result);
    out.push(b'}');
    out
}

pub fn error_response(id: Option<&str>, error: &ApiError) -> Vec<u8> {
    let mut out = start(id);
    out.extend_from_slice(br#","error":"#);
    match serde_json::to_vec(&error.to_object()) {
        Ok(body) => out.extend_from_slice(&body),
        Err(_) => out.extend_from_slice(
            br#"{"code":-32603,"message":"encode error","data":{"kind":"internal"}}"#,
        ),
    }
    out.push(b'}');
    out
}

pub fn notification(method: &str, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(params.len() + method.len() + 48);
    out.extend_from_slice(br#"{"jsonrpc":"2.0","method":""#);
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(br#"","params":"#);
    out.extend_from_slice(params);
    out.push(b'}');
    out
}

/// `{"sub":3,"seq":7,"data":[…],"dropped":2}` from already encoded events.
pub fn event_params(sub: u64, seq: u64, events: &[Vec<u8>], dropped: u64) -> Vec<u8> {
    let size: usize = events.iter().map(|event| event.len() + 1).sum();
    let mut out = Vec::with_capacity(size + 64);
    out.extend_from_slice(format!("{{\"sub\":{sub},\"seq\":{seq},\"data\":[").as_bytes());
    for (index, event) in events.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(event);
    }
    out.push(b']');
    if dropped > 0 {
        out.extend_from_slice(format!(",\"dropped\":{dropped}").as_bytes());
    }
    out.push(b'}');
    out
}

pub fn resync_params(sub: u64, seq: u64) -> Vec<u8> {
    format!("{{\"sub\":{sub},\"seq\":{seq},\"resync\":true}}").into_bytes()
}
