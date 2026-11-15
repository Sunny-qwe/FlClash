use schemars::SchemaGenerator;
use schemars::generate::SchemaSettings;
use serde_json::{Map, Value, json};

use crate::error::ErrorObject;
use crate::registry::{Kind, METHODS};
use crate::{
    DEFAULT_BATCH_MS, DEFAULT_CREDIT, ERROR_KINDS, MAX_BATCH_BYTES, MAX_MESSAGE, PROTOCOL_VERSION,
};

fn value(schema: schemars::Schema) -> Value {
    serde_json::to_value(schema).unwrap_or(Value::Null)
}

/// The document `schema/api.json` holds: every method with its parameters, result,
/// execution class and stream policy, the error kinds, and the shared definitions.
pub fn api_schema() -> Value {
    let mut generator = SchemaGenerator::new(SchemaSettings::draft2020_12());
    let methods: Vec<Value> = METHODS
        .iter()
        .map(|spec| {
            let mut entry = Map::new();
            entry.insert("name".into(), json!(spec.name));
            entry.insert(
                "kind".into(),
                json!(match spec.kind {
                    Kind::Unary => "unary",
                    Kind::Stream => "stream",
                    Kind::Rpc => "rpc",
                }),
            );
            entry.insert("exec".into(), json!(spec.exec.name()));
            if let Some(capability) = spec.capability.name() {
                entry.insert("capability".into(), json!(capability));
            }
            entry.insert("params".into(), value((spec.params)(&mut generator)));
            entry.insert(
                if spec.kind == Kind::Stream {
                    "snapshot"
                } else {
                    "result"
                }
                .into(),
                value((spec.result)(&mut generator)),
            );
            if let Some(policy) = spec.policy {
                entry.insert(
                    "stream".into(),
                    json!({
                        "policy": policy.name(),
                        "event": value((spec.event)(&mut generator)),
                    }),
                );
            }
            Value::Object(entry)
        })
        .collect();
    let errors: Vec<Value> = ERROR_KINDS
        .iter()
        .map(|(kind, code, fields)| json!({"kind": kind, "code": code, "fields": fields}))
        .collect();
    let error = value(generator.subschema_for::<ErrorObject>());
    let definitions = generator.take_definitions(true);
    json!({
        "version": PROTOCOL_VERSION,
        "limits": {
            "maxMessage": MAX_MESSAGE,
            "maxBatchBytes": MAX_BATCH_BYTES,
            "defaultCredit": DEFAULT_CREDIT,
            "defaultBatchMs": DEFAULT_BATCH_MS,
        },
        "methods": methods,
        "error": error,
        "errors": errors,
        "$defs": definitions,
    })
}
