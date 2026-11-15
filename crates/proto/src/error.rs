use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::Issue;

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// The stable part of an error. Clients branch on `kind`; `message` is for people.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ErrorData {
    InvalidParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    Unsupported {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability: Option<String>,
    },
    NotFound {
        entity: String,
        name: String,
    },
    #[serde(rename_all = "camelCase")]
    Rejected {
        #[serde(default)]
        issues: Vec<Issue>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fell_back: Option<bool>,
        /// A stable subcode, such as `rule_set_empty`, for clients that word the failure themselves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Conflict {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<String>,
    },
    Cancelled,
    Timeout {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<u64>,
    },
    Unavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
    },
    PayloadTooLarge {
        limit: u64,
    },
    Internal,
}

impl ErrorData {
    pub fn kind(&self) -> &'static str {
        match self {
            ErrorData::InvalidParams { .. } => "invalid_params",
            ErrorData::Unsupported { .. } => "unsupported",
            ErrorData::NotFound { .. } => "not_found",
            ErrorData::Rejected { .. } => "rejected",
            ErrorData::Conflict { .. } => "conflict",
            ErrorData::Cancelled => "cancelled",
            ErrorData::Timeout { .. } => "timeout",
            ErrorData::Unavailable { .. } => "unavailable",
            ErrorData::PayloadTooLarge { .. } => "payload_too_large",
            ErrorData::Internal => "internal",
        }
    }

    /// Standard JSON-RPC codes where one exists, the -32010 block otherwise.
    pub fn code(&self) -> i32 {
        match self {
            ErrorData::InvalidParams { .. } => INVALID_PARAMS,
            ErrorData::Unsupported { .. } => METHOD_NOT_FOUND,
            ErrorData::Internal => INTERNAL_ERROR,
            ErrorData::NotFound { .. } => -32010,
            ErrorData::Rejected { .. } => -32011,
            ErrorData::Conflict { .. } => -32012,
            ErrorData::Cancelled => -32014,
            ErrorData::Timeout { .. } => -32015,
            ErrorData::Unavailable { .. } => -32016,
            ErrorData::PayloadTooLarge { .. } => -32017,
        }
    }
}

/// Every kind with the fields it carries, which `schema/api.json` publishes.
pub const ERROR_KINDS: &[(&str, i32, &str)] = &[
    ("invalid_params", INVALID_PARAMS, "path"),
    ("unsupported", METHOD_NOT_FOUND, "method | capability"),
    ("not_found", -32010, "entity, name"),
    ("rejected", -32011, "issues, fellBack, reason"),
    ("conflict", -32012, "state"),
    ("cancelled", -32014, ""),
    ("timeout", -32015, "after"),
    ("unavailable", -32016, "target"),
    ("payload_too_large", -32017, "limit"),
    ("internal", INTERNAL_ERROR, ""),
];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorObject {
    pub code: i32,
    pub message: String,
    pub data: ErrorData,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApiError {
    pub message: String,
    pub data: ErrorData,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.data.kind(), self.message)
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    pub fn new(data: ErrorData, message: impl Into<String>) -> Self {
        ApiError {
            message: message.into(),
            data,
        }
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorData::InvalidParams { path: None }, message)
    }

    pub fn invalid_field(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            ErrorData::InvalidParams {
                path: Some(path.into()),
            },
            message,
        )
    }

    pub fn unsupported_method(method: impl Into<String>) -> Self {
        let method = method.into();
        Self::new(
            ErrorData::Unsupported {
                method: Some(method.clone()),
                capability: None,
            },
            format!("unknown method: {method}"),
        )
    }

    pub fn unsupported_capability(
        capability: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(
            ErrorData::Unsupported {
                method: None,
                capability: Some(capability.into()),
            },
            message,
        )
    }

    pub fn not_found(entity: impl Into<String>, name: impl Into<String>) -> Self {
        let (entity, name) = (entity.into(), name.into());
        Self::new(
            ErrorData::NotFound {
                entity: entity.clone(),
                name: name.clone(),
            },
            format!("{entity} not found: {name}"),
        )
    }

    pub fn conflict(state: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            ErrorData::Conflict {
                state: Some(state.into()),
            },
            message,
        )
    }

    pub fn rejected(message: impl Into<String>, fell_back: bool) -> Self {
        let message = message.into();
        Self::new(
            ErrorData::Rejected {
                issues: vec![Issue::message(message.clone())],
                fell_back: fell_back.then_some(true),
                reason: None,
            },
            message,
        )
    }

    pub fn rejected_because(reason: &str, message: impl Into<String>) -> Self {
        let message = message.into();
        Self::new(
            ErrorData::Rejected {
                issues: vec![Issue::message(message.clone())],
                fell_back: None,
                reason: Some(reason.to_string()),
            },
            message,
        )
    }

    pub fn cancelled() -> Self {
        Self::new(ErrorData::Cancelled, "the request was cancelled")
    }

    pub fn unavailable(target: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(
            ErrorData::Unavailable {
                target: Some(target.into()),
            },
            message,
        )
    }

    pub fn payload_too_large(limit: u64) -> Self {
        Self::new(
            ErrorData::PayloadTooLarge { limit },
            format!("the message is larger than {limit} bytes"),
        )
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorData::Internal, message)
    }

    pub fn code(&self) -> i32 {
        self.data.code()
    }

    pub fn to_object(&self) -> ErrorObject {
        ErrorObject {
            code: self.code(),
            message: self.message.clone(),
            data: self.data.clone(),
        }
    }
}

impl From<ErrorObject> for ApiError {
    fn from(object: ErrorObject) -> Self {
        ApiError {
            message: object.message,
            data: object.data,
        }
    }
}
