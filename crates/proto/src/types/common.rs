use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A Clash fragment, a proxy mapping or a script output.
pub type Json = serde_json::Value;

dto! {
    /// The result of a method that has nothing to report.
    #[derive(Default)]
    pub struct Empty {}

    /// A file inside the core's home directory.
    pub struct ProfileRef {
        pub path: String,
    }

    pub struct Issue {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub line: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub column: Option<u32>,
        pub message: String,
    }

    pub struct IndexedIssue {
        pub index: u32,
        pub message: String,
    }

    pub struct Warning {
        pub level: String,
        /// A stable identifier, such as `unknown_key`, for clients that word the warning themselves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub code: Option<String>,
        pub path: String,
        pub message: String,
    }

    /// Options every stream method accepts beside its own parameters.
    #[derive(Default)]
    pub struct WatchOptions {
        /// Batches the server may send before the next `$/credit`. Default 4.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub credit: Option<u32>,
        /// How long a batch may collect events. Default 16.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_batch_ms: Option<u32>,
        /// Size at which a batch is sent at once. Default 51200.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_batch_bytes: Option<u32>,
    }

    pub struct TextResult {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub file: Option<String>,
        /// Bytes written, for a file output.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub size: Option<u64>,
    }
}

/// Where a large result goes: back in the response, or into a file the caller
/// names inside the home directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Output {
    Inline { inline: bool },
    File { file: String },
}

impl Default for Output {
    fn default() -> Self {
        Output::Inline { inline: true }
    }
}

// Declared in rising severity: the derived order is the filter order.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    Silent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Tcp,
    Udp,
}

dto! {
    pub struct RouteStamp {
        pub epoch: u64,
        pub version: u64,
        /// Whether the listeners were running when `epoch` last moved.
        #[serde(default)]
        pub running: bool,
    }

    pub struct RouteHit {
        pub host: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub proxy: String,
        pub exit: String,
    }
}

impl Issue {
    pub fn message(message: impl Into<String>) -> Self {
        Issue {
            path: None,
            line: None,
            column: None,
            message: message.into(),
        }
    }
}
