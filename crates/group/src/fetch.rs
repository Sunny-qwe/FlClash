use std::time::Duration;

use async_trait::async_trait;

use crate::error::FetchError;

pub struct FetchRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub via_proxy: Option<String>,
    pub size_limit: Option<u64>,
    pub timeout: Duration,
}

pub struct FetchResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FetchResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// A body past `size_limit` is cut, not refused.
#[async_trait]
pub trait Fetcher: Send + Sync {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError>;
}
