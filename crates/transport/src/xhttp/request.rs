use std::collections::BTreeMap;
use std::io;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::browser::Browser;
use super::config::{
    PLACEMENT_AUTO, PLACEMENT_BODY, PLACEMENT_COOKIE, PLACEMENT_HEADER, PLACEMENT_PATH,
    PLACEMENT_QUERY, PLACEMENT_QUERY_IN_HEADER, Settings, XhttpOptions, normalized_path,
};
use super::padding;
use crate::http1::{HeaderMap, escape_path, query_escape};

/// A request before it meets a transport. The path is the decoded one, as in
/// Go's `url.URL`, and is escaped when written.
#[derive(Clone, Debug)]
pub(crate) struct Built {
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: HeaderMap,
    cookies: Vec<(String, String)>,
}

impl Built {
    fn new(method: &str, host: &str, path: String, headers: HeaderMap) -> Built {
        let mut cookies = Vec::new();
        if let Some(existing) = headers.get("Cookie").filter(|c| !c.is_empty()) {
            cookies.push((String::new(), existing.to_string()));
        }
        Built {
            method: method.to_string(),
            host: host.to_string(),
            path,
            query: BTreeMap::new(),
            headers,
            cookies,
        }
    }

    #[cfg(test)]
    pub fn test_new(method: &str, host: &str, path: &str, headers: HeaderMap) -> Built {
        Built::new(method, host, path.to_string(), headers)
    }

    fn raw_query(&self) -> String {
        self.query
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    query_escape(k.as_bytes()),
                    query_escape(v.as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    pub fn path_and_query(&self) -> String {
        let path = escape_path(self.path.as_bytes());
        let query = self.raw_query();
        if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        }
    }

    fn add_cookie(&mut self, name: &str, value: &str) {
        self.cookies.push((name.to_string(), value.to_string()));
    }

    pub fn finish(&mut self) {
        if self.cookies.is_empty() {
            return;
        }
        let joined = self
            .cookies
            .iter()
            .map(|(name, value)| {
                if name.is_empty() {
                    value.clone()
                } else {
                    format!("{name}={value}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        self.headers.set("Cookie", &joined);
        self.cookies.clear();
    }
}

fn append_to_path(path: &str, value: &str) -> String {
    if path.ends_with('/') {
        format!("{path}{value}")
    } else {
        format!("{path}/{value}")
    }
}

/// The request side of `xhttp.Config`: headers, padding and where the session id
/// and sequence number go.
pub(crate) struct RequestFactory {
    opts: XhttpOptions,
    settings: Settings,
    browser: Browser,
    path: String,
}

impl RequestFactory {
    pub fn new(opts: XhttpOptions, settings: Settings, browser: Browser) -> RequestFactory {
        let path = normalized_path(&opts, &settings);
        RequestFactory {
            opts,
            settings,
            browser,
            path,
        }
    }

    pub fn uplink_method(&self) -> &str {
        &self.settings.method
    }

    fn base_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::default();
        for (key, value) in &self.opts.headers {
            headers.set(key, value);
        }
        self.browser.apply_fetch_defaults(&mut headers);
        headers
    }

    fn apply_padding(&self, req: &mut Built) {
        let length = self.settings.x_padding_bytes.rand();
        let (placement, key, header, method) = if self.opts.x_padding_obfs_mode {
            (
                self.opts.x_padding_placement.as_str(),
                self.opts.x_padding_key.as_str(),
                self.opts.x_padding_header.as_str(),
                self.opts.x_padding_method.as_str(),
            )
        } else {
            (PLACEMENT_QUERY_IN_HEADER, "x_padding", "Referer", "")
        };
        let value = padding::generate(method, length);
        match placement {
            PLACEMENT_HEADER => req.headers.set(header, &value),
            PLACEMENT_QUERY_IN_HEADER => {
                let raw = format!("https://{}{}", req.host, escape_path(req.path.as_bytes()));
                req.headers.set(header, &format!("{raw}?{key}={value}"));
            }
            PLACEMENT_COOKIE if !key.is_empty() && !value.is_empty() => req.add_cookie(key, &value),
            PLACEMENT_QUERY if !key.is_empty() && !value.is_empty() => {
                req.query.insert(key.to_string(), value);
            }
            _ => {}
        }
    }

    fn apply_meta(&self, req: &mut Built, session: &str, seq: &str) {
        for (value, placement, key) in [
            (
                session,
                &self.settings.session_placement,
                &self.settings.session_key,
            ),
            (seq, &self.settings.seq_placement, &self.settings.seq_key),
        ] {
            if value.is_empty() {
                continue;
            }
            match placement.as_str() {
                PLACEMENT_PATH => req.path = append_to_path(&req.path, value),
                PLACEMENT_QUERY => {
                    req.query.insert(key.clone(), value.to_string());
                }
                PLACEMENT_HEADER => req.headers.set(key, value),
                PLACEMENT_COOKIE => req.add_cookie(key, value),
                _ => {}
            }
        }
    }

    /// `FillStreamRequest` / `FillDownloadRequest`: `streaming_body` is true for the
    /// uploads that carry a body.
    pub fn stream_request(&self, method: &str, session: &str, streaming_body: bool) -> Built {
        let mut req = Built::new(
            method,
            &self.opts.host,
            self.path.clone(),
            self.base_headers(),
        );
        self.apply_padding(&mut req);
        self.apply_meta(&mut req, session, "");
        if streaming_body && !self.opts.no_grpc_header {
            req.headers.set("Content-Type", "application/grpc");
        }
        req.finish();
        req
    }

    /// `FillPacketRequest`: the body is returned apart when the data rides in the body.
    pub fn packet_request(
        &self,
        session: &str,
        seq: u64,
        data: &[u8],
    ) -> io::Result<(Built, Vec<u8>)> {
        let placement = self.settings.data_placement.as_str();
        let mut req = Built::new(
            &self.settings.method,
            &self.opts.host,
            self.path.clone(),
            self.base_headers(),
        );
        let mut body = Vec::new();
        if placement == PLACEMENT_BODY || placement == PLACEMENT_AUTO {
            body = data.to_vec();
        } else if placement == PLACEMENT_HEADER {
            let encoded = URL_SAFE_NO_PAD.encode(data);
            for (idx, chunk) in self.chunks(&encoded).into_iter().enumerate() {
                req.headers
                    .set(&format!("{}-{idx}", self.opts.uplink_data_key), &chunk);
            }
        } else if placement == PLACEMENT_COOKIE {
            let encoded = URL_SAFE_NO_PAD.encode(data);
            for (idx, chunk) in self.chunks(&encoded).into_iter().enumerate() {
                req.add_cookie(&format!("{}_{idx}", self.opts.uplink_data_key), &chunk);
            }
        }
        self.apply_padding(&mut req);
        self.apply_meta(&mut req, session, &seq.to_string());
        req.finish();
        Ok((req, body))
    }

    fn chunks(&self, encoded: &str) -> Vec<String> {
        let mut rest = encoded;
        let mut out = Vec::new();
        while !rest.is_empty() {
            let size = self
                .settings
                .uplink_chunk_size
                .rand()
                .max(1)
                .min(rest.len());
            let (head, tail) = rest.split_at(size);
            out.push(head.to_string());
            rest = tail;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factory(opts: XhttpOptions) -> RequestFactory {
        let settings = Settings::resolve(&opts).unwrap();
        RequestFactory::new(opts, settings, Browser::new())
    }

    fn base() -> XhttpOptions {
        XhttpOptions {
            host: "cdn.example.com".into(),
            path: "/xh".into(),
            ..XhttpOptions::default()
        }
    }

    #[test]
    fn stream_up_upload_default_layout() {
        let f = factory(base());
        let req = f.stream_request("POST", "sess", true);
        assert_eq!(req.path_and_query(), "/xh/sess");
        let referer = req.headers.get("Referer").unwrap();
        assert!(
            referer.starts_with("https://cdn.example.com/xh/?x_padding=XXXX"),
            "{referer}"
        );
        let pad = referer.split("x_padding=").nth(1).unwrap();
        assert!((100..=1000).contains(&pad.len()));
        assert_eq!(req.headers.get("Content-Type"), Some("application/grpc"));
    }

    #[test]
    fn download_has_no_grpc_content_type_and_no_grpc_with_the_flag() {
        let f = factory(base());
        assert!(
            f.stream_request("GET", "s", false)
                .headers
                .get("Content-Type")
                .is_none()
        );
        let mut opts = base();
        opts.no_grpc_header = true;
        assert!(
            factory(opts)
                .stream_request("POST", "", true)
                .headers
                .get("Content-Type")
                .is_none()
        );
    }

    #[test]
    fn packet_up_puts_session_and_seq_in_the_path() {
        let f = factory(base());
        let (req, body) = f.packet_request("sess", 7, b"abc").unwrap();
        assert_eq!(req.path_and_query(), "/xh/sess/7");
        assert_eq!(req.method, "POST");
        assert_eq!(body, b"abc");
    }

    #[test]
    fn obfs_padding_and_other_placements() {
        let mut opts = base();
        opts.x_padding_obfs_mode = true;
        opts.x_padding_placement = "query".into();
        opts.x_padding_key = "pad".into();
        opts.x_padding_bytes = "5".into();
        opts.session_placement = "header".into();
        opts.seq_placement = "cookie".into();
        opts.path = "/xh".into();
        let f = factory(opts);
        let (req, _) = f.packet_request("sess", 3, b"x").unwrap();
        assert_eq!(req.path_and_query(), "/xh?pad=XXXXX");
        assert_eq!(req.headers.get("X-Session"), Some("sess"));
        assert_eq!(req.headers.get("Cookie"), Some("x_seq=3"));
        assert!(req.headers.get("Referer").is_none());
    }

    #[test]
    fn header_and_cookie_data_placements_chunk_base64() {
        let mut opts = base();
        opts.uplink_data_placement = "header".into();
        opts.uplink_data_key = "X-Data".into();
        opts.uplink_chunk_size = "64".into();
        let f = factory(opts);
        let data = vec![7u8; 80];
        let (req, body) = f.packet_request("s", 0, &data).unwrap();
        assert!(body.is_empty());
        let encoded = URL_SAFE_NO_PAD.encode(&data);
        let joined = format!(
            "{}{}",
            req.headers.get("X-Data-0").unwrap(),
            req.headers.get("X-Data-1").unwrap()
        );
        assert_eq!(joined, encoded);
        assert_eq!(req.headers.get("X-Data-0").unwrap().len(), 64);

        let mut opts = base();
        opts.uplink_data_placement = "cookie".into();
        opts.uplink_data_key = "d".into();
        opts.uplink_chunk_size = "64".into();
        let (req, _) = factory(opts).packet_request("s", 0, &data).unwrap();
        let cookie = req.headers.get("Cookie").unwrap();
        assert!(cookie.starts_with("d_0="));
        assert!(cookie.contains("; d_1="));
    }

    #[test]
    fn custom_path_escapes_like_go() {
        let mut opts = base();
        opts.path = "/a b".into();
        let f = factory(opts);
        let req = f.stream_request("POST", "", true);
        assert_eq!(req.path_and_query(), "/a%20b/");
    }
}
