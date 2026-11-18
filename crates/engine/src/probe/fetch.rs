use std::io;
use std::pin::pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use concord_common::{Address, BoxStream};
use concord_tls::{TlsConnector, TlsOptions};
use futures_util::{Stream, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyDataStream, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, sleep};
use url::{Position, Url};

use super::ctx::{Ctx, ProbeError};
use super::hits::{DialLog, HitRecorder, RouteHit};
use super::{DEFAULT_PROBE_TIMEOUT, ProbeEnv, Prober};

const TUNNEL_POLL: Duration = Duration::from_millis(50);
const SCAN_OVERLAP: usize = 256;
const MAX_REDIRECTS: usize = 10;
const PRIVATE_ON_REDIRECT: [&str; 4] = ["authorization", "cookie", "cookie2", "www-authenticate"];
const BODY_HEADERS: [&str; 5] = [
    "content-type",
    "content-length",
    "content-encoding",
    "content-language",
    "transfer-encoding",
];

#[derive(Clone)]
pub struct ProbeRequest {
    pub method: Method,
    pub url: String,
    pub proxy: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub timeout: Duration,
    pub max_body: usize,
    /// A followed redirect loses the Location that Netflix names its region in.
    pub no_redirect: bool,
    /// Sees the latest frame of the body and 256 bytes before it.
    pub until: Option<Until>,
    pub recorder: Option<Arc<HitRecorder>>,
}

pub type Until = Arc<dyn Fn(&str) -> bool + Send + Sync>;

impl ProbeRequest {
    pub fn get(url: &str) -> Self {
        Self {
            method: Method::GET,
            url: url.to_string(),
            proxy: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            timeout: Duration::ZERO,
            max_body: 0,
            no_redirect: false,
            until: None,
            recorder: None,
        }
    }
}

#[derive(Default)]
pub struct ProbeResult {
    pub status: u16,
    pub delay: i64,
    pub body: String,
    pub url: String,
    pub chains: Vec<String>,
    pub error: Option<ProbeError>,
    pub message: String,
    pub core_epoch: u64,
    pub route_version: u64,
    pub headers: HeaderMap,
    pub hits: Vec<RouteHit>,
    pub(super) lower_body: OnceLock<String>,
}

impl ProbeResult {
    pub fn body_contains(&self, needles: &[&str]) -> bool {
        let lower = self.lower_body.get_or_init(|| self.body.to_lowercase());
        needles.iter().any(|needle| lower.contains(needle))
    }

    #[cfg(test)]
    pub fn answer(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_string(),
            ..Self::default()
        }
    }

    fn failed(mut self, kind: ProbeError, message: String) -> Self {
        self.error = Some(kind);
        self.message = message;
        self
    }
}

struct Fail {
    kind: ProbeError,
    message: String,
}

impl Fail {
    fn failed(err: impl std::fmt::Display) -> Self {
        Self {
            kind: ProbeError::Failed,
            message: err.to_string(),
        }
    }
}

impl From<io::Error> for Fail {
    fn from(err: io::Error) -> Self {
        let kind = if err.kind() == io::ErrorKind::TimedOut {
            ProbeError::Timeout
        } else {
            ProbeError::Failed
        };
        Self {
            kind,
            message: err.to_string(),
        }
    }
}

/// Records the hits when the probe ends, including when its future is dropped.
struct HitGuard {
    env: Arc<dyn ProbeEnv>,
    log: Arc<DialLog>,
    proxy: String,
    recorder: Option<Arc<HitRecorder>>,
    finished: bool,
}

impl HitGuard {
    fn collect(&self) -> Vec<RouteHit> {
        let hits = self.log.hits(&*self.env, &self.proxy);
        if let Some(recorder) = &self.recorder {
            recorder.add(&hits);
        }
        hits
    }

    fn finish(mut self) -> Vec<RouteHit> {
        self.finished = true;
        self.collect()
    }
}

impl Drop for HitGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.collect();
        }
    }
}

pub(super) async fn acquire(slots: &Arc<Semaphore>, ctx: &Ctx) -> Option<OwnedSemaphorePermit> {
    if ctx.err().is_some() {
        return None;
    }
    tokio::select! {
        permit = slots.clone().acquire_owned() => permit.ok(),
        _ = ctx.done() => None,
    }
}

struct Head {
    status: StatusCode,
    headers: HeaderMap,
    url: Url,
    body: Incoming,
    _sender: http1::SendRequest<Full<Bytes>>,
}

impl Prober {
    /// `None` when the request never got a slot before its deadline.
    pub(super) async fn run_probe(&self, parent: &Ctx, req: ProbeRequest) -> Option<ProbeResult> {
        let stamp = self.env.stamp();
        let result = ProbeResult {
            url: req.url.clone(),
            core_epoch: stamp.epoch,
            route_version: stamp.version,
            ..ProbeResult::default()
        };
        if !req.proxy.is_empty() && !self.env.knows(&req.proxy) {
            let hits = vec![RouteHit {
                proxy: req.proxy.clone(),
                ..RouteHit::default()
            }];
            if let Some(recorder) = &req.recorder {
                recorder.add(&hits);
            }
            let message = format!("proxy {:?} is not part of the applied config", req.proxy);
            let mut result = result.failed(ProbeError::Failed, message);
            result.hits = hits;
            return Some(result);
        }

        let log = Arc::new(DialLog::default());
        let guard = HitGuard {
            env: self.env.clone(),
            log: log.clone(),
            proxy: req.proxy.clone(),
            recorder: req.recorder.clone(),
            finished: false,
        };
        let timeout = if req.timeout.is_zero() {
            DEFAULT_PROBE_TIMEOUT
        } else {
            req.timeout
        };
        let _slot = acquire(&self.slots, &parent.child(timeout)).await?;

        let ctx = parent.child(timeout);
        let fetched = self.fetch(&ctx, &req, &log).await;
        ctx.cancel();
        let mut result = match fetched {
            Ok(fetched) => ProbeResult {
                status: fetched.status,
                delay: fetched.delay,
                body: fetched.body,
                url: fetched.url,
                chains: log.last_chains(),
                headers: fetched.headers,
                ..result
            },
            Err(fail) => result.failed(fail.kind, fail.message),
        };
        result.hits = guard.finish();
        Some(result)
    }

    async fn fetch(&self, ctx: &Ctx, req: &ProbeRequest, log: &DialLog) -> Result<Fetched, Fail> {
        let start = Instant::now();
        let head = tokio::select! {
            stop = ctx.done() => {
                return Err(Fail { kind: stop.kind(), message: stop.message().to_string() });
            }
            head = self.exchange(ctx, req, log) => head?,
        };
        let delay = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);

        let mut body = Vec::new();
        if req.max_body > 0 {
            let mut chunks = pin!(BodyDataStream::new(head.body));
            tokio::select! {
                () = read_body(&mut chunks, &mut body, req.max_body, req.until.as_deref()) => {}
                _ = ctx.done() => {}
            }
        }
        let url = if head.url.as_str() == req.url {
            req.url.clone()
        } else {
            head.url.to_string()
        };
        Ok(Fetched {
            status: head.status.as_u16(),
            delay,
            body: String::from_utf8_lossy(&body).into_owned(),
            url,
            headers: head.headers,
        })
    }

    async fn exchange(&self, ctx: &Ctx, req: &ProbeRequest, log: &DialLog) -> Result<Head, Fail> {
        let mut url = Url::parse(&req.url).map_err(Fail::failed)?;
        let mut method = req.method.clone();
        let mut body = Bytes::from(req.body.clone());
        let mut headers = req.headers.clone();
        let mut hops = 0;
        loop {
            let (sender, response) = self
                .round_trip(ctx, &req.proxy, log, &url, &method, &headers, &body)
                .await?;
            let (parts, incoming) = response.into_parts();
            let next = if req.no_redirect {
                None
            } else {
                redirect_target(&url, parts.status, &parts.headers)
            };
            let Some(next) = next else {
                return Ok(Head {
                    status: parts.status,
                    headers: parts.headers,
                    url,
                    body: incoming,
                    _sender: sender,
                });
            };
            hops += 1;
            if hops > MAX_REDIRECTS {
                return Err(Fail::failed(format!(
                    "stopped after {MAX_REDIRECTS} redirects"
                )));
            }
            let keeps_body = matches!(parts.status.as_u16(), 307 | 308);
            if !keeps_body && method != Method::GET && method != Method::HEAD {
                method = Method::GET;
            }
            if !keeps_body {
                body = Bytes::new();
                headers.retain(|(name, _)| {
                    !BODY_HEADERS.contains(&name.to_ascii_lowercase().as_str())
                });
            }
            if next.host_str() != url.host_str() {
                headers.retain(|(name, _)| {
                    !PRIVATE_ON_REDIRECT.contains(&name.to_ascii_lowercase().as_str())
                });
            }
            url = next;
        }
    }

    #[expect(clippy::too_many_arguments, reason = "one hop of a request, kept flat")]
    async fn round_trip(
        &self,
        ctx: &Ctx,
        proxy: &str,
        log: &DialLog,
        url: &Url,
        method: &Method,
        headers: &[(String, String)],
        body: &Bytes,
    ) -> Result<(http1::SendRequest<Full<Bytes>>, Response<Incoming>), Fail> {
        let tls = match url.scheme() {
            "https" => true,
            "http" => false,
            other => {
                return Err(Fail::failed(format!(
                    "unsupported protocol scheme {other:?}"
                )));
            }
        };
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| Fail::failed("no Host in request URL"))?;
        let port = url
            .port_or_known_default()
            .unwrap_or(if tls { 443 } else { 80 });
        let bare_host = host.trim_matches(['[', ']']);
        let stream = self
            .dial(log, proxy, &Address::new(bare_host, port))
            .await?;
        let io: BoxStream = if tls {
            let connector = TlsConnector::new(
                TlsOptions {
                    alpn: vec!["http/1.1".to_string()],
                    ..TlsOptions::default()
                },
                self.env.trust(),
            )
            .map_err(Fail::failed)?;
            Box::new(connector.connect(stream, bare_host).await?)
        } else {
            stream
        };

        let (mut sender, connection) = http1::handshake(TokioIo::new(io))
            .await
            .map_err(Fail::failed)?;
        let bound = ctx.clone();
        self.env.tasks().spawn(async move {
            tokio::select! {
                _ = connection => {}
                _ = bound.done() => {}
            }
        });

        let target = &url[Position::BeforePath..Position::AfterQuery];
        let mut request = Request::builder()
            .method(method.clone())
            .uri(if target.is_empty() { "/" } else { target })
            .header(
                header::HOST,
                &url[Position::BeforeHost..Position::AfterPort],
            )
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Full::new(body.clone()))
            .map_err(Fail::failed)?;
        for (name, value) in headers {
            request.headers_mut().insert(
                HeaderName::from_bytes(name.as_bytes()).map_err(Fail::failed)?,
                HeaderValue::from_str(value).map_err(Fail::failed)?,
            );
        }
        let response = sender.send_request(request).await.map_err(Fail::failed)?;
        Ok((sender, response))
    }

    async fn dial(&self, log: &DialLog, proxy: &str, address: &Address) -> Result<BoxStream, Fail> {
        let index = log.track(&address.to_string());
        let pinned = (!proxy.is_empty()).then_some(proxy);
        if pinned.is_none() {
            while self.env.suspended() {
                sleep(TUNNEL_POLL).await;
            }
        }
        let dialed = self.env.dial(address, pinned).await?;
        log.settle(index, dialed.chains);
        Ok(dialed.stream)
    }
}

struct Fetched {
    status: u16,
    delay: i64,
    body: String,
    url: String,
    headers: HeaderMap,
}

fn redirect_target(from: &Url, status: StatusCode, headers: &HeaderMap) -> Option<Url> {
    if !matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = headers.get(header::LOCATION)?.to_str().ok()?;
    if location.is_empty() {
        return None;
    }
    from.join(location).ok()
}

pub(super) async fn read_body<S, E>(
    chunks: &mut S,
    buf: &mut Vec<u8>,
    max: usize,
    until: Option<&(dyn Fn(&str) -> bool + Send + Sync)>,
) where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    while buf.len() < max {
        let Some(Ok(chunk)) = chunks.next().await else {
            return;
        };
        let room = max - buf.len();
        let piece = chunk.get(..room.min(chunk.len())).unwrap_or_default();
        let from = buf.len().saturating_sub(SCAN_OVERLAP);
        buf.extend_from_slice(piece);
        if let Some(until) = until
            && until(&String::from_utf8_lossy(
                buf.get(from..).unwrap_or_default(),
            ))
        {
            return;
        }
    }
}
