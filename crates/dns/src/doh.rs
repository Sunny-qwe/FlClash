use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use concord_common::sync::lock;
use hickory_proto::op::Message;
use http::{Request, StatusCode, header};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

use crate::client::{BoxIo, Client, Params, checked, decode, encode, with_random_id, with_timeout};
use crate::dialer::{Connector, Cx};
use crate::dot::{server_name, tls_connector};

const MAX_BODY: usize = 65_535;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_IDLE: usize = 2;

pub(crate) struct DohTarget {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl DohTarget {
    pub(crate) fn host_port(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn authority(&self) -> String {
        let default = if self.secure { 443 } else { 80 };
        match (self.port == default, self.host.contains(':')) {
            (true, true) => format!("[{}]", self.host),
            (true, false) => self.host.clone(),
            (false, _) => self.host_port(),
        }
    }

    pub(crate) fn path(&self) -> &str {
        let path = self.path.split('?').next().unwrap_or_default();
        if path.is_empty() { "/" } else { path }
    }

    pub(crate) fn request(&self, query: &[u8], absolute: bool) -> io::Result<Request<Body>> {
        let path = format!("{}?dns={}", self.path(), URL_SAFE_NO_PAD.encode(query));
        let builder = Request::builder()
            .method(http::Method::GET)
            .header(header::ACCEPT, "application/dns-message");
        let builder = if absolute {
            builder.uri(format!("{}://{}{path}", self.scheme(), self.authority()))
        } else {
            builder.uri(path).header(header::HOST, self.authority())
        };
        builder
            .body(Empty::new())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    }

    fn scheme(&self) -> &'static str {
        if self.secure { "https" } else { "http" }
    }
}

pub(crate) type Body = Empty<Bytes>;

/// `https://` and `http://` upstreams over HTTP/2, or HTTP/1.1 when the server
/// does not negotiate h2. The connection is dialed through the `Connector`, so
/// it is protected and can go through a proxy.
pub(crate) struct DohClient {
    target: DohTarget,
    connector: Arc<Connector>,
    tls: Option<tokio_rustls::TlsConnector>,
    h2: Mutex<Option<http2::SendRequest<Body>>>,
    h1: Mutex<Vec<http1::SendRequest<Body>>>,
}

enum Sender {
    H2(http2::SendRequest<Body>),
    H1(http1::SendRequest<Body>),
}

impl DohClient {
    pub(crate) fn new(
        target: DohTarget,
        connector: Arc<Connector>,
        params: &Params<'_>,
    ) -> io::Result<Self> {
        let tls = if target.secure {
            Some(tls_connector(&connector, params, &["h2", "http/1.1"])?)
        } else {
            None
        };
        Ok(DohClient {
            target,
            connector,
            tls,
            h2: Mutex::new(None),
            h1: Mutex::new(Vec::new()),
        })
    }

    fn cached(&self) -> Option<Sender> {
        {
            let mut slot = lock(&self.h2);
            match slot.as_ref() {
                Some(sender) if !sender.is_closed() => return Some(Sender::H2(sender.clone())),
                Some(_) => *slot = None,
                None => {}
            }
        }
        let mut idle = lock(&self.h1);
        while let Some(sender) = idle.pop() {
            if !sender.is_closed() {
                return Some(Sender::H1(sender));
            }
        }
        None
    }

    async fn dial(&self, cx: Cx) -> io::Result<Sender> {
        let dial = async {
            let tcp = self
                .connector
                .tcp(&self.target.host, self.target.port, cx)
                .await?;
            let Some(tls) = &self.tls else {
                return Ok((Box::new(tcp) as BoxIo, false));
            };
            let stream = tls.connect(server_name(&self.target.host)?, tcp).await?;
            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            Ok::<_, io::Error>((Box::new(stream) as BoxIo, h2))
        };
        let (io, h2) = tokio::time::timeout(DIAL_TIMEOUT, dial)
            .await
            .map_err(|_| crate::client::timed_out())??;
        if h2 {
            let (sender, conn) = http2::Builder::new(TokioExecutor::new())
                .timer(TokioTimer::new())
                .keep_alive_interval(PING_INTERVAL)
                .keep_alive_timeout(PING_TIMEOUT)
                .handshake(TokioIo::new(io))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            {
                let mut slot = lock(&self.h2);
                *slot = Some(sender.clone());
            }
            Ok(Sender::H2(sender))
        } else {
            let (sender, conn) = http1::handshake(TokioIo::new(io))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            Ok(Sender::H1(sender))
        }
    }

    fn request(&self, query: &[u8], h2: bool) -> io::Result<Request<Body>> {
        self.target.request(query, h2)
    }

    async fn round_trip(&self, sender: Sender, query: &[u8]) -> io::Result<Message> {
        let (response, keep) = match sender {
            Sender::H2(mut sender) => {
                let response = sender
                    .send_request(self.request(query, true)?)
                    .await
                    .map_err(io::Error::other)?;
                (response, None)
            }
            Sender::H1(mut sender) => {
                let response = sender
                    .send_request(self.request(query, false)?)
                    .await
                    .map_err(io::Error::other)?;
                (response, Some(sender))
            }
        };
        let message = self.read(response).await?;
        if let Some(sender) = keep {
            let mut idle = lock(&self.h1);
            if !sender.is_closed() && idle.len() < MAX_IDLE {
                idle.push(sender);
            }
        }
        Ok(message)
    }

    async fn read(&self, response: http::Response<Incoming>) -> io::Result<Message> {
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?
            .to_bytes();
        if status != StatusCode::OK {
            return Err(io::Error::other(format!(
                "expected status 200, got {} from {}://{}{}",
                status.as_u16(),
                self.target.scheme(),
                self.target.host_port(),
                self.target.path()
            )));
        }
        decode(&body)
    }
}

#[async_trait]
impl Client for DohClient {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let original = req.metadata.id;
        let mut query = with_random_id(req);
        query.metadata.id = 0;
        let bytes = encode(&query)?;
        with_timeout(async {
            let mut sender = self.cached();
            let mut attempts = 0;
            loop {
                let (current, reused) = match sender.take() {
                    Some(current) => (current, true),
                    None => (self.dial(cx).await?, false),
                };
                let answer = self
                    .round_trip(current, &bytes)
                    .await
                    .and_then(|resp| checked(&query, resp));
                match answer {
                    Ok(mut resp) => {
                        resp.metadata.id = original;
                        return Ok(resp);
                    }
                    Err(err) if reused && attempts < 2 => {
                        attempts += 1;
                        self.reset();
                        tracing::debug!("re-creating the DoH connection after {err}");
                    }
                    Err(err) => {
                        self.reset();
                        return Err(err);
                    }
                }
            }
        })
        .await
    }

    fn address(&self) -> String {
        format!(
            "{}://{}{}",
            self.target.scheme(),
            self.target.host_port(),
            self.target.path()
        )
    }

    fn reset(&self) {
        {
            let mut slot = lock(&self.h2);
            *slot = None;
        }
        {
            let mut idle = lock(&self.h1);
            idle.clear();
        }
    }
}
