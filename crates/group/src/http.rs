use std::sync::Arc;

use bytes::Bytes;
use concord_common::{Address, BoxStream};
use concord_tls::{TlsConnector, TlsOptions, TrustStore};
use http::{HeaderMap, Method};
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("{0}")]
    Url(String),
    #[error("{0}")]
    Tls(String),
    #[error("{0}")]
    Protocol(String),
}

fn protocol(err: impl std::fmt::Display) -> HttpError {
    HttpError::Protocol(err.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Target {
    pub fn parse(text: &str) -> Result<Target, HttpError> {
        let url = url::Url::parse(text).map_err(|err| HttpError::Url(err.to_string()))?;
        let tls = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return Err(HttpError::Url(format!("{text} scheme not Support"))),
        };
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| HttpError::Url(format!("{text} has no host")))?;
        let mut path = url.path().to_string();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok(Target {
            tls,
            host: host.trim_matches(['[', ']']).to_string(),
            port: url
                .port_or_known_default()
                .unwrap_or(if tls { 443 } else { 80 }),
            path,
        })
    }

    pub fn address(&self) -> Address {
        Address::new(&self.host, self.port)
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

pub struct Connection {
    sender: Sender,
    target: Target,
}

#[derive(Clone)]
pub struct TlsSettings {
    pub trust: Arc<TrustStore>,
    pub skip_cert_verify: bool,
    pub offer_h2: bool,
}

/// Runs the TLS handshake when the target is `https`, then the HTTP one. The
/// connection driver ends when the returned value is dropped.
pub async fn connect(
    io: BoxStream,
    target: &Target,
    tls: &TlsSettings,
) -> Result<Connection, HttpError> {
    if !target.tls {
        return handshake(TokioIo::new(io), target, false).await;
    }
    let alpn = if tls.offer_h2 {
        vec!["h2".to_string(), "http/1.1".to_string()]
    } else {
        vec!["http/1.1".to_string()]
    };
    let connector = TlsConnector::new(
        TlsOptions {
            alpn,
            skip_cert_verify: tls.skip_cert_verify,
            ..TlsOptions::default()
        },
        tls.trust.clone(),
    )
    .map_err(|err| HttpError::Tls(err.to_string()))?;
    let stream = connector
        .connect(io, &target.host)
        .await
        .map_err(|err| HttpError::Tls(err.to_string()))?;
    let h2 = stream.negotiated_alpn() == Some(b"h2".as_slice());
    handshake(TokioIo::new(stream), target, h2).await
}

async fn handshake<I>(io: TokioIo<I>, target: &Target, h2: bool) -> Result<Connection, HttpError>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let sender = if h2 {
        let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(protocol)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Sender::H2(sender)
    } else {
        let (sender, conn) = http1::handshake(io).await.map_err(protocol)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Sender::H1(sender)
    };
    Ok(Connection {
        sender,
        target: target.clone(),
    })
}

impl Connection {
    pub fn is_h2(&self) -> bool {
        matches!(self.sender, Sender::H2(_))
    }

    /// Redirects are not followed. A body longer than `limit` is an error.
    pub async fn send(
        &mut self,
        method: Method,
        headers: &[(String, String)],
        body: Bytes,
        limit: usize,
    ) -> Result<Response, HttpError> {
        let target = &self.target;
        let h2 = self.is_h2();
        let uri = if h2 {
            format!(
                "{}://{}{}",
                if target.tls { "https" } else { "http" },
                target.authority(),
                target.path
            )
        } else {
            target.path.clone()
        };
        let mut builder = http::Request::builder().method(method).uri(uri);
        if !h2 {
            builder = builder.header(http::header::HOST, target.authority());
        }
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder.body(Full::new(body)).map_err(protocol)?;
        let response = match &mut self.sender {
            Sender::H1(sender) => sender.send_request(request).await,
            Sender::H2(sender) => sender.send_request(request).await,
        }
        .map_err(protocol)?;
        let (parts, body) = response.into_parts();
        let body = Limited::new(body, limit)
            .collect()
            .await
            .map_err(protocol)?
            .to_bytes();
        Ok(Response {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn urls_read_like_the_url_test_wants() {
        let target = Target::parse("https://www.gstatic.com/generate_204?x=1").unwrap();
        assert_eq!(
            (target.tls, target.host.as_str(), target.port),
            (true, "www.gstatic.com", 443)
        );
        assert_eq!(target.path, "/generate_204?x=1");
        assert_eq!(
            Target::parse("http://[::1]:8080").unwrap().authority(),
            "[::1]:8080"
        );
        assert_eq!(Target::parse("http://a.b").unwrap().path, "/");
        assert!(Target::parse("ftp://a.b").is_err());
    }

    #[tokio::test]
    async fn two_head_requests_share_one_connection() {
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            for _ in 0..2 {
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = server.read(&mut buf).await.unwrap();
                    seen.extend_from_slice(&buf[..n]);
                }
                assert!(seen.starts_with(b"HEAD /generate_204 HTTP/1.1\r\n"));
                server
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let target = Target::parse("http://probe.test/generate_204").unwrap();
        let mut conn = handshake(TokioIo::new(client), &target, false)
            .await
            .unwrap();
        for _ in 0..2 {
            let response = conn
                .send(Method::HEAD, &[], Bytes::new(), 1024)
                .await
                .unwrap();
            assert_eq!(response.status, 204);
        }
    }
}
