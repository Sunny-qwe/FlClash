use std::collections::HashMap;
use std::future::pending;
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::BytesMut;
use concord_common::{Address, InboundKind};
use tokio::io::{
    AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
    copy_bidirectional,
};

use super::body::{Framing, copy_body, declared_length, request_framing, response_framing};
use super::head::{
    Headers, RequestHead, fill, read_response_head, strip_hop_by_hop, strip_proxy_headers,
};
use super::target::{Target, host_header, parse_absolute, parse_authority};
use super::{Next, Session, connection_headers, status_text};
use crate::ctx::{Client, ListenCtx, Peer, dst_address};

const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_IDLE: usize = 100;

pub(super) struct Upstream {
    rd: ReadHalf<DuplexStream>,
    wr: WriteHalf<DuplexStream>,
    buf: BytesMut,
    last_used: Instant,
}

impl Upstream {
    /// An idle flow whose far end has gone away, or sent something unasked,
    /// reads ready here without blocking.
    fn is_stale(&mut self) -> bool {
        if self.last_used.elapsed() > IDLE_TIMEOUT || !self.buf.is_empty() {
            return true;
        }
        let mut cx = Context::from_waker(Waker::noop());
        let mut probe = [0u8; 1];
        let mut read_buf = ReadBuf::new(&mut probe);
        !matches!(
            Pin::new(&mut self.rd).poll_read(&mut cx, &mut read_buf),
            Poll::Pending
        )
    }
}

/// The idle flows one client connection keeps toward its origins, one per host.
pub(super) struct Upstreams {
    ctx: Arc<ListenCtx>,
    peer: Peer,
    idle: HashMap<Address, Upstream>,
}

impl Upstreams {
    pub(super) fn new(ctx: Arc<ListenCtx>, peer: Peer) -> Self {
        Upstreams {
            ctx,
            peer,
            idle: HashMap::new(),
        }
    }

    pub(super) fn clear(&mut self) {
        self.idle.clear();
    }

    fn take(&mut self, dst: &Address) -> Option<Upstream> {
        let mut upstream = self.idle.remove(dst)?;
        (!upstream.is_stale()).then_some(upstream)
    }

    fn put(&mut self, dst: Address, mut upstream: Upstream) {
        upstream.last_used = Instant::now();
        if self.idle.len() >= MAX_IDLE
            && let Some(oldest) = self
                .idle
                .iter()
                .min_by_key(|(_, candidate)| candidate.last_used)
                .map(|(key, _)| key.clone())
        {
            self.idle.remove(&oldest);
        }
        self.idle.insert(dst, upstream);
    }

    fn dial(&self, dst: &Address, client: &Client) -> Upstream {
        let (left, right) = tokio::io::duplex(concord_common::stream_buffer::COPY_BUFFER_SIZE);
        let meta = self
            .ctx
            .tcp_meta(InboundKind::Http, &self.peer, dst.clone(), client.clone());
        self.ctx.hand_off(meta, Box::new(right));
        let (rd, wr) = tokio::io::split(left);
        Upstream {
            rd,
            wr,
            buf: BytesMut::new(),
            last_used: Instant::now(),
        }
    }
}

enum Failure {
    NoResponse,
    BadResponse,
    Broken,
}

struct Outcome {
    upstream_reusable: bool,
    client_close: bool,
}

fn head_bytes(minor: u8, status: u16, reason: &str, headers: &Headers) -> Vec<u8> {
    let reason = if reason.is_empty() {
        status_text(status)
    } else {
        reason
    };
    let mut out = format!("HTTP/1.{minor} {status} {reason}\r\n").into_bytes();
    headers.write_into(&mut out);
    out
}

fn request_bytes(
    method: &str,
    path: &str,
    host: &str,
    headers: &Headers,
    framing: Framing,
) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
    headers.write_into(&mut out);
    if framing == Framing::Chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// A body-bearing request's headers keep `Content-Length` unless the body is
/// chunked, which wins.
fn outgoing_headers(mut headers: Headers, framing: Framing, hop_by_hop: bool) -> Headers {
    headers.remove("Host");
    if framing == Framing::Chunked {
        headers.remove("Content-Length");
    }
    if hop_by_hop {
        strip_hop_by_hop(&mut headers);
    } else {
        strip_proxy_headers(&mut headers);
    }
    headers
}

async fn watch_eof<R: AsyncRead + Unpin>(reader: &mut R, buf: &mut BytesMut) {
    if buf.is_empty() && matches!(fill(reader, buf).await, Ok(0) | Err(_)) {
        return;
    }
    pending::<()>().await;
}

async fn relay_response<R, W>(
    upstream: &mut R,
    ubuf: &mut BytesMut,
    client: &mut W,
    head_request: bool,
    keep_alive: bool,
) -> Result<Outcome, Failure>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let head = loop {
        let head = match read_response_head(upstream, ubuf).await {
            Ok(Some(head)) => head,
            Ok(None) => return Err(Failure::NoResponse),
            Err(err) if err.kind() == io::ErrorKind::InvalidData => {
                return Err(Failure::BadResponse);
            }
            Err(_) => return Err(Failure::NoResponse),
        };
        if (100..200).contains(&head.status) && head.status != 101 {
            let mut interim = head_bytes(head.minor, head.status, &head.reason, &head.headers);
            interim.extend_from_slice(b"\r\n");
            client
                .write_all(&interim)
                .await
                .map_err(|_| Failure::Broken)?;
            continue;
        }
        break head;
    };

    let switching = head.status == 101;
    let framing = if switching {
        Framing::None
    } else {
        response_framing(head_request, head.status, &head.headers)
            .map_err(|_| Failure::BadResponse)?
    };
    let upstream_close = switching
        || head.headers.has_token("Connection", "close")
        || (head.minor == 0 && !head.headers.has_token("Connection", "keep-alive"));
    let declared = declared_length(&head.headers);

    let mut headers = head.headers;
    strip_hop_by_hop(&mut headers);
    let mut close = upstream_close || !keep_alive;
    if keep_alive && declared.is_some_and(|length| length > 0) {
        close = false;
    }
    if framing == Framing::Eof {
        close = true;
    }
    let mut out = head_bytes(head.minor, head.status, &head.reason, &headers);
    if framing == Framing::Chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    connection_headers(&mut out, close);
    out.extend_from_slice(b"\r\n");
    client.write_all(&out).await.map_err(|_| Failure::Broken)?;
    copy_body(framing, upstream, ubuf, client)
        .await
        .map_err(|_| Failure::Broken)?;
    Ok(Outcome {
        upstream_reusable: !upstream_close && framing != Framing::Eof,
        client_close: close,
    })
}

/// Sends one request and relays its response. The request body and the
/// response run together because a client that sent `Expect: 100-continue`
/// holds its body until the origin answers.
async fn exchange<R, W>(
    client: (&mut R, &mut BytesMut, &mut W),
    upstream: &mut Upstream,
    request: &[u8],
    framing: Framing,
    head_request: bool,
    keep_alive: bool,
) -> Result<Outcome, Failure>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (crd, cbuf, cwr) = client;
    let Upstream {
        rd: urd,
        wr: uwr,
        buf: ubuf,
        ..
    } = upstream;
    if uwr.write_all(request).await.is_err() {
        return Err(Failure::NoResponse);
    }
    let mut response = pin!(relay_response(urd, ubuf, cwr, head_request, keep_alive));
    let mut body = (framing != Framing::None).then(|| Box::pin(copy_body(framing, crd, cbuf, uwr)));
    if let Some(sending) = body.as_mut() {
        tokio::select! {
            sent = sending.as_mut() => {
                if sent.is_err() {
                    return Err(Failure::Broken);
                }
            }
            done = response.as_mut() => {
                drop(body);
                return done.map(|_| Outcome { upstream_reusable: false, client_close: true });
            }
        }
    }
    drop(body);
    tokio::select! {
        done = response.as_mut() => done,
        () = watch_eof(crd, cbuf) => Err(Failure::Broken),
    }
}

/// Go's `http.Client` sends a URL's userinfo as basic credentials unless the request
/// already carries an `Authorization` header.
fn with_url_credentials(mut headers: Headers, target: &Target) -> Headers {
    if let Some(userinfo) = &target.userinfo
        && headers.get("Authorization").is_none()
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(userinfo);
        headers.push("Authorization", format!("Basic {encoded}").as_bytes());
    }
    headers
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
    pub(super) async fn forward(
        &mut self,
        head: RequestHead,
        keep_alive: bool,
    ) -> io::Result<Next> {
        let Some(target) = parse_absolute(&head.target) else {
            return self.reply(head.minor, 400, keep_alive).await;
        };
        if target.scheme != "http" {
            return self.reply(head.minor, 502, keep_alive).await;
        }
        let framing = request_framing(&head.headers)?;
        let dst = dst_address(&target.host, target.port_or_default());
        let head_request = head.method.eq_ignore_ascii_case("HEAD");
        let request = request_bytes(
            &head.method,
            &target.path,
            &target.host_header(),
            &with_url_credentials(outgoing_headers(head.headers, framing, true), &target),
            framing,
        );

        let mut retry = true;
        loop {
            let (mut upstream, reused) = match self.upstreams.take(&dst) {
                Some(upstream) => (upstream, true),
                None => (self.upstreams.dial(&dst, &self.client), false),
            };
            let result = exchange(
                (&mut self.rd, &mut self.rbuf, &mut self.wr),
                &mut upstream,
                &request,
                framing,
                head_request,
                keep_alive,
            )
            .await;
            match result {
                Ok(outcome) => {
                    if outcome.upstream_reusable {
                        self.upstreams.put(dst, upstream);
                    }
                    return Ok(if outcome.client_close {
                        Next::Close
                    } else {
                        Next::Continue
                    });
                }
                Err(Failure::NoResponse) if reused && retry && framing == Framing::None => {
                    retry = false;
                }
                Err(Failure::NoResponse | Failure::BadResponse) => {
                    let keep = keep_alive && framing == Framing::None;
                    return self.reply(head.minor, 502, keep).await;
                }
                Err(Failure::Broken) => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }

    /// Everything but the `Proxy-*` headers goes through, since the origin has
    /// to see `Connection: Upgrade`. The connection is closed unless the
    /// origin switches protocols.
    pub(super) async fn upgrade(self, head: RequestHead) -> io::Result<()> {
        let Session {
            mut rd,
            mut wr,
            mut rbuf,
            upstreams,
            client,
        } = self;
        let (host, port, path) = match parse_absolute(&head.target) {
            Some(Target {
                host, port, path, ..
            }) => (host, port, path),
            None => {
                let value = head.headers.get("Host").unwrap_or_default();
                let (host, port) = parse_authority(&String::from_utf8_lossy(value))
                    .ok_or(io::ErrorKind::InvalidInput)?;
                (host, port, head.target.clone())
            }
        };
        let framing = request_framing(&head.headers)?;
        let request = request_bytes(
            &head.method,
            &path,
            &host_header(&host, port),
            &outgoing_headers(head.headers, framing, false),
            framing,
        );
        let dst = dst_address(&host, port.unwrap_or(80));
        let mut upstream = upstreams.dial(&dst, &client);
        upstream.wr.write_all(&request).await?;
        copy_body(framing, &mut rd, &mut rbuf, &mut upstream.wr).await?;

        let response = read_response_head(&mut upstream.rd, &mut upstream.buf)
            .await?
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let switching = response.status == 101;
        let body = if switching {
            Framing::None
        } else {
            response_framing(
                head.method.eq_ignore_ascii_case("HEAD"),
                response.status,
                &response.headers,
            )?
        };
        let mut headers = response.headers;
        strip_proxy_headers(&mut headers);
        let mut out = head_bytes(response.minor, response.status, &response.reason, &headers);
        out.extend_from_slice(b"\r\n");
        wr.write_all(&out).await?;
        copy_body(body, &mut upstream.rd, &mut upstream.buf, &mut wr).await?;
        if !switching {
            return Ok(());
        }

        upstream.wr.write_all(&rbuf.split()).await?;
        wr.write_all(&upstream.buf.split()).await?;
        let mut client = rd.unsplit(wr);
        let mut origin = upstream.rd.unsplit(upstream.wr);
        copy_bidirectional(&mut client, &mut origin).await?;
        Ok(())
    }

    async fn reply(&mut self, minor: u8, status: u16, keep_alive: bool) -> io::Result<Next> {
        self.wr
            .write_all(&super::status_response(minor, status, keep_alive))
            .await?;
        Ok(if keep_alive {
            Next::Continue
        } else {
            Next::Close
        })
    }
}
