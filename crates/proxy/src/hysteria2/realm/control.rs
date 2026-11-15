use std::io;
use std::net::SocketAddr;

use concord_common::{Address, DialCx};
use concord_tls::TlsConnector;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::punch::Metadata;
use crate::node::Egress;

const MAX_ERROR_BODY: usize = 64 * 1024;
const MAX_HEAD: usize = 10 << 20;

pub(super) struct Reply {
    pub(super) addresses: Vec<SocketAddr>,
    pub(super) metadata: Metadata,
}

pub(super) struct Control {
    url: String,
    token: String,
    tls: TlsConnector,
}

struct Target {
    https: bool,
    host: String,
    port: u16,
    authority: String,
    prefix: String,
}

fn target(url: &str) -> io::Result<Target> {
    let url = url.trim_end_matches('/');
    let uri: http::Uri = url
        .parse()
        .map_err(|err| io::Error::other(format!("parse control server URL {url:?}: {err}")))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        other => {
            return Err(io::Error::other(format!(
                "unsupported protocol scheme {:?}",
                other.unwrap_or_default()
            )));
        }
    };
    let host = uri
        .host()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| io::Error::other(format!("no Host in control server URL {url:?}")))?;
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    Ok(Target {
        https,
        host: host.to_string(),
        port,
        authority: uri
            .authority()
            .map(|authority| authority.as_str().rsplit('@').next().unwrap_or_default())
            .unwrap_or_default()
            .to_string(),
        prefix: uri.path().trim_end_matches('/').to_string(),
    })
}

/// Go's `url.PathEscape`: what may stay in one path segment unescaped.
fn path_escape(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+=:@".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn status_error(status: u16, body: &[u8]) -> io::Error {
    let parsed: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let text = |key: &str| {
        parsed
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let (code, message) = (text("error"), text("message"));
    if message.is_empty() {
        io::Error::other(format!("control {status}/{code}"))
    } else {
        io::Error::other(format!("control {status}/{code}: {message}"))
    }
}

fn decode_hex<const N: usize>(text: &str, what: &str) -> io::Result<[u8; N]> {
    let bytes =
        hex::decode(text).map_err(|err| io::Error::other(format!("decode {what}: {err}")))?;
    let length = bytes.len();
    bytes
        .try_into()
        .map_err(|_| io::Error::other(format!("invalid {what} length: {length}")))
}

fn parse_reply(body: &[u8]) -> io::Result<Reply> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|err| io::Error::other(format!("decode response: {err}")))?;
    let text = |key: &str| value.get(key).and_then(Value::as_str).unwrap_or_default();
    let mut addresses = Vec::new();
    for entry in value
        .get("addresses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let address = entry
            .as_str()
            .and_then(|text| text.parse::<SocketAddr>().ok())
            .ok_or_else(|| io::Error::other(format!("decode response: invalid address {entry}")))?;
        addresses.push(address);
    }
    let metadata = Metadata {
        nonce: decode_hex(text("nonce"), "nonce")
            .map_err(|err| io::Error::other(format!("decode connect response metadata: {err}")))?,
        key: decode_hex(text("obfs"), "obfs")
            .map_err(|err| io::Error::other(format!("decode connect response metadata: {err}")))?,
    };
    Ok(Reply {
        addresses,
        metadata,
    })
}

/// One `Connection: close` exchange: the status and the body, however the
/// server framed it.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    request: &[u8],
) -> io::Result<(u16, Vec<u8>)> {
    io.write_all(request).await?;
    io.flush().await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::other("response head too large"));
        }
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(chunk.get(..read).unwrap_or_default());
    };
    let head = String::from_utf8_lossy(buf.get(..head_end).unwrap_or_default()).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other("malformed HTTP response"))?;
    let header = |name: &str| {
        lines
            .clone()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_string())
    };
    let chunked = header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let length = header("content-length").and_then(|value| value.parse::<usize>().ok());
    let mut body = buf.get(head_end + 4..).unwrap_or_default().to_vec();
    if chunked {
        loop {
            if let Some(decoded) = dechunk(&body)? {
                return Ok((status, decoded));
            }
            let read = io.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            body.extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
    }
    while length.is_none_or(|length| body.len() < length) {
        let read = io.read(&mut chunk).await?;
        if read == 0 {
            if length.is_some() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            break;
        }
        body.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }
    if let Some(length) = length {
        body.truncate(length);
    }
    Ok((status, body))
}

/// The decoded body once the last chunk is in, `None` while more is needed.
fn dechunk(data: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        let Some(line_end) = rest.windows(2).position(|window| window == b"\r\n") else {
            return Ok(None);
        };
        let line = String::from_utf8_lossy(rest.get(..line_end).unwrap_or_default()).into_owned();
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| io::Error::other("malformed chunked response"))?;
        let start = line_end + 2;
        if size == 0 {
            return Ok(Some(out));
        }
        let Some(chunk) = rest.get(start..start + size) else {
            return Ok(None);
        };
        if rest.get(start + size..start + size + 2).is_none() {
            return Ok(None);
        }
        out.extend_from_slice(chunk);
        rest = rest.get(start + size + 2..).unwrap_or_default();
    }
}

impl Control {
    pub(super) fn new(url: String, token: String, tls: TlsConnector) -> Self {
        Control { url, token, tls }
    }

    async fn post(
        &self,
        cx: &DialCx<'_>,
        egress: &Egress,
        path: &str,
        body: &[u8],
    ) -> io::Result<(u16, Vec<u8>)> {
        let target = target(&self.url)?;
        let address = Address::new(&target.host, target.port);
        let mut request = format!(
            "POST {}{path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: concord\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
            target.prefix,
            target.authority,
            body.len()
        );
        if !self.token.is_empty() {
            request.push_str(&format!("Authorization: Bearer {}\r\n", self.token));
        }
        request.push_str("\r\n");
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body);
        if target.https {
            let mut tls = self
                .tls
                .connect_dialing(|| egress.dial(cx, &address), &target.host)
                .await?;
            exchange(&mut tls, &bytes).await
        } else {
            let mut tcp = egress.dial(cx, &address).await?;
            exchange(&mut tcp, &bytes).await
        }
    }

    /// Asks the control server to tell the registered server about us and
    /// returns where it will punch from, with the metadata it echoes back.
    pub(super) async fn connect(
        &self,
        cx: &DialCx<'_>,
        egress: &Egress,
        realm_id: &str,
        addresses: &[SocketAddr],
        metadata: &Metadata,
    ) -> io::Result<Reply> {
        let body = json!({
            "addresses": addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "nonce": hex::encode(metadata.nonce),
            "obfs": hex::encode(metadata.key),
        });
        let path = format!("/v1/{}/connect", path_escape(realm_id));
        let (status, reply) = self
            .post(cx, egress, &path, body.to_string().as_bytes())
            .await?;
        if !(200..300).contains(&status) {
            return Err(status_error(
                status,
                reply
                    .get(..MAX_ERROR_BODY.min(reply.len()))
                    .unwrap_or_default(),
            ));
        }
        parse_reply(&reply)
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "the tests talk to loopback sockets directly"
)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_into_host_port_and_prefix() {
        let plain = target("http://realm.test/").unwrap();
        assert!(!plain.https);
        assert_eq!((plain.host.as_str(), plain.port), ("realm.test", 80));
        assert_eq!(plain.prefix, "");
        let nested = target("https://realm.test:8443/api/").unwrap();
        assert!(nested.https);
        assert_eq!(
            (nested.authority.as_str(), nested.port),
            ("realm.test:8443", 8443)
        );
        assert_eq!(nested.prefix, "/api");
        let v6 = target("https://[2001:db8::1]:444").unwrap();
        assert_eq!(v6.host, "[2001:db8::1]");
        assert!(target("ftp://realm.test").is_err());
        assert!(target("realm.test").is_err());
    }

    #[test]
    fn realm_ids_are_escaped_like_go() {
        assert_eq!(path_escape("my-realm_1"), "my-realm_1");
        assert_eq!(path_escape("a/b c?"), "a%2Fb%20c%3F");
        assert_eq!(path_escape("a;b,c"), "a%3Bb%2Cc");
        assert_eq!(path_escape("é"), "%C3%A9");
    }

    #[test]
    fn errors_carry_the_servers_code_and_message() {
        let err = status_error(
            404,
            br#"{"error":"realm_not_found","message":"realm not registered"}"#,
        );
        assert_eq!(
            err.to_string(),
            "control 404/realm_not_found: realm not registered"
        );
        assert_eq!(status_error(502, b"<html>").to_string(), "control 502/");
    }

    #[test]
    fn replies_need_sixteen_and_thirty_two_bytes_of_metadata() {
        let good = json!({
            "addresses": ["203.0.113.1:5000", "[2001:db8::1]:6000"],
            "nonce": "11".repeat(16),
            "obfs": "22".repeat(32),
        });
        let reply = parse_reply(good.to_string().as_bytes()).unwrap();
        assert_eq!(reply.addresses.len(), 2);
        assert_eq!(reply.metadata.nonce, [0x11; 16]);
        assert_eq!(reply.metadata.key, [0x22; 32]);
        let short = json!({"addresses": [], "nonce": "11", "obfs": "22".repeat(32)});
        assert!(parse_reply(short.to_string().as_bytes()).is_err());
        let bad = json!({"addresses": ["nope"], "nonce": "11".repeat(16), "obfs": "22".repeat(32)});
        assert!(parse_reply(bad.to_string().as_bytes()).is_err());
    }

    #[test]
    fn chunked_bodies_wait_for_the_last_chunk() {
        assert_eq!(
            dechunk(b"5\r\nhello\r\n0\r\n\r\n").unwrap(),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n").unwrap(),
            Some(b"abcde".to_vec())
        );
        assert_eq!(dechunk(b"5\r\nhel").unwrap(), None);
        assert_eq!(dechunk(b"5\r\nhello\r\n").unwrap(), None);
        assert!(dechunk(b"zz\r\n").is_err());
    }

    async fn serve(response: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let read = conn.read(&mut buf).await.unwrap();
                seen.extend_from_slice(&buf[..read]);
                if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&seen[..end]).to_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                    if seen.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            conn.write_all(response).await.unwrap();
            conn.shutdown().await.unwrap();
            seen
        });
        (addr, task)
    }

    #[tokio::test]
    async fn exchange_reads_a_content_length_body() {
        let (addr, server) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}EXTRA").await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (status, body) = exchange(&mut conn, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert_eq!((status, body.as_slice()), (200, &b"{}"[..]));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_reads_until_close_and_chunked() {
        let (addr, server) = serve(b"HTTP/1.1 404 Not Found\r\n\r\nnope").await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (status, body) = exchange(&mut conn, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert_eq!((status, body.as_slice()), (404, &b"nope"[..]));
        server.await.unwrap();
        let (addr, server) =
            serve(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n")
                .await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (status, body) = exchange(&mut conn, b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert_eq!((status, body.as_slice()), (200, &b"hi"[..]));
        server.await.unwrap();
    }
}
