use std::io;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_REQUEST_HEAD: usize = 1 << 20;
const MAX_RESPONSE_HEAD: usize = 10 << 20;

fn header_lines(buf: &[u8]) -> usize {
    buf.iter().filter(|&&byte| byte == b'\n').count()
}

/// Whether the blank line ending a head, CRLF or bare LF as httparse accepts, lies at or after
/// `from`, so a head is parsed once in full rather than again on every read.
fn head_complete(buf: &[u8], from: usize) -> bool {
    let tail = buf.get(from.saturating_sub(2)..).unwrap_or_default();
    tail.windows(2).any(|pair| pair == b"\n\n") || tail.windows(3).any(|triple| triple == b"\n\r\n")
}

#[derive(Debug, Default, Clone)]
pub(crate) struct Headers(Vec<(String, Vec<u8>)>);

impl Headers {
    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.0
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
    }

    pub(crate) fn push(&mut self, name: &str, value: &[u8]) {
        self.0.push((name.to_owned(), value.to_vec()));
    }

    pub(crate) fn get(&self, name: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
    }

    pub(crate) fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> {
        self.0
            .iter()
            .filter(move |(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
    }

    pub(crate) fn remove(&mut self, name: &str) {
        self.0
            .retain(|(candidate, _)| !candidate.eq_ignore_ascii_case(name));
    }

    /// Whether any comma-separated element of any `name` header equals `token`.
    pub(crate) fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name).any(|value| {
            value
                .split(|&byte| byte == b',')
                .any(|part| part.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
        })
    }

    pub(crate) fn write_into(&self, out: &mut Vec<u8>) {
        for (name, value) in &self.0 {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
    }

    fn from_parsed(parsed: &[httparse::Header<'_>]) -> Self {
        Headers(
            parsed
                .iter()
                .map(|header| (header.name.to_owned(), header.value.to_vec()))
                .collect(),
        )
    }
}

#[derive(Debug)]
pub(crate) struct RequestHead {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) minor: u8,
    pub(crate) headers: Headers,
}

#[derive(Debug)]
pub(crate) struct ResponseHead {
    pub(crate) minor: u8,
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Headers,
}

pub(crate) async fn fill<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
) -> io::Result<usize> {
    buf.reserve(16 * 1024);
    reader.read_buf(buf).await
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `Ok(None)` is a clean end of stream before the first byte of a message.
pub(crate) async fn read_request_head<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
) -> io::Result<Option<RequestHead>> {
    let mut scanned = 0;
    loop {
        if !buf.is_empty() {
            if head_complete(buf, scanned) {
                let mut slots = vec![httparse::EMPTY_HEADER; header_lines(buf)];
                let mut request = httparse::Request::new(&mut slots);
                match request.parse(buf) {
                    Ok(httparse::Status::Complete(used)) => {
                        let head = RequestHead {
                            method: request.method.unwrap_or_default().to_owned(),
                            target: request.path.unwrap_or_default().to_owned(),
                            minor: request.version.unwrap_or(1),
                            headers: Headers::from_parsed(request.headers),
                        };
                        buf.advance(used);
                        return Ok(Some(head));
                    }
                    Ok(httparse::Status::Partial) => {}
                    Err(_) => return Err(bad("malformed request head")),
                }
            } else if let Err(err) = httparse::Request::new(&mut []).parse(buf)
                && err != httparse::Error::TooManyHeaders
            {
                return Err(bad("malformed request head"));
            }
            scanned = buf.len();
            if buf.len() > MAX_REQUEST_HEAD {
                return Err(bad("request head too large"));
            }
        }
        if fill(reader, buf).await? == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
    }
}

pub(crate) async fn read_response_head<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
) -> io::Result<Option<ResponseHead>> {
    let mut scanned = 0;
    loop {
        if !buf.is_empty() {
            if head_complete(buf, scanned) {
                let mut slots = vec![httparse::EMPTY_HEADER; header_lines(buf)];
                let mut response = httparse::Response::new(&mut slots);
                match response.parse(buf) {
                    Ok(httparse::Status::Complete(used)) => {
                        let head = ResponseHead {
                            minor: response.version.unwrap_or(1),
                            status: response.code.unwrap_or(502),
                            reason: response.reason.unwrap_or_default().to_owned(),
                            headers: Headers::from_parsed(response.headers),
                        };
                        buf.advance(used);
                        return Ok(Some(head));
                    }
                    Ok(httparse::Status::Partial) => {}
                    Err(_) => return Err(bad("malformed response head")),
                }
            } else if let Err(err) = httparse::Response::new(&mut []).parse(buf)
                && err != httparse::Error::TooManyHeaders
            {
                return Err(bad("malformed response head"));
            }
            scanned = buf.len();
            if buf.len() > MAX_RESPONSE_HEAD {
                return Err(bad("response head too large"));
            }
        }
        if fill(reader, buf).await? == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::ErrorKind::UnexpectedEof.into())
            };
        }
    }
}

/// `listener/http/utils.go`: the three `Proxy-*` headers go, and so does what
/// RFC 2616 names hop-by-hop plus anything `Connection` lists.
pub(crate) fn strip_proxy_headers(headers: &mut Headers) {
    headers.remove("Proxy-Connection");
    headers.remove("Proxy-Authenticate");
    headers.remove("Proxy-Authorization");
}

pub(crate) fn strip_hop_by_hop(headers: &mut Headers) {
    strip_proxy_headers(headers);
    for name in [
        "TE",
        "Trailers",
        "Transfer-Encoding",
        "Upgrade",
        "Keep-Alive",
    ] {
        headers.remove(name);
    }
    let named: Vec<String> = headers
        .get_all("Connection")
        .flat_map(|value| value.split(|&byte| byte == b','))
        .map(|part| String::from_utf8_lossy(part.trim_ascii()).into_owned())
        .collect();
    headers.remove("Connection");
    for name in named.iter().filter(|name| !name.is_empty()) {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Headers {
        let mut headers = Headers::default();
        for (name, value) in pairs {
            headers.push(name, value.as_bytes());
        }
        headers
    }

    #[test]
    fn hop_by_hop_headers_go_with_the_ones_connection_names() {
        let mut h = headers(&[
            ("Host", "a"),
            ("Proxy-Connection", "keep-alive"),
            ("Proxy-Authorization", "Basic x"),
            ("Connection", "close, X-Private"),
            ("X-Private", "1"),
            ("TE", "trailers"),
            ("Upgrade", "websocket"),
            ("Accept", "*/*"),
        ]);
        strip_hop_by_hop(&mut h);
        let names: Vec<&str> = h.iter().map(|(name, _)| name).collect();
        assert_eq!(names, ["Host", "Accept"]);
    }

    #[test]
    fn tokens_match_case_insensitively_across_values() {
        let h = headers(&[("Connection", "keep-alive"), ("connection", " Upgrade ")]);
        assert!(h.has_token("Connection", "upgrade"));
        assert!(!h.has_token("Connection", "close"));
    }

    #[tokio::test]
    async fn a_head_split_across_reads_parses_and_leaves_the_rest() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(b"GET http://a/ HTT").await.unwrap();
            tokio::task::yield_now().await;
            client
                .write_all(b"P/1.1\r\nHost: a\r\n\r\nrest")
                .await
                .unwrap();
        });
        let mut buf = BytesMut::new();
        let head = read_request_head(&mut server, &mut buf)
            .await
            .unwrap()
            .unwrap();
        writer.await.unwrap();
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "http://a/");
        assert_eq!(head.minor, 1);
        assert_eq!(head.headers.get("host"), Some(&b"a"[..]));
        fill(&mut server, &mut buf).await.ok();
        assert_eq!(&buf[..], b"rest");
    }

    #[tokio::test]
    async fn a_head_with_hundreds_of_headers_parses() {
        let mut text = b"GET http://a/ HTTP/1.1\r\nHost: a\r\n".to_vec();
        for n in 0..300 {
            text.extend_from_slice(format!("X-{n}: v\r\n").as_bytes());
        }
        text.extend_from_slice(b"\r\n");
        let mut buf = BytesMut::new();
        let head = read_request_head(&mut text.as_slice(), &mut buf)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.headers.get("x-299"), Some(&b"v"[..]));
    }

    #[tokio::test]
    async fn garbage_is_an_error_and_a_clean_close_is_none() {
        let mut buf = BytesMut::new();
        let mut garbage: &[u8] = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n";
        assert!(read_request_head(&mut garbage, &mut buf).await.is_err());
        let mut buf = BytesMut::new();
        let mut empty: &[u8] = b"";
        assert!(
            read_request_head(&mut empty, &mut buf)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn heads_are_held_to_go_server_limit() {
        let filler = "X-Filler: ".to_string() + &"a".repeat(1000) + "\r\n";
        let mut text = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
        for _ in 0..100 {
            text.extend_from_slice(filler.as_bytes());
        }
        text.extend_from_slice(b"\r\n");
        let mut buf = BytesMut::new();
        let head = read_request_head(&mut text.as_slice(), &mut buf)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head.headers.iter().count(), 101);

        let mut oversized = b"GET / HTTP/1.1\r\n".to_vec();
        while oversized.len() <= MAX_REQUEST_HEAD {
            oversized.extend_from_slice(filler.as_bytes());
        }
        let mut buf = BytesMut::new();
        let err = read_request_head(&mut oversized.as_slice(), &mut buf)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
