use std::io;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::head::{Headers, fill};

const MAX_LINE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    None,
    Length(u64),
    Chunked,
    /// A response body that ends when the server closes.
    Eof,
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn content_length(headers: &Headers) -> io::Result<Option<u64>> {
    let mut found: Option<u64> = None;
    for value in headers.get_all("Content-Length") {
        for part in value.split(|&byte| byte == b',') {
            let part = part.trim_ascii();
            if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
                return Err(bad("invalid Content-Length"));
            }
            let parsed: u64 = std::str::from_utf8(part)
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or_else(|| bad("invalid Content-Length"))?;
            if found.is_some_and(|previous| previous != parsed) {
                return Err(bad("conflicting Content-Length"));
            }
            found = Some(parsed);
        }
    }
    Ok(found)
}

fn is_chunked(headers: &Headers) -> io::Result<bool> {
    let mut last = None;
    for value in headers.get_all("Transfer-Encoding") {
        for part in value.split(|&byte| byte == b',') {
            let part = part.trim_ascii();
            if !part.is_empty() {
                last = Some(part.eq_ignore_ascii_case(b"chunked"));
            }
        }
    }
    match last {
        None => Ok(false),
        Some(true) => Ok(true),
        Some(false) => Err(bad("unsupported transfer encoding")),
    }
}

pub(crate) fn request_framing(headers: &Headers) -> io::Result<Framing> {
    if is_chunked(headers)? {
        return Ok(Framing::Chunked);
    }
    Ok(content_length(headers)?.map_or(Framing::None, Framing::Length))
}

pub(crate) fn response_framing(
    head_request: bool,
    status: u16,
    headers: &Headers,
) -> io::Result<Framing> {
    if head_request || (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(Framing::None);
    }
    if is_chunked(headers)? {
        return Ok(Framing::Chunked);
    }
    Ok(content_length(headers)?.map_or(Framing::Eof, Framing::Length))
}

/// The length a `Content-Length` header declares, whether or not a body follows.
pub(crate) fn declared_length(headers: &Headers) -> Option<u64> {
    content_length(headers).ok().flatten()
}

async fn copy_exact<R, W>(
    reader: &mut R,
    buf: &mut BytesMut,
    writer: &mut W,
    mut remaining: u64,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while remaining > 0 {
        if buf.is_empty() && fill(reader, buf).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let take = usize::try_from(remaining).map_or(buf.len(), |left| left.min(buf.len()));
        let chunk = buf.split_to(take);
        writer.write_all(&chunk).await?;
        remaining -= take as u64;
    }
    Ok(())
}

async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
) -> io::Result<BytesMut> {
    let mut scanned = 0;
    loop {
        if let Some(offset) = buf
            .get(scanned..)
            .and_then(|tail| tail.iter().position(|&byte| byte == b'\n'))
        {
            return Ok(buf.split_to(scanned + offset + 1));
        }
        scanned = buf.len();
        if scanned > MAX_LINE {
            return Err(bad("chunk line too long"));
        }
        if fill(reader, buf).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

fn chunk_size(line: &[u8]) -> io::Result<u64> {
    let digits = line
        .split(|&byte| byte == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(bad("invalid chunk size"));
    }
    std::str::from_utf8(digits)
        .ok()
        .and_then(|text| u64::from_str_radix(text, 16).ok())
        .ok_or_else(|| bad("invalid chunk size"))
}

/// Moves one message body from `reader` to `writer` with its framing intact:
/// chunk lines, extensions and trailers are forwarded as they came.
pub(crate) async fn copy_body<R, W>(
    framing: Framing,
    reader: &mut R,
    buf: &mut BytesMut,
    writer: &mut W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        Framing::None => Ok(()),
        Framing::Length(length) => copy_exact(reader, buf, writer, length).await,
        Framing::Eof => loop {
            if buf.is_empty() && fill(reader, buf).await? == 0 {
                return Ok(());
            }
            let chunk = buf.split();
            writer.write_all(&chunk).await?;
        },
        Framing::Chunked => loop {
            let line = read_line(reader, buf).await?;
            let size = chunk_size(&line)?;
            writer.write_all(&line).await?;
            if size == 0 {
                loop {
                    let trailer = read_line(reader, buf).await?;
                    writer.write_all(&trailer).await?;
                    if trailer.trim_ascii().is_empty() {
                        return Ok(());
                    }
                }
            }
            copy_exact(reader, buf, writer, size.saturating_add(2)).await?;
        },
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
    fn requests_without_a_length_have_no_body() {
        assert_eq!(request_framing(&headers(&[])).unwrap(), Framing::None);
        assert_eq!(
            request_framing(&headers(&[("Content-Length", "12")])).unwrap(),
            Framing::Length(12)
        );
        assert_eq!(
            request_framing(&headers(&[
                ("Content-Length", "12"),
                ("Transfer-Encoding", "gzip, chunked")
            ]))
            .unwrap(),
            Framing::Chunked
        );
    }

    #[test]
    fn conflicting_or_malformed_lengths_are_refused() {
        assert!(
            request_framing(&headers(&[
                ("Content-Length", "1"),
                ("Content-Length", "2")
            ]))
            .is_err()
        );
        assert!(request_framing(&headers(&[("Content-Length", "1, 1")])).is_ok());
        assert!(request_framing(&headers(&[("Content-Length", "-1")])).is_err());
        assert!(
            request_framing(&headers(&[("Content-Length", "99999999999999999999999")])).is_err()
        );
        assert!(request_framing(&headers(&[("Transfer-Encoding", "gzip")])).is_err());
    }

    #[test]
    fn responses_without_a_length_run_to_the_end() {
        let h = headers(&[]);
        assert_eq!(response_framing(false, 200, &h).unwrap(), Framing::Eof);
        assert_eq!(response_framing(true, 200, &h).unwrap(), Framing::None);
        assert_eq!(response_framing(false, 304, &h).unwrap(), Framing::None);
        assert_eq!(response_framing(false, 204, &h).unwrap(), Framing::None);
        assert_eq!(response_framing(false, 100, &h).unwrap(), Framing::None);
    }

    async fn relay(framing: Framing, input: &[u8]) -> (io::Result<()>, Vec<u8>, Vec<u8>) {
        let mut reader = input;
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        let result = copy_body(framing, &mut reader, &mut buf, &mut out).await;
        (result, out, buf.to_vec())
    }

    #[tokio::test]
    async fn a_length_body_stops_at_its_length_and_keeps_the_next_message() {
        let (result, out, rest) = relay(Framing::Length(5), b"helloGET /").await;
        result.unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(rest, b"GET /");
    }

    #[tokio::test]
    async fn a_short_length_body_is_an_error() {
        let (result, ..) = relay(Framing::Length(9), b"short").await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn chunks_extensions_and_trailers_pass_through_verbatim() {
        let wire = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
        let (result, out, rest) = relay(Framing::Chunked, wire).await;
        result.unwrap();
        assert_eq!(out, &wire[..wire.len() - 4]);
        assert_eq!(rest, b"NEXT");
    }

    #[tokio::test]
    async fn a_bad_chunk_size_is_an_error() {
        let (result, ..) = relay(Framing::Chunked, b"zz\r\n").await;
        assert!(result.is_err());
        let (result, ..) = relay(Framing::Chunked, b"3\r\nab").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_eof_body_copies_everything() {
        let (result, out, _) = relay(Framing::Eof, b"until close").await;
        result.unwrap();
        assert_eq!(out, b"until close");
    }
}
