use std::net::IpAddr;

use super::dispatcher::DataSniffer;
use super::error::SniffError;
use super::hpack::Decoder;

const METHODS: [&[u8]; 9] = [
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"CONNECT", b"PATCH", b"TRACE",
];

pub(super) const H2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub(super) const H2_FRAME_HEADER_LEN: usize = 9;
pub(super) const H2_DEFAULT_MAX_FRAME_SIZE: usize = 1 << 14;

pub(super) const H2_FRAME_HEADERS: u8 = 0x1;
pub(super) const H2_FRAME_SETTINGS: u8 = 0x4;
pub(super) const H2_FRAME_CONTINUATION: u8 = 0x9;
pub(super) const H2_FLAG_ACK: u8 = 0x1;
pub(super) const H2_FLAG_END_HEADERS: u8 = 0x4;
pub(super) const H2_FLAG_PADDED: u8 = 0x8;
pub(super) const H2_FLAG_PRIORITY: u8 = 0x20;

const HEADER_TABLE_SIZE: usize = 4096;

pub(super) struct HttpSniffer;

impl DataSniffer for HttpSniffer {
    fn sniff(&self, data: &[u8]) -> Result<String, SniffError> {
        if data.len() < H2_CLIENT_PREFACE.len() {
            if H2_CLIENT_PREFACE.starts_with(data) {
                // One byte at a time lets a mismatch fall back to HTTP/1 early.
                return Err(SniffError::NeedAtLeast(data.len() + 1));
            }
            return sniff_http1(data);
        }
        if data.starts_with(H2_CLIENT_PREFACE) {
            return sniff_http2(data);
        }
        sniff_http1(data)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() == 1 {
        let byte = needle.first()?;
        return haystack.iter().position(|b| b == byte);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn cut<'a>(data: &'a [u8], sep: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let at = find(data, sep)?;
    Some((
        data.get(..at)?,
        data.get(at + sep.len()..).unwrap_or_default(),
    ))
}

fn is_method(method: &[u8]) -> bool {
    METHODS.iter().any(|m| m.eq_ignore_ascii_case(method))
}

fn is_method_prefix(prefix: &[u8]) -> bool {
    METHODS.iter().any(|method| {
        method
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    })
}

fn leading_char(data: &[u8]) -> Option<(char, usize)> {
    let head = data.get(..data.len().min(4))?;
    let valid = match std::str::from_utf8(head) {
        Ok(text) => text,
        Err(err) => std::str::from_utf8(head.get(..err.valid_up_to())?).ok()?,
    };
    valid.chars().next().map(|c| (c, c.len_utf8()))
}

fn trailing_char(data: &[u8]) -> Option<(char, usize)> {
    (1..=data.len().min(4)).find_map(|n| {
        let text = std::str::from_utf8(data.get(data.len() - n..)?).ok()?;
        let mut chars = text.chars();
        let c = chars.next()?;
        chars.next().is_none().then_some((c, n))
    })
}

/// Go's `bytes.TrimSpace`: Unicode white space, with bytes that are not valid UTF-8 left alone.
fn trim_space(mut data: &[u8]) -> &[u8] {
    while let Some((c, n)) = leading_char(data)
        && c.is_whitespace()
    {
        data = data.get(n..).unwrap_or_default();
    }
    while let Some((c, n)) = trailing_char(data)
        && c.is_whitespace()
    {
        data = data.get(..data.len() - n).unwrap_or_default();
    }
    data
}

pub(super) fn sniff_http1(b: &[u8]) -> Result<String, SniffError> {
    let Some((method, _)) = cut(b, b" ") else {
        if is_method_prefix(b) {
            return Err(SniffError::NeedAtLeast(b.len() + 1));
        }
        return Err(SniffError::NotHttp);
    };
    if !is_method(method) {
        return Err(SniffError::NotHttp);
    }

    let Some((request_line, _)) = cut(b, b"\r\n") else {
        return Err(SniffError::NeedAtLeast(b.len() + 1));
    };
    if request_line.len() < 14 {
        return Err(SniffError::NoClue);
    }

    let Some((_, after_method)) = cut(request_line, b" ") else {
        return Err(SniffError::NoClue);
    };
    let Some((mut uri, _)) = cut(after_method, b" ") else {
        return Err(SniffError::NoClue);
    };
    match uri.first() {
        None => Err(SniffError::NoClue),
        Some(b'/' | b'*') => parse_header_host_h1(b),
        Some(_) => {
            if let Some((_, after_scheme)) = cut(uri, b"://") {
                uri = after_scheme;
            }
            if let Some(end) = uri.iter().position(|b| matches!(b, b'/' | b'?' | b'#')) {
                uri = uri.get(..end).unwrap_or_default();
            }
            if let Some((_, after_at)) = cut(uri, b"@") {
                uri = after_at;
            }
            parse_host(uri).or_else(|_| parse_header_host_h1(b))
        }
    }
}

fn parse_header_host_h1(b: &[u8]) -> Result<String, SniffError> {
    let mut rest = b;
    loop {
        let Some((line, tail)) = cut(rest, b"\r\n") else {
            return Err(SniffError::NeedAtLeast(b.len() + 1));
        };
        if line.is_empty() {
            return Err(SniffError::NoClue);
        }
        rest = tail;
        let Some((key, value)) = cut(line, b":") else {
            continue;
        };
        if !key.eq_ignore_ascii_case(b"host") {
            continue;
        }
        // A complete Host field is enough, no need to wait for the header end.
        return parse_host(trim_space(value));
    }
}

pub(super) fn sniff_http2(input: &[u8]) -> Result<String, SniffError> {
    let total = input.len();
    let mut b = input.get(H2_CLIENT_PREFACE.len()..).unwrap_or_default();

    let mut authority: Vec<u8> = Vec::new();
    let mut host: Vec<u8> = Vec::new();
    let mut header_stream_id = 0u32;
    let mut decoder = Decoder::new(HEADER_TABLE_SIZE);

    loop {
        let Some((header, rest)) = b.split_first_chunk::<H2_FRAME_HEADER_LEN>() else {
            return Err(SniffError::NeedAtLeast(
                total - b.len() + H2_FRAME_HEADER_LEN,
            ));
        };
        let [l0, l1, l2, frame_type, flags, s0, s1, s2, s3] = *header;
        let length = usize::from(l0) << 16 | usize::from(l1) << 8 | usize::from(l2);
        let stream_id = u32::from_be_bytes([s0, s1, s2, s3]) & 0x7fff_ffff;

        b = rest;
        let payload_offset = total - b.len();
        // The preface must be followed by a non-ACK SETTINGS frame.
        if payload_offset == H2_CLIENT_PREFACE.len() + H2_FRAME_HEADER_LEN
            && (frame_type != H2_FRAME_SETTINGS || flags & H2_FLAG_ACK != 0)
        {
            return Err(SniffError::NoClue);
        }
        if length > H2_DEFAULT_MAX_FRAME_SIZE {
            // No server SETTINGS can arrive yet, so the default size applies.
            return Err(SniffError::NoClue);
        }
        if frame_type == H2_FRAME_SETTINGS {
            let ack = flags & H2_FLAG_ACK != 0;
            if stream_id != 0 || ack && length != 0 || !ack && length % 6 != 0 {
                return Err(SniffError::NoClue);
            }
        }
        if header_stream_id == 0 {
            if frame_type == H2_FRAME_CONTINUATION {
                return Err(SniffError::NoClue);
            }
            if frame_type == H2_FRAME_HEADERS && stream_id == 0 {
                return Err(SniffError::NoClue);
            }
        } else if frame_type != H2_FRAME_CONTINUATION || stream_id != header_stream_id {
            return Err(SniffError::NoClue);
        }

        if header_stream_id == 0 {
            if frame_type != H2_FRAME_HEADERS {
                let Some(after) = b.get(length..) else {
                    return Err(SniffError::NeedAtLeast(payload_offset + length));
                };
                b = after;
                continue;
            }
            header_stream_id = stream_id;
        }

        let mut fragment_start = 0usize;
        let mut fragment_end = length;
        if frame_type == H2_FRAME_HEADERS {
            if flags & H2_FLAG_PADDED != 0 {
                if length == 0 {
                    return Err(SniffError::NoClue);
                }
                let Some(&pad) = b.first() else {
                    return Err(SniffError::NeedAtLeast(payload_offset + 1));
                };
                let pad_len = usize::from(pad);
                if pad_len >= length {
                    return Err(SniffError::NoClue);
                }
                fragment_start += 1;
                fragment_end -= pad_len;
            }
            if flags & H2_FLAG_PRIORITY != 0 {
                if fragment_end - fragment_start < 5 {
                    return Err(SniffError::NoClue);
                }
                fragment_start += 5;
            }
        }

        let available_end = b.len().min(fragment_end);
        if available_end > fragment_start {
            let fragment = b.get(fragment_start..available_end).unwrap_or_default();
            let outcome = decoder.write(fragment, |name, value| match name {
                b":authority" => authority = value.to_vec(),
                b"host" => host = value.to_vec(),
                _ => {}
            });
            if !authority.is_empty() {
                return parse_host(&authority);
            }
            if !host.is_empty() {
                return parse_host(&host);
            }
            if outcome.is_err() {
                return Err(SniffError::NoClue);
            }
        }
        if flags & H2_FLAG_END_HEADERS != 0
            && (fragment_start == fragment_end || available_end == fragment_end)
        {
            return Err(SniffError::NoClue);
        }

        if b.len() < length {
            let mut want = payload_offset + length;
            if available_end < fragment_end {
                // More HPACK bytes may finish the authority before the frame ends.
                want = total + 1;
                if b.len() < fragment_start {
                    want = payload_offset + fragment_start + 1;
                }
            }
            return Err(SniffError::NeedAtLeast(want));
        }
        b = b.get(length..).unwrap_or_default();
    }
}

/// Go's `net.SplitHostPort`, which also accepts an empty port.
fn split_host_port(hostport: &str) -> Option<&str> {
    let i = hostport.rfind(':')?;
    let (host, j, k);
    if hostport.starts_with('[') {
        let end = hostport.find(']')?;
        if end + 1 != i {
            return None;
        }
        host = hostport.get(1..end)?;
        j = 1;
        k = end + 1;
    } else {
        host = hostport.get(..i)?;
        if host.contains(':') {
            return None;
        }
        j = 0;
        k = 0;
    }
    if hostport.get(j..)?.contains('[') || hostport.get(k..)?.contains(']') {
        return None;
    }
    Some(host)
}

fn is_ip_literal(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    host.split_once('%')
        .is_some_and(|(addr, zone)| !zone.is_empty() && addr.parse::<std::net::Ipv6Addr>().is_ok())
}

pub(super) fn parse_host(h: &[u8]) -> Result<String, SniffError> {
    if h.is_empty() {
        return Err(SniffError::NoClue);
    }
    let text = String::from_utf8_lossy(h);
    let mut host: &str = &text;

    if let Some(stripped) = split_host_port(host) {
        host = stripped;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        host = inner;
    }

    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return Err(SniffError::NoClue);
    }
    if is_ip_literal(&host) {
        return Err(SniffError::HostIsIp);
    }
    Ok(host)
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
