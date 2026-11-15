use std::borrow::Cow;

use super::dispatcher::DataSniffer;
use super::error::SniffError;

pub(super) const RECORD_HEADER_LEN: usize = 5;
pub(super) const HANDSHAKE_HEADER_LEN: usize = 4;
const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const MAX_PLAINTEXT: usize = 1 << 14;

pub(super) struct TlsSniffer;

impl DataSniffer for TlsSniffer {
    fn sniff(&self, data: &[u8]) -> Result<String, SniffError> {
        sniff_tls(data)
    }
}

fn byte_at(data: &[u8], index: usize) -> usize {
    data.get(index).copied().map_or(0, usize::from)
}

fn u16_at(data: &[u8], index: usize) -> usize {
    byte_at(data, index) << 8 | byte_at(data, index + 1)
}

/// Returns the server name as soon as its field is complete in a ClientHello
/// prefix that starts with the four-byte handshake header.
pub(super) fn read_client_hello(data: &[u8]) -> Result<String, SniffError> {
    let Some(&first) = data.first() else {
        return Err(SniffError::NeedAtLeast(1));
    };
    if first != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SniffError::NotClientHello);
    }
    if data.len() < HANDSHAKE_HEADER_LEN {
        return Err(SniffError::NeedAtLeast(HANDSHAKE_HEADER_LEN));
    }

    let hello_size = client_hello_size(data)?;
    let data = data.get(..hello_size).unwrap_or(data);
    let need = |length: usize| -> Result<(), SniffError> {
        if length > hello_size {
            Err(SniffError::NotClientHello)
        } else if data.len() < length {
            Err(SniffError::NeedAtLeast(length))
        } else {
            Ok(())
        }
    };

    let mut offset = HANDSHAKE_HEADER_LEN + 2 + 32;
    need(offset + 1)?;
    let session_id_len = byte_at(data, offset);
    if session_id_len > 32 {
        return Err(SniffError::NotClientHello);
    }
    offset += 1;
    need(offset + session_id_len)?;
    offset += session_id_len;

    need(offset + 2)?;
    let cipher_suite_len = u16_at(data, offset);
    if cipher_suite_len % 2 == 1 {
        return Err(SniffError::NotClientHello);
    }
    offset += 2;
    need(offset + cipher_suite_len)?;
    offset += cipher_suite_len;

    need(offset + 1)?;
    let compression_len = byte_at(data, offset);
    offset += 1;
    need(offset + compression_len)?;
    offset += compression_len;

    if offset == hello_size {
        return Err(SniffError::NotClientHello);
    }
    need(offset + 2)?;

    let extensions_len = u16_at(data, offset);
    offset += 2;
    let extensions_end = offset + extensions_len;
    if extensions_end != hello_size {
        return Err(SniffError::NotClientHello);
    }

    while offset < extensions_end {
        need(offset + 4)?;
        let extension = u16_at(data, offset);
        let length = u16_at(data, offset + 2);
        offset += 4;
        let extension_end = offset + length;
        if extension_end > extensions_end {
            return Err(SniffError::NotClientHello);
        }

        if extension == 0 {
            if length < 2 {
                return Err(SniffError::NotClientHello);
            }
            need(offset + 2)?;
            let names_len = u16_at(data, offset);
            offset += 2;
            let names_end = offset + names_len;
            if names_end != extension_end {
                return Err(SniffError::NotClientHello);
            }
            while offset < names_end {
                need(offset + 3)?;
                let name_type = byte_at(data, offset);
                let name_len = u16_at(data, offset + 1);
                offset += 3;
                let name_end = offset + name_len;
                if name_end > names_end {
                    return Err(SniffError::NotClientHello);
                }
                need(name_end)?;
                if name_type == 0 {
                    let name = data.get(offset..name_end).unwrap_or_default();
                    // RFC 6066 section 3: a trailing dot is not allowed.
                    if name.last() == Some(&b'.') {
                        return Err(SniffError::NotClientHello);
                    }
                    return Ok(String::from_utf8_lossy(name).into_owned());
                }
                offset = name_end;
            }
        } else {
            if extension_end == extensions_end {
                // The last extension cannot hide a later server_name.
                return Err(SniffError::NotTls);
            }
            need(extension_end)?;
            offset = extension_end;
        }
    }

    Err(SniffError::NotTls)
}

pub(super) fn client_hello_size(data: &[u8]) -> Result<usize, SniffError> {
    if data.len() < HANDSHAKE_HEADER_LEN {
        return Err(SniffError::NoClue);
    }
    if byte_at(data, 0) != usize::from(HANDSHAKE_TYPE_CLIENT_HELLO) {
        return Err(SniffError::NotClientHello);
    }
    let body_len = byte_at(data, 1) << 16 | byte_at(data, 2) << 8 | byte_at(data, 3);
    Ok(HANDSHAKE_HEADER_LEN + body_len)
}

/// Walks TLS records, joining their payloads, until the ClientHello yields a
/// server name or a verdict. Only a ClientHello split across records copies.
pub(super) fn sniff_tls(b: &[u8]) -> Result<String, SniffError> {
    let mut client_hello: Cow<'_, [u8]> = Cow::Borrowed(&[]);
    let mut wire_offset = 0usize;

    loop {
        let rest = b.get(wire_offset..).unwrap_or_default();
        let Some((header, payload_and_more)) = rest.split_first_chunk::<RECORD_HEADER_LEN>() else {
            return Err(SniffError::NeedAtLeast(wire_offset + RECORD_HEADER_LEN));
        };
        let [record_type, major, _minor, len_hi, len_lo] = *header;
        if record_type != RECORD_TYPE_HANDSHAKE || major != 3 {
            return Err(SniffError::NotTls);
        }

        let record_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        if record_len > MAX_PLAINTEXT {
            return Err(SniffError::NotTls);
        }
        if record_len == 0 {
            return Err(SniffError::NotClientHello);
        }

        let payload_offset = wire_offset + RECORD_HEADER_LEN;
        let record_end = payload_offset + record_len;
        let payload_end = b.len().min(record_end);
        let payload = payload_and_more
            .get(..payload_end - payload_offset)
            .unwrap_or_default();
        if wire_offset == 0 {
            client_hello = Cow::Borrowed(payload);
        } else {
            client_hello.to_mut().extend_from_slice(payload);
        }

        let need = match read_client_hello(&client_hello) {
            Ok(domain) => return Ok(domain),
            Err(SniffError::NeedAtLeast(length)) => length,
            Err(err) => return Err(err),
        };

        if payload_end < record_end {
            // Translate the required ClientHello prefix back to a wire offset,
            // stopping at this record's boundary.
            let missing = need
                .saturating_sub(client_hello.len())
                .min(record_end - payload_end);
            return Err(SniffError::NeedAtLeast(payload_end + missing));
        }
        wire_offset = record_end;
    }
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
