use std::io::Read;

use crate::capture::Body;

enum Decoded {
    Whole(Vec<u8>),
    Cut(Vec<u8>),
}

/// The body with its content codings removed, in the order they were applied.
/// A coding it cannot read leaves the body encoded and names the codings.
pub(crate) fn decode_body(data: Vec<u8>, truncated: bool, encoding: &str, limit: i64) -> Body {
    let codings: Vec<String> = encoding
        .split(',')
        .map(|coding| coding.trim().to_ascii_lowercase())
        .filter(|coding| !coding.is_empty() && coding != "identity")
        .collect();
    if codings.is_empty() || data.is_empty() {
        return Body {
            data,
            truncated,
            encoding: String::new(),
        };
    }
    let (mut current, mut short) = (data.clone(), false);
    for coding in codings.iter().rev() {
        match decode(coding, &current, limit) {
            Some(Decoded::Whole(out)) => current = out,
            Some(Decoded::Cut(out)) => {
                current = out;
                short = true;
            }
            None => {
                return Body {
                    data,
                    truncated,
                    encoding: encoding.to_string(),
                };
            }
        }
    }
    Body {
        data: current,
        truncated: truncated || short,
        encoding: String::new(),
    }
}

/// Returns what it read before the data or the limit ran out, so a cut body still shows its start.
fn decode(coding: &str, data: &[u8], limit: i64) -> Option<Decoded> {
    let reader: Box<dyn Read + '_> = match coding {
        "gzip" | "x-gzip" => Box::new(flate2::read::GzDecoder::new(data)),
        "deflate" if looks_like_zlib(data) => Box::new(flate2::read::ZlibDecoder::new(data)),
        "deflate" => Box::new(flate2::read::DeflateDecoder::new(data)),
        "br" => Box::new(brotli_decompressor::Decompressor::new(data, 4096)),
        "zstd" => Box::new(ruzstd::decoding::StreamingDecoder::new(data).ok()?),
        _ => return None,
    };
    read_limited(reader, limit)
}

fn looks_like_zlib(data: &[u8]) -> bool {
    match data {
        [cmf, flg, ..] => cmf & 0x0f == 8 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0,
        _ => false,
    }
}

fn read_limited(reader: Box<dyn Read + '_>, limit: i64) -> Option<Decoded> {
    let cap = u64::try_from(limit).unwrap_or(0);
    let mut out = Vec::new();
    let result = reader.take(cap.saturating_add(1)).read_to_end(&mut out);
    if out.len() as u64 > cap {
        out.truncate(cap as usize);
        return Some(Decoded::Cut(out));
    }
    match result {
        Ok(_) => Some(Decoded::Whole(out)),
        Err(_) if out.is_empty() => None,
        Err(_) => Some(Decoded::Cut(out)),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn gzip(text: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn identity_and_empty_are_left_alone() {
        let body = decode_body(b"plain".to_vec(), false, "identity", 100);
        assert_eq!(
            (body.data.as_slice(), body.encoding.as_str()),
            (&b"plain"[..], "")
        );
        assert!(decode_body(Vec::new(), true, "gzip", 100).truncated);
    }

    #[test]
    fn gzip_deflate_and_stacked_codings_decode() {
        assert_eq!(
            decode_body(gzip(b"hello"), false, "gzip", 100).data,
            b"hello"
        );
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(b"zlib body").unwrap();
        assert_eq!(
            decode_body(zlib.finish().unwrap(), false, "deflate", 100).data,
            b"zlib body"
        );
        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"raw body").unwrap();
        assert_eq!(
            decode_body(raw.finish().unwrap(), false, "deflate", 100).data,
            b"raw body"
        );
        let stacked = gzip(&gzip(b"twice"));
        assert_eq!(
            decode_body(stacked, false, "gzip, gzip", 100).data,
            b"twice"
        );
    }

    #[test]
    fn an_unknown_coding_keeps_the_body_encoded() {
        let body = decode_body(b"???".to_vec(), false, "rot13", 100);
        assert_eq!(body.encoding, "rot13");
        assert_eq!(body.data, b"???");
    }

    #[test]
    fn a_cut_body_still_shows_its_start() {
        let encoded = gzip(&b"0123456789".repeat(100));
        let body = decode_body(encoded.clone(), false, "gzip", 25);
        assert_eq!(body.data, b"0123456789012345678901234");
        assert!(body.truncated);
        let noisy: Vec<u8> = (0..4000u32)
            .map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let packed = gzip(&noisy);
        let half = packed.get(..packed.len() * 3 / 4).unwrap().to_vec();
        let body = decode_body(half, false, "gzip", 10_000);
        assert!(body.truncated && !body.data.is_empty());
    }

    #[test]
    fn brotli_and_zstd_decode() {
        let mut brotli = vec![0xa0, 0x00, 0x10];
        brotli.extend_from_slice(b"brotli body");
        brotli.push(0x03);
        assert_eq!(decode_body(brotli, false, "br", 100).data, b"brotli body");
        let mut zstd = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x09, 0x49, 0x00, 0x00];
        zstd.extend_from_slice(b"zstd body");
        assert_eq!(decode_body(zstd, false, "zstd", 100).data, b"zstd body");
    }
}
