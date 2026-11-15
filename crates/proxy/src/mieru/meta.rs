use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const META_LEN: usize = 32;
pub(super) const TAG_LEN: usize = 16;
pub(super) const NONCE_LEN: usize = 24;
pub(super) const MAX_OPEN_PAYLOAD: usize = 1024;
pub(super) const MAX_PDU: usize = 32 * 1024;

pub(super) const OPEN_REQUEST: u8 = 2;
pub(super) const OPEN_RESPONSE: u8 = 3;
pub(super) const CLOSE_REQUEST: u8 = 4;
pub(super) const CLOSE_RESPONSE: u8 = 5;
pub(super) const DATA_C2S: u8 = 6;
pub(super) const DATA_S2C: u8 = 7;
pub(super) const ACK_C2S: u8 = 8;
pub(super) const ACK_S2C: u8 = 9;
pub(super) const DATA_C2S_LOW: u8 = 10;
pub(super) const DATA_S2C_LOW: u8 = 11;

pub(super) fn is_session(kind: u8) -> bool {
    (OPEN_REQUEST..=CLOSE_RESPONSE).contains(&kind)
}

pub(super) fn is_data_or_ack(kind: u8) -> bool {
    (DATA_C2S..=DATA_S2C_LOW).contains(&kind)
}

pub(super) fn is_low_entropy(kind: u8) -> bool {
    kind == DATA_C2S_LOW || kind == DATA_S2C_LOW
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct LowEntropyMeta {
    pub(super) mode: u8,
    pub(super) mask: u32,
    pub(super) extracted_len: u16,
    pub(super) rotation: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Meta {
    Session {
        kind: u8,
        id: u32,
        seq: u32,
        status: u8,
        payload_len: u16,
        suffix_len: u8,
    },
    Data {
        kind: u8,
        id: u32,
        seq: u32,
        unack: u32,
        window: u16,
        fragment: u8,
        prefix_len: u8,
        payload_len: u16,
        suffix_len: u8,
        low: LowEntropyMeta,
    },
}

fn minutes() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    u32::try_from(secs / 60).unwrap_or(u32::MAX)
}

fn put(out: &mut [u8; META_LEN], at: usize, bytes: &[u8]) {
    if let Some(target) = out.get_mut(at..at + bytes.len()) {
        target.copy_from_slice(bytes);
    }
}

fn take<const N: usize>(from: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    if let Some(source) = from.get(at..at + N) {
        out.copy_from_slice(source);
    }
    out
}

impl Meta {
    pub(super) fn encode(&self) -> [u8; META_LEN] {
        let mut out = [0u8; META_LEN];
        put(&mut out, 2, &minutes().to_be_bytes());
        match *self {
            Meta::Session {
                kind,
                id,
                seq,
                status,
                payload_len,
                suffix_len,
            } => {
                put(&mut out, 0, &[kind]);
                put(&mut out, 6, &id.to_be_bytes());
                put(&mut out, 10, &seq.to_be_bytes());
                put(&mut out, 14, &[status]);
                put(&mut out, 15, &payload_len.to_be_bytes());
                put(&mut out, 17, &[suffix_len]);
            }
            Meta::Data {
                kind,
                id,
                seq,
                unack,
                window,
                fragment,
                prefix_len,
                payload_len,
                suffix_len,
                low,
            } => {
                put(&mut out, 0, &[kind]);
                if is_low_entropy(kind) {
                    put(&mut out, 1, &[low.mode]);
                    put(&mut out, 25, &low.mask.to_be_bytes());
                    put(&mut out, 29, &low.extracted_len.to_be_bytes());
                    put(&mut out, 31, &[low.rotation]);
                }
                put(&mut out, 6, &id.to_be_bytes());
                put(&mut out, 10, &seq.to_be_bytes());
                put(&mut out, 14, &unack.to_be_bytes());
                put(&mut out, 18, &window.to_be_bytes());
                put(&mut out, 20, &[fragment, prefix_len]);
                put(&mut out, 22, &payload_len.to_be_bytes());
                put(&mut out, 24, &[suffix_len]);
            }
        }
        out
    }

    pub(super) fn decode(raw: &[u8]) -> io::Result<Meta> {
        let kind = raw
            .first()
            .copied()
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        if raw.len() != META_LEN {
            return Err(invalid("metadata length"));
        }
        if is_session(kind) {
            let payload_len = u16::from_be_bytes(take(raw, 15));
            if usize::from(payload_len) > MAX_OPEN_PAYLOAD {
                return Err(invalid("session payload too large"));
            }
            return Ok(Meta::Session {
                kind,
                id: u32::from_be_bytes(take(raw, 6)),
                seq: u32::from_be_bytes(take(raw, 10)),
                status: take::<1>(raw, 14)[0],
                payload_len,
                suffix_len: take::<1>(raw, 17)[0],
            });
        }
        if !is_data_or_ack(kind) {
            return Err(invalid("unknown protocol type"));
        }
        let low = if is_low_entropy(kind) {
            LowEntropyMeta {
                mode: take::<1>(raw, 1)[0],
                mask: u32::from_be_bytes(take(raw, 25)),
                extracted_len: u16::from_be_bytes(take(raw, 29)),
                rotation: take::<1>(raw, 31)[0],
            }
        } else {
            LowEntropyMeta::default()
        };
        Ok(Meta::Data {
            kind,
            id: u32::from_be_bytes(take(raw, 6)),
            seq: u32::from_be_bytes(take(raw, 10)),
            unack: u32::from_be_bytes(take(raw, 14)),
            window: u16::from_be_bytes(take(raw, 18)),
            fragment: take::<1>(raw, 20)[0],
            prefix_len: take::<1>(raw, 21)[0],
            payload_len: u16::from_be_bytes(take(raw, 22)),
            suffix_len: take::<1>(raw, 24)[0],
            low,
        })
    }
}

pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("mieru: {message}"))
}
