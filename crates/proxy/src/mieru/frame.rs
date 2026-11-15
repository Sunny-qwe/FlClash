use std::io;

use super::cipher::Seal;
use super::meta::{self, LowEntropyMeta, Meta, TAG_LEN, invalid};
use super::padding;
use super::pattern::LowEntropy;

pub(super) fn write_session<S: Seal>(
    seal: &mut S,
    kind: u8,
    id: u32,
    seq: u32,
    payload: &[u8],
    padding: &[u8],
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let meta = Meta::Session {
        kind,
        id,
        seq,
        status: 0,
        payload_len: u16::try_from(payload.len()).map_err(|_| invalid("payload"))?,
        suffix_len: u8::try_from(padding.len()).map_err(|_| invalid("padding"))?,
    };
    seal.seal(out, &meta.encode())?;
    if !payload.is_empty() {
        seal.seal(out, payload)?;
    }
    out.extend_from_slice(padding);
    Ok(())
}

pub(super) struct DataFrame<'a> {
    pub(super) kind: u8,
    pub(super) id: u32,
    pub(super) seq: u32,
    pub(super) unack: u32,
    pub(super) window: u16,
    pub(super) fragment: u8,
    pub(super) prefix: &'a [u8],
    pub(super) suffix: &'a [u8],
    pub(super) payload: &'a [u8],
    pub(super) low: Option<LowEntropy>,
}

pub(super) fn write_data<S: Seal>(
    seal: &mut S,
    frame: &DataFrame<'_>,
    out: &mut Vec<u8>,
) -> io::Result<()> {
    let payload = frame.payload;
    let low = frame.low.filter(|_| frame.kind == meta::DATA_C2S);
    let mut meta = Meta::Data {
        kind: if low.is_some() {
            meta::DATA_C2S_LOW
        } else {
            frame.kind
        },
        id: frame.id,
        seq: frame.seq,
        unack: frame.unack,
        window: frame.window,
        fragment: frame.fragment,
        prefix_len: u8::try_from(frame.prefix.len()).map_err(|_| invalid("padding"))?,
        payload_len: u16::try_from(payload.len()).map_err(|_| invalid("payload"))?,
        suffix_len: u8::try_from(frame.suffix.len()).map_err(|_| invalid("padding"))?,
        low: LowEntropyMeta::default(),
    };
    let mut half = 0;
    if let (
        Some(low),
        Meta::Data {
            low: slot,
            payload_len,
            ..
        },
    ) = (low, &mut meta)
    {
        half = padding::new_half_mask(low.mode)?;
        *payload_len = u16::try_from(padding::encoded_len(payload.len(), low.mode)?)
            .map_err(|_| invalid("payload"))?;
        *slot = LowEntropyMeta {
            mode: low.mode,
            mask: half,
            extracted_len: u16::try_from(payload.len()).map_err(|_| invalid("payload"))?,
            rotation: low.rotation,
        };
    }
    seal.seal(out, &meta.encode())?;
    out.extend_from_slice(frame.prefix);
    if !payload.is_empty() {
        match low {
            None => seal.seal(out, payload)?,
            Some(low) => {
                let mut sealed = Vec::with_capacity(payload.len() + TAG_LEN);
                seal.seal(&mut sealed, payload)?;
                let (body, tag) = sealed.split_at(payload.len());
                out.extend_from_slice(&padding::encode_low(
                    body,
                    low.mode,
                    half,
                    low.rotation,
                    false,
                )?);
                out.extend_from_slice(tag);
            }
        }
    }
    out.extend_from_slice(frame.suffix);
    Ok(())
}
