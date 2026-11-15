use aws_lc_rs::aead::quic::{AES_128, HeaderProtectionKey};
use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

use super::error::SniffError;

/// Long-header packet types are remapped in QUIC v2, so they live here with the
/// other version-specific parameters.
pub(super) struct Version {
    pub(super) id: u32,
    pub(super) type_initial: u8,
    pub(super) type_retry: u8,
    pub(super) initial_salt: [u8; 20],
    pub(super) label_prefix: &'static str,
}

pub(super) const DRAFT_29: Version = Version {
    id: 0xff00_001d,
    type_initial: 0b00,
    type_retry: 0b11,
    initial_salt: [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ],
    label_prefix: "quic",
};

pub(super) const V1: Version = Version {
    id: 1,
    type_initial: 0b00,
    type_retry: 0b11,
    initial_salt: [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ],
    label_prefix: "quic",
};

pub(super) const V2: Version = Version {
    id: 0x6b33_43cf,
    type_initial: 0b01,
    type_retry: 0b00,
    initial_salt: [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ],
    label_prefix: "quicv2",
};

pub(super) const VERSIONS: [&Version; 3] = [&DRAFT_29, &V1, &V2];

pub(super) struct Labels {
    hp: [u8; 16],
    key: [u8; 16],
    iv: [u8; 12],
}

pub(super) struct InitialKey {
    pub(super) dest_conn_id: Vec<u8>,
    pub(super) labels: Labels,
    pub(super) largest_packet_number: i64,
}

impl InitialKey {
    pub(super) fn new(dest_conn_id: &[u8], version: &Version) -> Result<Self, SniffError> {
        Ok(InitialKey {
            dest_conn_id: dest_conn_id.to_vec(),
            labels: Labels::derive(dest_conn_id, version).ok_or(SniffError::NotQuic)?,
            largest_packet_number: -1,
        })
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(secret: &Prk, label: &str, out: &mut [u8]) -> Option<()> {
    let length = u16::try_from(out.len()).ok()?.to_be_bytes();
    let label_len = [u8::try_from(6 + label.len()).ok()?];
    let info: [&[u8]; 5] = [&length, &label_len, b"tls13 ", label.as_bytes(), &[0]];
    secret.expand(&info, Len(out.len())).ok()?.fill(out).ok()
}

impl Labels {
    pub(super) fn derive(dest_conn_id: &[u8], version: &Version) -> Option<Labels> {
        let initial_secret = Salt::new(HKDF_SHA256, &version.initial_salt).extract(dest_conn_id);
        let mut client = [0u8; 32];
        expand_label(&initial_secret, "client in", &mut client)?;
        let client = Prk::new_less_safe(HKDF_SHA256, &client);

        let prefix = version.label_prefix;
        let mut labels = Labels {
            hp: [0; 16],
            key: [0; 16],
            iv: [0; 12],
        };
        expand_label(&client, &format!("{prefix} hp"), &mut labels.hp)?;
        expand_label(&client, &format!("{prefix} key"), &mut labels.key)?;
        expand_label(&client, &format!("{prefix} iv"), &mut labels.iv)?;
        Some(labels)
    }

    fn nonce(&self, packet_number: i64) -> Nonce {
        let mut iv = self.iv;
        let pn = (packet_number as u64).to_be_bytes();
        for (slot, byte) in iv.iter_mut().rev().zip(pn.iter().rev()) {
            *slot ^= byte;
        }
        Nonce::assume_unique_for_key(iv)
    }

    fn header_mask(&self, sample: &[u8]) -> Option<[u8; 5]> {
        HeaderProtectionKey::new(&AES_128, &self.hp)
            .ok()?
            .new_mask(sample)
            .ok()
    }

    fn aead(&self) -> Option<LessSafeKey> {
        Some(LessSafeKey::new(
            UnboundKey::new(&AES_128_GCM, &self.key).ok()?,
        ))
    }
}

/// Reconstructs a packet number from its truncated wire form with the window
/// of RFC 9000 appendix A.3.
pub(super) fn decode_packet_number(length: usize, largest: i64, truncated: i64) -> i64 {
    let expected = largest + 1;
    let window = 1i64 << (length * 8);
    let half_window = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate <= expected - half_window && candidate < (1i64 << 62) - window {
        return candidate + window;
    }
    if candidate > expected + half_window && candidate >= window {
        return candidate - window;
    }
    candidate
}

/// Removes header protection and decrypts one Initial packet, returning its
/// frames and the reconstructed packet number. `b` starts at the first byte
/// of the packet, `hdr_len` is the offset of the protected packet number.
pub(super) fn decrypt_initial(
    b: &[u8],
    hdr_len: usize,
    packet_end: usize,
    labels: &Labels,
    largest_packet_number: i64,
) -> Result<(Vec<u8>, i64), SniffError> {
    let sample_start = hdr_len + 4;
    if sample_start + 16 > packet_end {
        return Err(SniffError::NotQuic);
    }
    let sample = b.get(sample_start..sample_start + 16);
    let mask = sample
        .and_then(|sample| labels.header_mask(sample))
        .ok_or(SniffError::NotQuic)?;
    let first_byte = b.first().ok_or(SniffError::NotQuic)? ^ (mask[0] & 0x0f);
    let packet_number_len = usize::from(first_byte & 0x03) + 1;
    let ext_hdr_len = hdr_len + packet_number_len;
    if ext_hdr_len > packet_end {
        return Err(SniffError::NotQuic);
    }

    let mut ext_hdr = b.get(..ext_hdr_len).ok_or(SniffError::NotQuic)?.to_vec();
    if let Some(first) = ext_hdr.first_mut() {
        *first = first_byte;
    }
    let mut truncated = 0i64;
    for (byte, mask_byte) in ext_hdr
        .get_mut(hdr_len..)
        .unwrap_or_default()
        .iter_mut()
        .zip(mask.iter().skip(1))
    {
        *byte ^= mask_byte;
        truncated = truncated << 8 | i64::from(*byte);
    }
    let packet_number = decode_packet_number(packet_number_len, largest_packet_number, truncated);

    let mut data = b
        .get(ext_hdr_len..packet_end)
        .ok_or(SniffError::NotQuic)?
        .to_vec();
    let key = labels.aead().ok_or(SniffError::NotQuic)?;
    let plaintext_len = key
        .open_in_place(labels.nonce(packet_number), Aad::from(&ext_hdr), &mut data)
        .map_err(|_| SniffError::DecryptionFailed)?
        .len();
    data.truncate(plaintext_len);
    Ok((data, packet_number))
}

#[cfg(test)]
impl Labels {
    pub(super) fn seal_for_test(
        &self,
        packet_number: i64,
        header: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut out = plaintext.to_vec();
        let Some(key) = self.aead() else {
            return out;
        };
        let nonce = self.nonce(packet_number);
        if key
            .seal_in_place_append_tag(nonce, Aad::from(header), &mut out)
            .is_err()
        {
            out.clear();
        }
        out
    }

    pub(super) fn mask_for_test(&self, sample: &[u8]) -> Option<[u8; 5]> {
        self.header_mask(sample)
    }
}
