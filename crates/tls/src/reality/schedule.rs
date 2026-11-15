use aws_lc_rs::aead::{
    AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey,
};
use aws_lc_rs::{digest, hkdf, hmac};

use crate::error::invalid_data;

pub(crate) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub(crate) const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub(crate) const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub(crate) const TAG_LEN: usize = 16;
pub(crate) const RECORD_OVERHEAD: usize = 5 + 1 + TAG_LEN;

pub(crate) const CT_ALERT: u8 = 21;
pub(crate) const CT_HANDSHAKE: u8 = 22;
pub(crate) const CT_APPLICATION_DATA: u8 = 23;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    Sha384,
}

impl Hash {
    pub(crate) fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
        }
    }

    fn hkdf(self) -> hkdf::Algorithm {
        match self {
            Hash::Sha256 => hkdf::HKDF_SHA256,
            Hash::Sha384 => hkdf::HKDF_SHA384,
        }
    }

    fn hmac(self) -> hmac::Algorithm {
        match self {
            Hash::Sha256 => hmac::HMAC_SHA256,
            Hash::Sha384 => hmac::HMAC_SHA384,
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        let algorithm = match self {
            Hash::Sha256 => &digest::SHA256,
            Hash::Sha384 => &digest::SHA384,
        };
        digest::digest(algorithm, data).as_ref().to_vec()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Suite {
    pub(crate) fn from_id(id: u16) -> Option<Self> {
        match id {
            TLS_AES_128_GCM_SHA256 => Some(Suite::Aes128Gcm),
            TLS_AES_256_GCM_SHA384 => Some(Suite::Aes256Gcm),
            TLS_CHACHA20_POLY1305_SHA256 => Some(Suite::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub(crate) fn hash(self) -> Hash {
        match self {
            Suite::Aes256Gcm => Hash::Sha384,
            _ => Hash::Sha256,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        match self {
            Suite::Aes128Gcm => 16,
            _ => 32,
        }
    }

    pub(crate) fn algorithm(self) -> &'static aws_lc_rs::aead::Algorithm {
        match self {
            Suite::Aes128Gcm => &AES_128_GCM,
            Suite::Aes256Gcm => &AES_256_GCM,
            Suite::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        }
    }
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

pub(crate) fn extract(hash: Hash, salt: &[u8], ikm: &[u8]) -> hkdf::Prk {
    hkdf::Salt::new(hash.hkdf(), salt).extract(ikm)
}

pub(crate) fn prk_from_secret(hash: Hash, secret: &[u8]) -> hkdf::Prk {
    hkdf::Prk::new_less_safe(hash.hkdf(), secret)
}

pub(crate) fn expand(prk: &hkdf::Prk, info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let info = [info];
    if let Ok(okm) = prk.expand(&info, Len(len)) {
        let _ = okm.fill(&mut out);
    }
    out
}

pub(crate) fn expand_label(prk: &hkdf::Prk, label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(10 + label.len() + context.len());
    info.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    info.push(u8::try_from(6 + label.len()).unwrap_or(u8::MAX));
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(u8::try_from(context.len()).unwrap_or(u8::MAX));
    info.extend_from_slice(context);
    expand(prk, &info, len)
}

pub(crate) fn hmac_sign(algorithm: hmac::Algorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(algorithm, key), data)
        .as_ref()
        .to_vec()
}

pub(crate) fn finished_verify_data(hash: Hash, secret: &[u8], transcript: &[u8]) -> Vec<u8> {
    let prk = prk_from_secret(hash, secret);
    let key = expand_label(&prk, "finished", &[], hash.len());
    hmac_sign(hash.hmac(), &key, &hash.digest(transcript))
}

pub(crate) struct HandshakeSecrets {
    pub client: Vec<u8>,
    pub server: Vec<u8>,
    pub master: hkdf::Prk,
}

pub(crate) fn handshake_secrets(
    hash: Hash,
    shared: &[u8],
    hello_transcript: &[u8],
) -> HandshakeSecrets {
    let zeros = vec![0u8; hash.len()];
    let empty = hash.digest(&[]);
    let early = extract(hash, &zeros, &zeros);
    let derived = expand_label(&early, "derived", &empty, hash.len());
    let handshake = extract(hash, &derived, shared);
    let transcript = hash.digest(hello_transcript);
    let client = expand_label(&handshake, "c hs traffic", &transcript, hash.len());
    let server = expand_label(&handshake, "s hs traffic", &transcript, hash.len());
    let derived = expand_label(&handshake, "derived", &empty, hash.len());
    HandshakeSecrets {
        client,
        server,
        master: extract(hash, &derived, &zeros),
    }
}

pub(crate) fn application_secrets(
    hash: Hash,
    master: &hkdf::Prk,
    transcript: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let digest = hash.digest(transcript);
    (
        expand_label(master, "c ap traffic", &digest, hash.len()),
        expand_label(master, "s ap traffic", &digest, hash.len()),
    )
}

pub(crate) struct RecordKey {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    pub(crate) fn new(suite: Suite, secret: &[u8]) -> Result<Self, std::io::Error> {
        let prk = prk_from_secret(suite.hash(), secret);
        let key = expand_label(&prk, "key", &[], suite.key_len());
        let iv = expand_label(&prk, "iv", &[], 12);
        let unbound = UnboundKey::new(suite.algorithm(), &key)
            .map_err(|_| invalid_data("record key rejected"))?;
        let iv: [u8; 12] = iv
            .try_into()
            .map_err(|_| invalid_data("record iv length"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            iv,
            seq: 0,
        })
    }

    fn next_nonce(&mut self) -> Nonce {
        let mut nonce = self.iv;
        for (dst, src) in nonce.iter_mut().skip(4).zip(self.seq.to_be_bytes()) {
            *dst ^= src;
        }
        self.seq = self.seq.wrapping_add(1);
        Nonce::assume_unique_for_key(nonce)
    }

    pub(crate) fn seal_into(
        &mut self,
        out: &mut Vec<u8>,
        inner_type: u8,
        plaintext: &[u8],
    ) -> Result<(), std::io::Error> {
        let record_len = plaintext.len() + 1 + TAG_LEN;
        let len16 = u16::try_from(record_len).map_err(|_| invalid_data("record too large"))?;
        let start = out.len();
        out.extend_from_slice(&[CT_APPLICATION_DATA, 3, 3]);
        out.extend_from_slice(&len16.to_be_bytes());
        out.extend_from_slice(plaintext);
        out.push(inner_type);
        let [hi, lo] = len16.to_be_bytes();
        let aad: [u8; 5] = [CT_APPLICATION_DATA, 3, 3, hi, lo];
        let nonce = self.next_nonce();
        let body = out
            .get_mut(start + 5..)
            .ok_or_else(|| invalid_data("record buffer"))?;
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), body)
            .map_err(|_| invalid_data("record encrypt"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    pub(crate) fn seal(
        &mut self,
        inner_type: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut out = Vec::with_capacity(RECORD_OVERHEAD + plaintext.len());
        self.seal_into(&mut out, inner_type, plaintext)?;
        Ok(out)
    }

    /// Opens `payload` (ciphertext and tag) in place and returns the inner
    /// content type with the plaintext length; the plaintext is `payload[..len]`.
    pub(crate) fn open_in_place(
        &mut self,
        header: &[u8; 5],
        payload: &mut [u8],
    ) -> Result<(u8, usize), std::io::Error> {
        if payload.len() < TAG_LEN + 1 {
            return Err(invalid_data("tls ciphertext too short"));
        }
        let nonce = self.next_nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(header), payload)
            .map_err(|_| invalid_data("tls record decrypt"))?;
        let pos = plain
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or_else(|| invalid_data("tls inner plaintext missing type"))?;
        let kind = plain
            .get(pos)
            .copied()
            .ok_or_else(|| invalid_data("tls inner plaintext missing type"))?;
        Ok((kind, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8448 section 3: the simple 1-RTT handshake trace.
    fn unhex(text: &str) -> Vec<u8> {
        hex::decode(text.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn rfc8448_handshake_secrets_and_keys() {
        let shared = unhex(
            "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d",
        );
        let hello_hash_input = unhex(
            "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01",
        );
        let server_hello = unhex(
            "02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04",
        );
        let mut transcript = hello_hash_input;
        transcript.extend(server_hello);
        let secrets = handshake_secrets(Hash::Sha256, &shared, &transcript);
        assert_eq!(
            secrets.server,
            unhex(
                "b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"
            )
        );
        assert_eq!(
            secrets.client,
            unhex(
                "b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"
            )
        );
        let prk = prk_from_secret(Hash::Sha256, &secrets.server);
        assert_eq!(
            expand_label(&prk, "key", &[], 16),
            unhex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc")
        );
        assert_eq!(
            expand_label(&prk, "iv", &[], 12),
            unhex("5d 31 3e b2 67 12 76 ee 13 00 0b 30")
        );
    }

    #[test]
    fn records_round_trip_and_reject_tampering() {
        let secret = [7u8; 32];
        let mut sealer = RecordKey::new(Suite::Aes128Gcm, &secret).unwrap();
        let mut opener = RecordKey::new(Suite::Aes128Gcm, &secret).unwrap();
        for suite_secret in [b"hello".as_slice(), b"".as_slice(), &[9u8; 4000]] {
            let wire = sealer.seal(CT_APPLICATION_DATA, suite_secret).unwrap();
            let mut header = [0u8; 5];
            header.copy_from_slice(&wire[..5]);
            let mut body = wire[5..].to_vec();
            let (kind, len) = opener.open_in_place(&header, &mut body).unwrap();
            assert_eq!(kind, CT_APPLICATION_DATA);
            assert_eq!(&body[..len], suite_secret);
        }
        let wire = sealer.seal(CT_HANDSHAKE, b"x").unwrap();
        let mut header = [0u8; 5];
        header.copy_from_slice(&wire[..5]);
        let mut body = wire[5..].to_vec();
        body[0] ^= 1;
        assert!(opener.open_in_place(&header, &mut body).is_err());
    }
}
