use std::io;

use bytes::BytesMut;
use shadowsocks::crypto::CipherKind;
use shadowsocks::crypto::v1::{Cipher, openssl_bytes_to_key};

use super::stream::{BoxLayer, Layer};
use crate::ctx::BuildError;

const KDF_LEN_DUMMY: usize = 16;

#[derive(Clone)]
pub(super) struct SsrCipher {
    kind: Option<CipherKind>,
    pub(super) key: Vec<u8>,
}

/// EVP_BytesToKey over MD5, which is what Go's `core.Kdf` is.
pub(super) fn kdf(password: &[u8], len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    openssl_bytes_to_key(password, &mut key);
    key
}

impl SsrCipher {
    pub(super) fn pick(name: &str, password: &str) -> Result<Self, BuildError> {
        let upper = name.to_ascii_uppercase();
        let kind = match upper.as_str() {
            "NONE" | "DUMMY" => {
                return Ok(SsrCipher {
                    kind: None,
                    key: kdf(password.as_bytes(), KDF_LEN_DUMMY),
                });
            }
            "RC4-MD5" => CipherKind::SS_RC4_MD5,
            "AES-128-CTR" => CipherKind::AES_128_CTR,
            "AES-192-CTR" => CipherKind::AES_192_CTR,
            "AES-256-CTR" => CipherKind::AES_256_CTR,
            "AES-128-CFB" => CipherKind::AES_128_CFB128,
            "AES-192-CFB" => CipherKind::AES_192_CFB128,
            "AES-256-CFB" => CipherKind::AES_256_CFB128,
            "CHACHA20-IETF" => CipherKind::CHACHA20,
            "CHACHA20" | "XCHACHA20" => {
                return Err(BuildError::unsupported(format!(
                    "ssr cipher {name} is not implemented yet"
                )));
            }
            other if is_aead(other) => {
                return Err(BuildError::invalid(format!(
                    "{name} is not none or a supported stream cipher in ssr"
                )));
            }
            _ => {
                return Err(BuildError::invalid(format!(
                    "ssr cipher: {name} initialize error: cipher not supported"
                )));
            }
        };
        Ok(SsrCipher {
            kind: Some(kind),
            key: kdf(password.as_bytes(), kind.key_len()),
        })
    }

    pub(super) fn iv_len(&self) -> usize {
        self.kind.map_or(0, |kind| kind.iv_len())
    }

    pub(super) fn layer(&self) -> CipherLayer {
        let mut iv = vec![0u8; self.iv_len()];
        rand::fill(&mut iv[..]);
        CipherLayer {
            kind: self.kind,
            key: self.key.clone(),
            enc: self.kind.map(|kind| Cipher::new(kind, &self.key, &iv)),
            iv,
            wrote_iv: false,
            dec: None,
        }
    }

    /// A UDP packet is a fresh IV followed by the stream-encrypted payload.
    pub(super) fn seal_packet(&self, packet: &mut concord_common::PacketBuf) {
        let Some(kind) = self.kind else { return };
        let mut iv = vec![0u8; kind.iv_len()];
        rand::fill(&mut iv[..]);
        let mut cipher = Cipher::new(kind, &self.key, &iv);
        cipher.encrypt_packet(packet.as_mut_slice());
        packet.prepend(iv.len()).copy_from_slice(&iv);
    }

    pub(super) fn open_packet(&self, packet: &mut concord_common::PacketBuf) -> io::Result<()> {
        let Some(kind) = self.kind else {
            return Ok(());
        };
        let iv_len = kind.iv_len();
        let iv = packet
            .as_slice()
            .get(..iv_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short packet"))?
            .to_vec();
        packet.consume(iv_len);
        let mut cipher = Cipher::new(kind, &self.key, &iv);
        if !cipher.decrypt_packet(packet.as_mut_slice()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad packet"));
        }
        Ok(())
    }

    pub(super) fn headroom(&self) -> usize {
        self.iv_len()
    }
}

fn is_aead(upper: &str) -> bool {
    upper.contains("GCM")
        || upper.contains("POLY1305")
        || upper.contains("CCM")
        || upper.starts_with("AEAD_")
}

pub(super) struct CipherLayer {
    kind: Option<CipherKind>,
    key: Vec<u8>,
    pub(super) iv: Vec<u8>,
    enc: Option<Cipher>,
    wrote_iv: bool,
    dec: Option<Cipher>,
}

impl Layer for CipherLayer {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        if !self.wrote_iv {
            out.extend_from_slice(&self.iv);
            self.wrote_iv = true;
        }
        let start = out.len();
        out.extend_from_slice(data);
        if let (Some(enc), Some(tail)) = (self.enc.as_mut(), out.get_mut(start..)) {
            enc.encrypt_packet(tail);
        }
        Ok(())
    }

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        _reply: &mut Vec<u8>,
    ) -> io::Result<()> {
        if let (None, Some(kind)) = (&self.dec, self.kind) {
            let iv_len = kind.iv_len();
            if input.len() < iv_len {
                return Ok(());
            }
            let iv = input.split_to(iv_len);
            self.dec = Some(Cipher::new(kind, &self.key, &iv));
        }
        let mut chunk = input.split();
        if let Some(dec) = self.dec.as_mut()
            && !dec.decrypt_packet(&mut chunk)
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad stream"));
        }
        decoded.unsplit(chunk);
        Ok(())
    }

    fn split(self) -> (BoxLayer, BoxLayer) {
        let decode = CipherLayer {
            kind: self.kind,
            key: self.key.clone(),
            iv: Vec::new(),
            enc: None,
            wrote_iv: true,
            dec: self.dec,
        };
        let encode = CipherLayer { dec: None, ..self };
        (Box::new(decode), Box::new(encode))
    }
}
