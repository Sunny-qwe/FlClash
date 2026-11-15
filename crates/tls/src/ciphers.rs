//! Record ciphers for transferred traffic keys (rustls, BoringSSL, REALITY), behind
//! rustls's own `MessageEncrypter`/`MessageDecrypter` so the record layer stays one code
//! path. Nonces, additional data and TLS 1.3 unpadding use rustls's public helpers.

use std::io;

use aws_lc_rs::aead;
use rustls::crypto::cipher::{
    InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, make_tls12_aad,
};
use rustls::{ContentType, ProtocolVersion};

use crate::reality::schedule::{Suite, expand_label, prk_from_secret};
use crate::record::{KeySchedule, Keys};

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const GCM_EXPLICIT_NONCE_LEN: usize = 8;
/// The record limits rustls's provider gives these AEADs.
const AES_GCM_LIMIT: u64 = 1 << 24;
const CHACHA_LIMIT: u64 = u64::MAX;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn key(algorithm: &'static aead::Algorithm, bytes: &[u8]) -> io::Result<aead::LessSafeKey> {
    let key = aead::UnboundKey::new(algorithm, bytes).map_err(|_| invalid("tls: bad key"))?;
    Ok(aead::LessSafeKey::new(key))
}

fn nonce(iv: &Iv, seq: u64) -> aead::Nonce {
    aead::Nonce::assume_unique_for_key(Nonce::new(iv, seq).0)
}

fn record_len(len: usize) -> Result<[u8; 2], rustls::Error> {
    u16::try_from(len)
        .map(u16::to_be_bytes)
        .map_err(|_| rustls::Error::EncryptError)
}

/// RFC 8446 5.2.
struct Tls13Cipher {
    key: aead::LessSafeKey,
    iv: Iv,
}

/// AWS-LC's TLS sealing context infers the IV from a first record at sequence zero.
/// A midstream handoff must instead keep the exported IV and the writer's nonzero sequence.
pub(crate) fn tls13_sealer(
    algorithm: &'static aead::Algorithm,
    key_bytes: &[u8],
    iv: Iv,
) -> io::Result<Box<dyn MessageEncrypter>> {
    Ok(Box::new(Tls13Cipher {
        key: key(algorithm, key_bytes)?,
        iv,
    }))
}

impl Tls13Cipher {
    fn new(suite: Suite, secret: &[u8]) -> io::Result<Self> {
        let prk = prk_from_secret(suite.hash(), secret);
        let key_bytes = expand_label(&prk, "key", &[], suite.key_len());
        let iv = expand_label(&prk, "iv", &[], NONCE_LEN);
        Ok(Tls13Cipher {
            key: key(suite.algorithm(), &key_bytes)?,
            iv: Iv::copy(&iv),
        })
    }
}

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&[u8::from(msg.typ)]);
        let [hi, lo] = record_len(total)?;
        let aad = aead::Aad::from([u8::from(ContentType::ApplicationData), 3, 3, hi, lo]);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce(&self.iv, seq), aad, payload.as_mut())
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend_from_slice(tag.as_ref());
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let [hi, lo] = record_len(msg.payload.len()).map_err(|_| rustls::Error::DecryptError)?;
        let [major, minor] = u16::from(msg.version).to_be_bytes();
        let aad = aead::Aad::from([u8::from(msg.typ), major, minor, hi, lo]);
        let plain = self
            .key
            .open_in_place(nonce(&self.iv, seq), aad, &mut msg.payload)
            .map_err(|_| rustls::Error::DecryptError)?
            .len();
        msg.payload.truncate(plain);
        msg.into_tls13_unpadded_message()
    }
}

/// RFC 8446 7.2: each KeyUpdate moves a direction's secret one step.
struct Tls13Schedule {
    suite: Suite,
    tx: Vec<u8>,
    rx: Vec<u8>,
}

fn next_secret(suite: Suite, secret: &[u8]) -> Vec<u8> {
    let prk = prk_from_secret(suite.hash(), secret);
    expand_label(&prk, "traffic upd", &[], suite.hash().len())
}

impl KeySchedule for Tls13Schedule {
    fn next_tx(&mut self) -> io::Result<Box<dyn MessageEncrypter>> {
        self.tx = next_secret(self.suite, &self.tx);
        Ok(Box::new(Tls13Cipher::new(self.suite, &self.tx)?))
    }

    fn next_rx(&mut self) -> io::Result<Box<dyn MessageDecrypter>> {
        self.rx = next_secret(self.suite, &self.rx);
        Ok(Box::new(Tls13Cipher::new(self.suite, &self.rx)?))
    }
}

/// A client's TLS 1.3 record keys from its application traffic secrets.
pub(crate) fn tls13_keys(
    suite: Suite,
    client_secret: Vec<u8>,
    server_secret: Vec<u8>,
    write_seq: u64,
    read_seq: u64,
) -> io::Result<Keys> {
    let limit = match suite {
        Suite::ChaCha20Poly1305 => CHACHA_LIMIT,
        Suite::Aes128Gcm | Suite::Aes256Gcm => AES_GCM_LIMIT,
    };
    Ok(Keys {
        tls13: true,
        limit,
        tx: (
            write_seq,
            Box::new(Tls13Cipher::new(suite, &client_secret)?),
        ),
        rx: (read_seq, Box::new(Tls13Cipher::new(suite, &server_secret)?)),
        schedule: Box::new(Tls13Schedule {
            suite,
            tx: client_secret,
            rx: server_secret,
        }),
    })
}

/// rustls's TLS 1.2 AES-GCM sealer, on a key that does not insist on starting at sequence
/// zero: rustls builds it on aws-lc's TLS 1.3 key, which takes its nonce mask from the first
/// nonce it sees, and after the handshake the first application record is sequence 1. Same
/// nonce (fixed IV and explicit part, xor the sequence) and additional data as rustls.
pub(crate) struct Tls12GcmSeal {
    key: aead::LessSafeKey,
    iv: Iv,
}

impl Tls12GcmSeal {
    /// `iv` is the 4-byte fixed IV followed by the 8-byte explicit nonce base.
    pub(crate) fn new(
        algorithm: &'static aead::Algorithm,
        key_bytes: &[u8],
        iv: &[u8],
    ) -> io::Result<Self> {
        if iv.len() != NONCE_LEN {
            return Err(invalid("tls: bad AES-GCM iv"));
        }
        Ok(Tls12GcmSeal {
            key: key(algorithm, key_bytes)?,
            iv: Iv::copy(iv),
        })
    }
}

impl MessageEncrypter for Tls12GcmSeal {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let mut payload =
            PrefixedPayload::with_capacity(self.encrypted_payload_len(msg.payload.len()));
        let nonce = nonce(&self.iv, seq);
        let aad = aead::Aad::from(make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len()));
        payload.extend_from_slice(nonce.as_ref().get(4..).unwrap_or_default());
        payload.extend_from_chunks(&msg.payload);
        let sealed = payload
            .as_mut()
            .get_mut(GCM_EXPLICIT_NONCE_LEN..)
            .ok_or(rustls::Error::EncryptError)?;
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, sealed)
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend_from_slice(tag.as_ref());
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + GCM_EXPLICIT_NONCE_LEN + TAG_LEN
    }
}

/// TLS 1.2 AES-GCM open (RFC 5288): the explicit nonce travels in the record.
struct Tls12GcmOpen {
    key: aead::LessSafeKey,
    salt: [u8; 4],
}

impl MessageDecrypter for Tls12GcmOpen {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut msg.payload;
        let plain_len = payload
            .len()
            .checked_sub(GCM_EXPLICIT_NONCE_LEN + TAG_LEN)
            .ok_or(rustls::Error::DecryptError)?;
        let (explicit, sealed) = payload.split_at_mut(GCM_EXPLICIT_NONCE_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        let (fixed, rest) = nonce.split_at_mut(4);
        fixed.copy_from_slice(&self.salt);
        rest.copy_from_slice(explicit);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let plain = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                sealed,
            )
            .map_err(|_| rustls::Error::DecryptError)?
            .len();
        Ok(msg.into_plain_message_range(GCM_EXPLICIT_NONCE_LEN..GCM_EXPLICIT_NONCE_LEN + plain))
    }
}

/// TLS 1.2 ChaCha20-Poly1305 (RFC 7905): the nonce is the IV xor the sequence.
struct Tls12ChaCha {
    key: aead::LessSafeKey,
    iv: Iv,
}

impl MessageEncrypter for Tls12ChaCha {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let mut payload = PrefixedPayload::with_capacity(msg.payload.len() + TAG_LEN);
        payload.extend_from_chunks(&msg.payload);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, msg.payload.len());
        let tag = self
            .key
            .seal_in_place_separate_tag(
                nonce(&self.iv, seq),
                aead::Aad::from(aad),
                payload.as_mut(),
            )
            .map_err(|_| rustls::Error::EncryptError)?;
        payload.extend_from_slice(tag.as_ref());
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

impl MessageDecrypter for Tls12ChaCha {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let plain_len = msg
            .payload
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(rustls::Error::DecryptError)?;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plain_len);
        let plain = self
            .key
            .open_in_place(nonce(&self.iv, seq), aead::Aad::from(aad), &mut msg.payload)
            .map_err(|_| rustls::Error::DecryptError)?
            .len();
        Ok(msg.into_plain_message_range(0..plain))
    }
}

struct NoKeyUpdate;

impl KeySchedule for NoKeyUpdate {
    fn next_tx(&mut self) -> io::Result<Box<dyn MessageEncrypter>> {
        Err(invalid("tls: TLS 1.2 has no KeyUpdate"))
    }

    fn next_rx(&mut self) -> io::Result<Box<dyn MessageDecrypter>> {
        Err(invalid("tls: TLS 1.2 has no KeyUpdate"))
    }
}

#[derive(Clone, Copy)]
enum Tls12Aead {
    Gcm(&'static aead::Algorithm),
    ChaCha,
}

/// The AEAD suites BoringSSL can offer in TLS 1.2; anything else (CBC) has no record layer
/// here.
fn tls12_aead(suite: u16) -> Option<Tls12Aead> {
    match suite {
        0xc02b | 0xc02f | 0x009c => Some(Tls12Aead::Gcm(&aead::AES_128_GCM)),
        0xc02c | 0xc030 | 0x009d => Some(Tls12Aead::Gcm(&aead::AES_256_GCM)),
        0xcca9 | 0xcca8 => Some(Tls12Aead::ChaCha),
        _ => None,
    }
}

pub(crate) fn tls12_is_aead(suite: u16) -> bool {
    tls12_aead(suite).is_some()
}

/// A client's TLS 1.2 record keys from the key block. With no MAC keys, RFC 5246 6.3 lays it
/// out as client key, server key, client IV, server IV.
pub(crate) fn tls12_keys(
    suite: u16,
    key_block: &[u8],
    write_seq: u64,
    read_seq: u64,
) -> io::Result<Keys> {
    let aead = tls12_aead(suite).ok_or_else(|| invalid("tls: not an AEAD suite"))?;
    let (key_len, iv_len) = match aead {
        Tls12Aead::Gcm(algorithm) => (algorithm.key_len(), 4),
        Tls12Aead::ChaCha => (32, NONCE_LEN),
    };
    if key_block.len() != 2 * (key_len + iv_len) {
        return Err(invalid("tls: key block does not match the suite"));
    }
    let (client_key, rest) = key_block.split_at(key_len);
    let (server_key, rest) = rest.split_at(key_len);
    let (client_iv, server_iv) = rest.split_at(iv_len);
    let (tx, rx, limit): (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>, u64) = match aead {
        Tls12Aead::Gcm(algorithm) => {
            let mut iv = [0u8; NONCE_LEN];
            iv.get_mut(..4)
                .unwrap_or_default()
                .copy_from_slice(client_iv);
            let salt = server_iv
                .try_into()
                .map_err(|_| invalid("tls: bad AES-GCM iv"))?;
            let open = Tls12GcmOpen {
                key: key(algorithm, server_key)?,
                salt,
            };
            (
                Box::new(Tls12GcmSeal::new(algorithm, client_key, &iv)?),
                Box::new(open),
                AES_GCM_LIMIT,
            )
        }
        Tls12Aead::ChaCha => (
            Box::new(Tls12ChaCha {
                key: key(&aead::CHACHA20_POLY1305, client_key)?,
                iv: Iv::copy(client_iv),
            }),
            Box::new(Tls12ChaCha {
                key: key(&aead::CHACHA20_POLY1305, server_key)?,
                iv: Iv::copy(server_iv),
            }),
            CHACHA_LIMIT,
        ),
    };
    Ok(Keys {
        tls13: false,
        limit,
        tx: (write_seq, tx),
        rx: (read_seq, rx),
        schedule: Box::new(NoKeyUpdate),
    })
}
