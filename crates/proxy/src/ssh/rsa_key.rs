use aws_lc_rs::cipher::{
    AES_128, AES_192, AES_256, DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RSA_PKCS1_SHA512};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use md5::{Digest, Md5};
use num_bigint::BigUint;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::private::RsaKeypair;
use russh::keys::ssh_key::public::{KeyData, RsaPublicKey};
use russh::keys::ssh_key::{HashAlg, Mpint, PublicKey};

const RSA_ENCRYPTION_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// An RSA key that signs with aws-lc-rs, so the `rsa` crate's private-key operations stay out of the build.
#[derive(Debug)]
pub(super) struct RsaSigner {
    pair: KeyPair,
    public: PublicKey,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SignError {
    #[error(transparent)]
    Send(#[from] russh::SendError),
    #[error("{0}")]
    Sign(String),
}

fn positive(value: &Mpint) -> Result<&[u8], String> {
    value
        .as_positive_bytes()
        .ok_or_else(|| "RSA key has a negative component".to_string())
}

impl RsaSigner {
    pub(super) fn public(&self) -> PublicKey {
        self.public.clone()
    }

    pub(super) fn from_openssh(keypair: &RsaKeypair) -> Result<Self, String> {
        let (public, private) = (keypair.public(), keypair.private());
        let (n, e) = (positive(public.n())?, positive(public.e())?);
        let (d, p, q) = (
            positive(private.d())?,
            positive(private.p())?,
            positive(private.q())?,
        );
        let reduced = |prime: &[u8]| {
            let prime = BigUint::from_bytes_be(prime);
            (BigUint::from_bytes_be(d) % (prime - 1u8)).to_bytes_be()
        };
        let (dp, dq) = (reduced(p), reduced(q));
        let components = aws_lc_rs::rsa::KeyPairComponents {
            public_key: aws_lc_rs::rsa::PublicKeyComponents { n, e },
            d,
            p,
            q,
            dP: &dp,
            dQ: &dq,
            qInv: positive(private.iqmp())?,
        };
        let pair = KeyPair::from_components(&components).map_err(rejected)?;
        Self::new(pair, n, e)
    }

    fn from_pkcs1(der: &[u8]) -> Result<Self, String> {
        let pair = KeyPair::from_der(der).map_err(rejected)?;
        let numbers = integers(der)?;
        let (n, e) = match (numbers.get(1), numbers.get(2)) {
            (Some(n), Some(e)) => (*n, *e),
            _ => return Err("malformed RSA private key".to_string()),
        };
        Self::new(pair, n, e)
    }

    fn from_pkcs8(der: &[u8]) -> Result<Self, String> {
        let pair = KeyPair::from_pkcs8(der).map_err(rejected)?;
        let public = pair.public_key().as_ref().to_vec();
        let numbers = integers(&public)?;
        let (n, e) = match (numbers.first(), numbers.get(1)) {
            (Some(n), Some(e)) => (*n, *e),
            _ => return Err("malformed RSA public key".to_string()),
        };
        Self::new(pair, n, e)
    }

    fn new(pair: KeyPair, n: &[u8], e: &[u8]) -> Result<Self, String> {
        let rsa = RsaPublicKey::new(Mpint::from_positive_bytes(e), Mpint::from_positive_bytes(n))
            .map_err(|err| format!("RSA public key: {err}"))?;
        let public = PublicKey::from(KeyData::Rsa(rsa));
        Ok(RsaSigner { pair, public })
    }

    /// The SSH `userauth` signature for `rsa-sha2-256` or `rsa-sha2-512`, appended to `data`.
    fn sign_into(&self, hash: HashAlg, mut data: Vec<u8>) -> Result<Vec<u8>, SignError> {
        let (name, padding) = match hash {
            HashAlg::Sha256 => ("rsa-sha2-256", &RSA_PKCS1_SHA256),
            HashAlg::Sha512 => ("rsa-sha2-512", &RSA_PKCS1_SHA512),
            _ => return Err(SignError::Sign("unsupported RSA hash".to_string())),
        };
        let mut signature = vec![0u8; self.pair.public_modulus_len()];
        self.pair
            .sign(padding, &SystemRandom::new(), &data, &mut signature)
            .map_err(|_| SignError::Sign("RSA signing failed".to_string()))?;
        let framed = name.len() + signature.len() + 8;
        data.extend_from_slice(&u32::try_from(framed).unwrap_or(u32::MAX).to_be_bytes());
        data.extend_from_slice(&u32::try_from(name.len()).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(&u32::try_from(signature.len()).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(&signature);
        Ok(data)
    }
}

pub(super) struct Sign<'a> {
    pub(super) key: &'a RsaSigner,
    pub(super) hash: HashAlg,
}

impl russh::Signer for Sign<'_> {
    type Error = SignError;

    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.key.sign_into(self.hash, to_sign)
    }
}

fn rejected(err: aws_lc_rs::error::KeyRejected) -> String {
    format!("RSA key rejected: {err} (keys from 2048 to 8192 bits are supported)")
}

/// The contents of a DER `SEQUENCE` of `INTEGER`s without their leading zero byte.
fn integers(der: &[u8]) -> Result<Vec<&[u8]>, String> {
    let bad = || "malformed DER".to_string();
    let ((tag, mut rest), _) = element_split(der).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let mut out = Vec::new();
    while !rest.is_empty() {
        let ((kind, body), after) = element_split(rest).ok_or_else(bad)?;
        if kind == 0x02 {
            out.push(
                body.strip_prefix(&[0])
                    .filter(|b| !b.is_empty())
                    .unwrap_or(body),
            );
        }
        rest = after;
    }
    Ok(out)
}

type Element<'a> = ((u8, &'a [u8]), &'a [u8]);

fn element_split(der: &[u8]) -> Option<Element<'_>> {
    let (&kind, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (bytes, rest) = rest.split_at(count);
        (
            bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)),
            rest,
        )
    };
    if rest.len() < len {
        return None;
    }
    let (body, after) = rest.split_at(len);
    Some(((kind, body), after))
}

struct Pem {
    kind: String,
    cipher: Option<(String, Vec<u8>)>,
    der: Vec<u8>,
}

fn pem(text: &str) -> Option<Pem> {
    let mut lines = text.lines().map(str::trim);
    let kind = lines
        .find_map(|line| line.strip_prefix("-----BEGIN ")?.strip_suffix("-----"))?
        .to_string();
    let mut cipher = None;
    let mut body = String::new();
    for line in lines {
        if line.starts_with("-----END ") {
            break;
        }
        if let Some(info) = line.strip_prefix("DEK-Info:") {
            let (name, iv) = info.trim().split_once(',')?;
            cipher = Some((name.trim().to_string(), hex(iv.trim())?));
        } else if !line.contains(':') {
            body.push_str(line);
        }
    }
    Some(Pem {
        kind,
        cipher,
        der: STANDARD.decode(body).ok()?,
    })
}

fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one round, the key derivation of legacy encrypted PEM.
fn derive_key(passphrase: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(len + 16);
    let mut previous: Vec<u8> = Vec::new();
    while key.len() < len {
        let mut input = previous.clone();
        input.extend_from_slice(passphrase);
        input.extend_from_slice(salt);
        previous = Md5::digest(&input).to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(len);
    key
}

fn decrypt_legacy(
    mut der: Vec<u8>,
    (name, iv): &(String, Vec<u8>),
    passphrase: &[u8],
) -> Result<Vec<u8>, String> {
    let (algorithm, key_len) = match name.as_str() {
        "AES-128-CBC" => (&AES_128, 16),
        "AES-192-CBC" => (&AES_192, 24),
        "AES-256-CBC" => (&AES_256, 32),
        other => return Err(format!("unsupported PEM encryption {other}")),
    };
    let wrong = || "x509: decryption password incorrect".to_string();
    let iv: [u8; 16] = iv.as_slice().try_into().map_err(|_| wrong())?;
    let salt = iv.get(..8).ok_or_else(wrong)?;
    let key = UnboundCipherKey::new(algorithm, &derive_key(passphrase, salt, key_len))
        .map_err(|_| wrong())?;
    let decrypting = PaddedBlockDecryptingKey::cbc_pkcs7(key).map_err(|_| wrong())?;
    let plain = decrypting
        .decrypt(&mut der, DecryptionContext::Iv128(FixedLength::from(iv)))
        .map_err(|_| wrong())?;
    Ok(plain.to_vec())
}

/// `Ok(None)` when `text` is a PEM block of some other key type, for the caller to decode.
pub(super) fn from_pem(text: &str, passphrase: Option<&str>) -> Result<Option<RsaSigner>, String> {
    let Some(block) = pem(text) else {
        return Ok(None);
    };
    match block.kind.as_str() {
        "RSA PRIVATE KEY" => {
            let der = match (&block.cipher, passphrase) {
                (Some(cipher), Some(passphrase)) => {
                    decrypt_legacy(block.der, cipher, passphrase.as_bytes())?
                }
                (Some(_), None) => {
                    return Err("ssh: this private key is passphrase protected".to_string());
                }
                (None, Some(_)) => return Err("ssh: not an encrypted key".to_string()),
                (None, None) => block.der,
            };
            RsaSigner::from_pkcs1(&der)
                .map(Some)
                .map_err(|err| format!("x509: failed to parse private key ({err})"))
        }
        "PRIVATE KEY"
            if block
                .der
                .windows(RSA_ENCRYPTION_OID.len())
                .take(32)
                .any(|window| window == RSA_ENCRYPTION_OID) =>
        {
            if passphrase.is_some() {
                return Err("ssh: not an encrypted key".to_string());
            }
            RsaSigner::from_pkcs8(&block.der).map(Some)
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests assert on fixed shapes"
    )]

    use aws_lc_rs::cipher::{EncryptionContext, PaddedBlockEncryptingKey};
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeySize, PublicKeyComponents};
    use aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256;

    use super::*;

    fn generated() -> (Vec<u8>, Vec<u8>) {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = pair.as_der().unwrap().as_ref().to_vec();
        let ((_, body), _) = element_split(&pkcs8).unwrap();
        let (_, rest) = element_split(body).unwrap();
        let (_, rest) = element_split(rest).unwrap();
        let ((_, pkcs1), _) = element_split(rest).unwrap();
        let pkcs1 = pkcs1.to_vec();
        (pkcs8, pkcs1)
    }

    fn armored(label: &str, headers: &str, der: &[u8]) -> String {
        let body = STANDARD.encode(der);
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{headers}{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    fn encrypted(pkcs1: &[u8], name: &str, key_len: usize, passphrase: &str) -> String {
        let algorithm = match key_len {
            16 => &AES_128,
            24 => &AES_192,
            _ => &AES_256,
        };
        let iv = [7u8; 16];
        let key = UnboundCipherKey::new(
            algorithm,
            &derive_key(passphrase.as_bytes(), &iv[..8], key_len),
        )
        .unwrap();
        let mut data = pkcs1.to_vec();
        PaddedBlockEncryptingKey::cbc_pkcs7(key)
            .unwrap()
            .less_safe_encrypt(&mut data, EncryptionContext::Iv128(FixedLength::from(iv)))
            .unwrap();
        let hex: String = iv.iter().map(|b| format!("{b:02X}")).collect();
        armored(
            "RSA PRIVATE KEY",
            &format!("Proc-Type: 4,ENCRYPTED\nDEK-Info: {name},{hex}\n\n"),
            &data,
        )
    }

    fn signs_for(signer: &RsaSigner, hash: HashAlg) {
        let signed = signer.sign_into(hash, Vec::new()).unwrap();
        let blob = &signed[4..];
        let name_len = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
        let sig = &blob[8 + name_len..];
        let KeyData::Rsa(public) = signer.public().key_data().clone() else {
            unreachable!()
        };
        let params = match hash {
            HashAlg::Sha256 => &RSA_PKCS1_2048_8192_SHA256,
            _ => &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA512,
        };
        PublicKeyComponents {
            n: public.n().as_positive_bytes().unwrap(),
            e: public.e().as_positive_bytes().unwrap(),
        }
        .verify(params, b"", sig)
        .unwrap();
    }

    #[test]
    fn plain_pkcs1_and_pkcs8_keys_sign_for_both_hashes() {
        let (pkcs8, pkcs1) = generated();
        for text in [
            armored("RSA PRIVATE KEY", "", &pkcs1),
            armored("PRIVATE KEY", "", &pkcs8),
        ] {
            let signer = from_pem(&text, None).unwrap().unwrap();
            signs_for(&signer, HashAlg::Sha256);
            signs_for(&signer, HashAlg::Sha512);
        }
    }

    #[test]
    fn legacy_encrypted_pem_decrypts_for_every_aes_size() {
        let (_, pkcs1) = generated();
        for (name, len) in [
            ("AES-128-CBC", 16),
            ("AES-192-CBC", 24),
            ("AES-256-CBC", 32),
        ] {
            let text = encrypted(&pkcs1, name, len, "secret");
            let signer = from_pem(&text, Some("secret")).unwrap().unwrap();
            signs_for(&signer, HashAlg::Sha256);
            assert!(from_pem(&text, Some("wrong")).is_err(), "{name}");
            assert_eq!(
                from_pem(&text, None).err().as_deref(),
                Some("ssh: this private key is passphrase protected")
            );
        }
        let unknown = encrypted(&pkcs1, "DES-EDE3-CBC", 24, "secret");
        assert!(
            from_pem(&unknown, Some("secret"))
                .unwrap_err()
                .contains("unsupported")
        );
    }

    #[test]
    fn other_pem_types_and_stray_passphrases_are_left_to_the_caller() {
        let (pkcs8, pkcs1) = generated();
        assert!(
            from_pem(&armored("EC PRIVATE KEY", "", &[1, 2, 3]), None)
                .unwrap()
                .is_none()
        );
        assert!(
            from_pem(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
                None
            )
            .unwrap()
            .is_none()
        );
        assert!(
            from_pem(
                &armored("PRIVATE KEY", "", &[0x30, 0x03, 0x02, 0x01, 0x00]),
                None
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            from_pem(&armored("RSA PRIVATE KEY", "", &pkcs1), Some("x"))
                .err()
                .as_deref(),
            Some("ssh: not an encrypted key")
        );
        assert_eq!(
            from_pem(&armored("PRIVATE KEY", "", &pkcs8), Some("x"))
                .err()
                .as_deref(),
            Some("ssh: not an encrypted key")
        );
    }

    #[test]
    fn a_malformed_rsa_key_is_a_parse_error() {
        let err = from_pem(&armored("RSA PRIVATE KEY", "", &[0x30, 0x00]), None).unwrap_err();
        assert!(err.contains("failed to parse private key"), "{err}");
    }
}
