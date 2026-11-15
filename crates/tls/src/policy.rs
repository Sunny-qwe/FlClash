use std::sync::{Arc, OnceLock};

use rustls::NamedGroup;
use rustls::crypto::{WebPkiSupportedAlgorithms, aws_lc_rs};
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, KeyUsage};

use crate::{TlsError, TlsOptions, TrustStore};

const BROWSER_NAMES: [&str; 10] = [
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
];

pub(crate) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(prefer_hybrid(aws_lc_rs::default_provider())))
        .clone()
}

/// mihomo's TLS servers pick X25519MLKEM768 whenever it is listed, so offering it without its
/// share costs a HelloRetryRequest; first in the list, rustls sends it and its X25519 half.
fn prefer_hybrid(mut provider: rustls::crypto::CryptoProvider) -> rustls::crypto::CryptoProvider {
    provider
        .kx_groups
        .sort_by_key(|group| group.name() != NamedGroup::X25519MLKEM768);
    provider
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PolicyKey {
    skip: bool,
    pin: Option<[u8; 32]>,
    name_verify: Option<ServerName<'static>>,
}

/// `skip-cert-verify`, the SHA-256 pin and `name-cert-verify` in the order
/// mihomo's `ca.GetTLSConfig` applies them: a pin or a verify name still runs
/// when `skip-cert-verify` is set, because Go calls `VerifyConnection` either way.
#[derive(Debug)]
pub struct CertPolicy {
    skip: bool,
    pin: Option<[u8; 32]>,
    name_verify: Option<ServerName<'static>>,
    trust: Arc<TrustStore>,
    algs: WebPkiSupportedAlgorithms,
}

impl CertPolicy {
    pub fn new(options: &TlsOptions, trust: Arc<TrustStore>) -> Result<Self, TlsError> {
        let pin = options
            .fingerprint
            .as_deref()
            .filter(|text| !text.is_empty())
            .map(parse_pin)
            .transpose()?;
        let name_verify = options
            .name_cert_verify
            .as_deref()
            .filter(|name| !name.is_empty())
            .map(|name| {
                ServerName::try_from(name.to_owned())
                    .map_err(|_| TlsError::Config(format!("invalid name-cert-verify {name:?}")))
            })
            .transpose()?;
        if pin.is_none() && (name_verify.is_some() || !options.skip_cert_verify) {
            trust.expect_anchors();
        }
        Ok(Self {
            skip: options.skip_cert_verify,
            pin,
            name_verify,
            trust,
            algs: provider().signature_verification_algorithms,
        })
    }

    pub(crate) fn key(&self) -> PolicyKey {
        PolicyKey {
            skip: self.skip,
            pin: self.pin,
            name_verify: self.name_verify.clone(),
        }
    }

    pub(crate) fn trust(&self) -> &TrustStore {
        &self.trust
    }

    pub fn now(&self) -> UnixTime {
        UnixTime::since_unix_epoch(
            self.trust
                .clock()
                .now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default(),
        )
    }

    pub fn algorithms(&self) -> WebPkiSupportedAlgorithms {
        self.algs
    }

    pub fn verify(
        &self,
        chain: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<(), TlsError> {
        if let Some(pin) = &self.pin {
            return self.verify_pin(pin, chain, server_name, now);
        }
        if let Some(name) = &self.name_verify {
            return self.verify_path(chain, self.trust.anchors(), name, now);
        }
        if self.skip {
            return Ok(());
        }
        self.verify_path(chain, self.trust.anchors(), server_name, now)
    }

    fn verify_pin(
        &self,
        pin: &[u8; 32],
        chain: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<(), TlsError> {
        let index = chain
            .iter()
            .position(|cert| Sha256::digest(cert.as_ref()).as_slice() == pin)
            .ok_or_else(|| TlsError::Certificate("certificate fingerprints do not match".into()))?;
        if index == 0 {
            return Ok(());
        }
        let pinned = chain
            .get(index)
            .ok_or_else(|| TlsError::Certificate("certificate fingerprints do not match".into()))?;
        let anchor = webpki::anchor_from_trusted_cert(pinned)
            .map_err(|err| TlsError::Certificate(format!("pinned certificate: {err}")))?;
        let name = self.name_verify.as_ref().unwrap_or(server_name);
        let upto = chain.get(..index).unwrap_or(chain);
        self.verify_path(upto, std::slice::from_ref(&anchor), name, now)
    }

    fn verify_path(
        &self,
        chain: &[CertificateDer<'_>],
        anchors: &[TrustAnchor<'_>],
        name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<(), TlsError> {
        let (leaf, intermediates) = chain
            .split_first()
            .ok_or_else(|| TlsError::Certificate("tls: no peer certificates".into()))?;
        let end_entity = EndEntityCert::try_from(leaf)
            .map_err(|err| TlsError::Certificate(format!("certificate: {err}")))?;
        end_entity
            .verify_for_usage(
                self.algs.all,
                anchors,
                intermediates,
                now,
                KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|err| TlsError::Certificate(format!("certificate verify failed: {err}")))?;
        end_entity
            .verify_is_valid_for_subject_name(name)
            .map_err(|err| TlsError::Certificate(format!("certificate verify failed: {err}")))
    }
}

fn parse_pin(text: &str) -> Result<[u8; 32], TlsError> {
    if BROWSER_NAMES.contains(&text) {
        return Err(TlsError::Config(
            "`fingerprint` is used for TLS certificate pinning. If you need to specify the \
             browser fingerprint, use `client-fingerprint`"
                .into(),
        ));
    }
    let cleaned = text.replace(':', "");
    let bytes = hex::decode(cleaned.trim())
        .map_err(|err| TlsError::Config(format!("fingerprint string decode error: {err}")))?;
    bytes.try_into().map_err(|_| {
        TlsError::Config("fingerprint string length error,need sha256 fingerprint".into())
    })
}

pub(crate) fn rustls_error(err: TlsError) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        Arc::new(std::io::Error::other(err.to_string())),
    )))
}
