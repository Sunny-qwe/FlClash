use std::fs;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::{TlsError, TlsOptions};

pub struct ClientAuth {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Clone for ClientAuth {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuth")
            .field("chain", &self.chain.len())
            .finish_non_exhaustive()
    }
}

pub(crate) fn load_client_auth(options: &TlsOptions) -> Result<Option<ClientAuth>, TlsError> {
    let certificate = options.certificate.as_deref().unwrap_or_default();
    let private_key = options.private_key.as_deref().unwrap_or_default();
    if certificate.is_empty() && private_key.is_empty() {
        return Ok(None);
    }
    let plain = parse_pair(certificate.as_bytes(), private_key.as_bytes());
    let pair = match plain {
        Ok(pair) => pair,
        Err(plain_err) => {
            let loaded = fs::read(certificate)
                .and_then(|cert| fs::read(private_key).map(|key| (cert, key)))
                .map_err(|err| err.to_string())
                .and_then(|(cert, key)| parse_pair(&cert, &key));
            loaded.map_err(|load_err| {
                TlsError::Config(format!(
                    "parse certificate failed, maybe format error:{plain_err}, or path error: {load_err}"
                ))
            })?
        }
    };
    Ok(Some(pair))
}

fn parse_pair(certificate: &[u8], private_key: &[u8]) -> Result<ClientAuth, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(certificate)
        .collect::<Result<_, _>>()
        .map_err(|err| format!("certificate: {err}"))?;
    if chain.is_empty() {
        return Err("certificate: no PEM certificate found".into());
    }
    let key = PrivateKeyDer::from_pem_slice(private_key).map_err(|err| format!("key: {err}"))?;
    Ok(ClientAuth { chain, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (String, String) {
        let key = rcgen::generate_simple_self_signed(vec!["client.test".into()]).unwrap();
        (key.cert.pem(), key.signing_key.serialize_pem())
    }

    #[test]
    fn empty_options_mean_no_client_auth() {
        assert!(load_client_auth(&TlsOptions::default()).unwrap().is_none());
    }

    #[test]
    fn pem_text_and_files_both_load() {
        let (cert, key) = pair();
        let opts = TlsOptions {
            certificate: Some(cert.clone()),
            private_key: Some(key.clone()),
            ..TlsOptions::default()
        };
        assert_eq!(load_client_auth(&opts).unwrap().unwrap().chain.len(), 1);

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("c.pem");
        let key_path = dir.path().join("k.pem");
        fs::write(&cert_path, cert).unwrap();
        fs::write(&key_path, key).unwrap();
        let opts = TlsOptions {
            certificate: Some(cert_path.to_string_lossy().into_owned()),
            private_key: Some(key_path.to_string_lossy().into_owned()),
            ..TlsOptions::default()
        };
        assert!(load_client_auth(&opts).unwrap().is_some());
    }

    #[test]
    fn garbage_reports_both_attempts() {
        let opts = TlsOptions {
            certificate: Some("nope".into()),
            private_key: Some("nope".into()),
            ..TlsOptions::default()
        };
        let err = load_client_auth(&opts).unwrap_err().to_string();
        assert!(err.contains("format error"), "{err}");
        assert!(err.contains("path error"), "{err}");
    }

    #[test]
    fn a_lone_certificate_is_an_error() {
        let (cert, _) = pair();
        let opts = TlsOptions {
            certificate: Some(cert),
            ..TlsOptions::default()
        };
        assert!(load_client_auth(&opts).is_err());
    }
}
