use std::collections::HashSet;
use std::path::Path;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

/// Android: only the two system stores, so a user-installed CA never joins the
/// trust set. Elsewhere: the OS store through `rustls-native-certs`.
pub fn system_root_certs() -> Vec<CertificateDer<'static>> {
    #[cfg(target_os = "android")]
    {
        certs_from_dirs(&[
            Path::new("/system/etc/security/cacerts"),
            Path::new("/apex/com.android.conscrypt/cacerts"),
        ])
    }
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let loaded = rustls_native_certs::load_native_certs();
        for err in &loaded.errors {
            tracing::warn!("loading a system certificate failed: {err}");
        }
        loaded.certs
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "macos",
        target_os = "linux",
        target_os = "windows"
    )))]
    {
        Vec::new()
    }
}

pub fn certs_from_dirs(dirs: &[&Path]) -> Vec<CertificateDer<'static>> {
    let mut seen = HashSet::new();
    let mut certs = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        let mut files: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
        files.sort();
        for file in files {
            let Ok(bytes) = std::fs::read(&file) else {
                continue;
            };
            for cert in CertificateDer::pem_slice_iter(&bytes).flatten() {
                if seen.insert(cert.as_ref().to_vec()) {
                    certs.push(cert);
                }
            }
        }
    }
    certs
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "Certificate:\n    text dump the store prepends\n\
        -----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";

    #[test]
    fn certificates_are_read_once_across_directories() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        std::fs::write(first.path().join("1a2b3c4d.0"), PEM).unwrap();
        std::fs::write(second.path().join("1a2b3c4d.0"), PEM).unwrap();
        std::fs::write(second.path().join("README"), "not a certificate").unwrap();

        let certs = certs_from_dirs(&[first.path(), second.path(), Path::new("missing")]);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].as_ref(), b"hello");
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    #[test]
    fn the_os_store_is_not_empty() {
        assert!(!system_root_certs().is_empty());
    }
}
