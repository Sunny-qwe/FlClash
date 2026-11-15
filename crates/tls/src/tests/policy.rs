use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use super::support::{Ca, Leaf};
use crate::{CertPolicy, TlsOptions, TrustStore};

fn name(text: &str) -> ServerName<'static> {
    ServerName::try_from(text.to_owned()).unwrap()
}

fn verify(policy: &CertPolicy, leaf: &Leaf, sni: &str) -> Result<(), crate::TlsError> {
    let chain: Vec<CertificateDer<'_>> = leaf.chain.clone();
    policy.verify(&chain, &name(sni), UnixTime::now())
}

fn pin_of(der: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(der.as_ref()))
}

fn policy(ca: &Ca, options: TlsOptions) -> CertPolicy {
    CertPolicy::new(&options, ca.trust()).unwrap()
}

#[test]
fn trusted_chain_and_name_pass() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let policy = policy(&ca, TlsOptions::default());
    verify(&policy, &leaf, "node.test").unwrap();
}

#[test]
fn wrong_name_expired_and_unknown_issuer_fail() {
    let ca = Ca::new();
    let policy_a = policy(&ca, TlsOptions::default());
    assert!(verify(&policy_a, &ca.leaf(&["node.test"]), "other.test").is_err());
    assert!(verify(&policy_a, &ca.expired_leaf("node.test"), "node.test").is_err());
    let stranger = Ca::new();
    assert!(verify(&policy_a, &stranger.leaf(&["node.test"]), "node.test").is_err());
}

#[test]
fn ip_targets_match_ip_sans_only() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["192.0.2.7"]);
    let policy = policy(&ca, TlsOptions::default());
    verify(&policy, &leaf, "192.0.2.7").unwrap();
    assert!(verify(&policy, &leaf, "192.0.2.8").is_err());
    assert!(verify(&policy, &ca.leaf(&["node.test"]), "192.0.2.7").is_err());
}

#[test]
fn chains_through_an_intermediate_verify() {
    let ca = Ca::new();
    let (leaf, _) = ca.with_intermediate(&["deep.test"]);
    let policy = policy(&ca, TlsOptions::default());
    verify(&policy, &leaf, "deep.test").unwrap();
}

#[test]
fn skip_cert_verify_accepts_anything() {
    let ca = Ca::new();
    let stranger = Ca::new();
    let options = TlsOptions {
        skip_cert_verify: true,
        ..TlsOptions::default()
    };
    let policy = policy(&ca, options);
    verify(&policy, &stranger.leaf(&["x.test"]), "other.test").unwrap();
    verify(&policy, &ca.expired_leaf("x.test"), "x.test").unwrap();
}

#[test]
fn name_cert_verify_replaces_the_sni_for_the_check() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["real.test"]);
    let options = TlsOptions {
        name_cert_verify: Some("real.test".into()),
        ..TlsOptions::default()
    };
    let policy = policy(&ca, options);
    verify(&policy, &leaf, "front.test").unwrap();
    let wrong = TlsOptions {
        name_cert_verify: Some("fake.test".into()),
        ..TlsOptions::default()
    };
    assert!(verify(&self::policy(&ca, wrong), &leaf, "real.test").is_err());
}

#[test]
fn name_cert_verify_still_runs_under_skip_cert_verify() {
    let ca = Ca::new();
    let options = TlsOptions {
        skip_cert_verify: true,
        name_cert_verify: Some("real.test".into()),
        ..TlsOptions::default()
    };
    let policy = policy(&ca, options);
    verify(&policy, &ca.leaf(&["real.test"]), "x").unwrap();
    assert!(verify(&policy, &ca.leaf(&["other.test"]), "real.test").is_err());
    assert!(verify(&policy, &Ca::new().leaf(&["real.test"]), "real.test").is_err());
}

#[test]
fn a_leaf_pin_skips_chain_and_name_checks() {
    let ca = Ca::new();
    let stranger = Ca::new();
    let leaf = stranger.leaf(&["whatever.test"]);
    let options = TlsOptions {
        fingerprint: Some(pin_of(leaf.leaf_der())),
        ..TlsOptions::default()
    };
    let policy = policy(&ca, options);
    verify(&policy, &leaf, "unrelated.test").unwrap();
    verify(&policy, &stranger.expired_leaf("a.test"), "a.test").unwrap_err();
}

#[test]
fn pin_formats_and_case() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["a.test"]);
    let hexed = pin_of(leaf.leaf_der());
    let colons: Vec<String> = hexed
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap().to_uppercase())
        .collect();
    for text in [hexed.to_uppercase(), colons.join(":"), format!(" {hexed} ")] {
        let options = TlsOptions {
            fingerprint: Some(text),
            ..TlsOptions::default()
        };
        verify(&policy(&ca, options), &leaf, "a.test").unwrap();
    }
}

#[test]
fn a_mismatched_pin_is_refused_even_when_the_chain_is_good() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["a.test"]);
    let options = TlsOptions {
        fingerprint: Some("00".repeat(32)),
        ..TlsOptions::default()
    };
    let err = verify(&policy(&ca, options.clone()), &leaf, "a.test").unwrap_err();
    assert!(err.to_string().contains("do not match"), "{err}");
    let skipping = TlsOptions {
        skip_cert_verify: true,
        ..options
    };
    verify(&policy(&ca, skipping), &leaf, "a.test").unwrap_err();
}

#[test]
fn a_pin_on_an_intermediate_verifies_the_path_below_it() {
    let ca = Ca::new();
    let stranger = Ca::new();
    let (leaf, intermediate) = stranger.with_intermediate(&["deep.test"]);
    let options = TlsOptions {
        fingerprint: Some(pin_of(&intermediate)),
        ..TlsOptions::default()
    };
    let pinned = policy(&ca, options.clone());
    verify(&pinned, &leaf, "deep.test").unwrap();
    assert!(verify(&pinned, &leaf, "other.test").is_err());
    let with_name = TlsOptions {
        name_cert_verify: Some("deep.test".into()),
        ..options
    };
    verify(&self::policy(&ca, with_name), &leaf, "front.test").unwrap();
}

#[test]
fn a_pin_on_a_cert_that_does_not_sign_the_leaf_is_refused() {
    let ca = Ca::new();
    let stranger = Ca::new();
    let (leaf, _) = stranger.with_intermediate(&["deep.test"]);
    let mut forged = leaf.chain.clone();
    forged.push(ca.der.clone());
    let options = TlsOptions {
        fingerprint: Some(pin_of(&ca.der)),
        ..TlsOptions::default()
    };
    let chain: Vec<CertificateDer<'_>> = forged;
    let result = policy(&ca, options).verify(&chain, &name("deep.test"), UnixTime::now());
    assert!(result.is_err());
}

#[test]
fn bad_pins_are_config_errors() {
    let ca = Ca::new();
    for text in [
        "chrome",
        "firefox",
        "random",
        "zz",
        "abcd",
        &"ab".repeat(33),
    ] {
        let options = TlsOptions {
            fingerprint: Some(text.to_owned()),
            ..TlsOptions::default()
        };
        let err = CertPolicy::new(&options, ca.trust()).unwrap_err();
        assert!(matches!(err, crate::TlsError::Config(_)), "{text}: {err}");
    }
    let browser = CertPolicy::new(
        &TlsOptions {
            fingerprint: Some("chrome".into()),
            ..TlsOptions::default()
        },
        ca.trust(),
    )
    .unwrap_err();
    assert!(browser.to_string().contains("client-fingerprint"));
}

#[test]
fn an_empty_chain_is_refused() {
    let ca = Ca::new();
    let policy = policy(&ca, TlsOptions::default());
    assert!(
        policy
            .verify(&[], &name("a.test"), UnixTime::now())
            .is_err()
    );
}

#[test]
fn the_trust_store_merges_bundle_system_and_custom() {
    let a = Ca::new();
    let b = Ca::new();
    let c = Ca::new();
    let bundle = format!(
        "garbage\n{}\n-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
        super::support::pem_of(&b.der)
    );
    let store = TrustStore::from_parts(vec![a.der.clone()], bundle.as_bytes(), vec![c.der.clone()]);
    assert_eq!(store.len(), 3);
    let options = TlsOptions::default();
    let policy = CertPolicy::new(&options, store).unwrap();
    for ca in [&a, &b, &c] {
        verify(&policy, &ca.leaf(&["m.test"]), "m.test").unwrap();
    }
    verify(&policy, &Ca::new().leaf(&["m.test"]), "m.test").unwrap_err();
}

#[test]
fn the_default_store_reads_the_system_roots() {
    let store = TrustStore::new(b"", Vec::new());
    assert!(!store.is_empty());
}

#[test]
fn certificates_parse_from_pem() {
    let ca = Ca::new();
    let pem = super::support::pem_of(&ca.der);
    assert_eq!(crate::parse_certificates(&pem).len(), 1);
    assert!(crate::parse_certificates("nonsense").is_empty());
    assert!(crate::parse_certificates("").is_empty());
}
