use std::io;
use std::sync::Arc;

use concord_common::ClockOffset;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use super::support::{Ca, Leaf, Seen, ServerSpec, echo_server, server_config};
use crate::{Backend, ClientFingerprint, TlsConn, TlsConnector, TlsOptions, TrustStore};

const BACKENDS: [Option<ClientFingerprint>; 3] = [
    None,
    Some(ClientFingerprint::Chrome),
    Some(ClientFingerprint::Chrome120),
];

fn options(fp: Option<ClientFingerprint>, name: &str) -> TlsOptions {
    TlsOptions {
        server_name: Some(name.into()),
        client_fingerprint: fp,
        ..TlsOptions::default()
    }
}

async fn dial(
    options: TlsOptions,
    trust: Arc<TrustStore>,
    leaf: &Leaf,
    spec: &ServerSpec,
    fallback: &str,
) -> (io::Result<TlsConn>, JoinHandle<Option<Seen>>) {
    let connector = TlsConnector::new(options, trust).unwrap();
    let (client, server) = echo_server(server_config(leaf, spec));
    (connector.connect(client, fallback).await, server)
}

async fn echo(conn: &mut TlsConn, payload: &[u8]) {
    conn.write_all(payload).await.unwrap();
    conn.flush().await.unwrap();
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);
}

#[tokio::test]
async fn every_backend_handshakes_and_echoes_with_alpn() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let spec = ServerSpec {
        alpn: vec![b"h2"],
        ..ServerSpec::default()
    };
    for fp in BACKENDS {
        let mut opts = options(fp, "node.test");
        opts.alpn = vec!["h2".into(), "http/1.1".into()];
        let (conn, server) = dial(opts, ca.trust(), &leaf, &spec, "ignored").await;
        let mut conn = conn.unwrap();
        assert_eq!(conn.negotiated_alpn(), Some(b"h2".as_slice()), "{fp:?}");
        assert!(conn.is_tls13(), "{fp:?}");
        echo(&mut conn, b"ping").await;
        echo(&mut conn, &vec![7u8; 100_000]).await;
        drop(conn);
        assert_eq!(
            server.await.unwrap().unwrap().alpn.as_deref(),
            Some(b"h2".as_slice())
        );
    }
}

#[tokio::test]
async fn backend_choice_follows_the_options() {
    let ca = Ca::new();
    let plain = TlsConnector::new(options(None, "a.test"), ca.trust()).unwrap();
    assert_eq!(plain.backend(), Backend::Rustls);
    let none =
        TlsConnector::new(options(Some(ClientFingerprint::None), "a.test"), ca.trust()).unwrap();
    assert_eq!(none.backend(), Backend::Rustls);
    let chrome = TlsConnector::new(
        options(Some(ClientFingerprint::Chrome), "a.test"),
        ca.trust(),
    )
    .unwrap();
    assert_eq!(chrome.backend(), Backend::Boring);
    assert_eq!(chrome.fingerprint(), Some(ClientFingerprint::Chrome));
    let random = TlsConnector::new(
        options(Some(ClientFingerprint::Random), "a.test"),
        ca.trust(),
    )
    .unwrap();
    assert_eq!(random.backend(), Backend::Boring);
}

#[tokio::test]
async fn untrusted_certificates_are_refused_unless_skipped() {
    let ca = Ca::new();
    let leaf = Ca::new().leaf(&["node.test"]);
    for fp in BACKENDS {
        let (refused, _server) = dial(
            options(fp, "node.test"),
            ca.trust(),
            &leaf,
            &ServerSpec::default(),
            "",
        )
        .await;
        let err = refused.err().unwrap();
        assert!(err.to_string().contains("certificate"), "{fp:?}: {err}");

        let mut skipping = options(fp, "node.test");
        skipping.skip_cert_verify = true;
        let (accepted, _server) =
            dial(skipping, ca.trust(), &leaf, &ServerSpec::default(), "").await;
        echo(&mut accepted.unwrap(), b"ok").await;
    }
}

#[tokio::test]
async fn expired_and_misnamed_certificates_are_refused() {
    let ca = Ca::new();
    for fp in BACKENDS {
        let expired = ca.expired_leaf("node.test");
        let (result, _s) = dial(
            options(fp, "node.test"),
            ca.trust(),
            &expired,
            &ServerSpec::default(),
            "",
        )
        .await;
        assert!(result.is_err(), "{fp:?} expired");
        let other = ca.leaf(&["other.test"]);
        let (result, _s) = dial(
            options(fp, "node.test"),
            ca.trust(),
            &other,
            &ServerSpec::default(),
            "",
        )
        .await;
        assert!(result.is_err(), "{fp:?} name");
    }
}

#[tokio::test]
async fn the_clock_offset_decides_whether_a_certificate_has_expired() {
    const TEN_DAYS: i64 = 10 * 24 * 3600 * 1_000_000_000;
    let ca = Ca::new();
    let expired = ca.expired_leaf("node.test");
    for fp in BACKENDS {
        let clock = Arc::new(ClockOffset::default());
        let trust = TrustStore::with_clock(clock.clone(), Vec::new(), b"", vec![ca.der.clone()]);
        let (result, _s) = dial(
            options(fp, "node.test"),
            trust.clone(),
            &expired,
            &ServerSpec::default(),
            "",
        )
        .await;
        assert!(result.is_err(), "{fp:?} before the offset");

        clock.set(-TEN_DAYS);
        let (result, _s) = dial(
            options(fp, "node.test"),
            trust,
            &expired,
            &ServerSpec::default(),
            "",
        )
        .await;
        echo(&mut result.unwrap(), b"ok").await;
    }
}

#[tokio::test]
async fn pins_match_or_refuse_on_every_backend() {
    use sha2::{Digest, Sha256};
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let stranger = Ca::new();
    let pin = hex::encode(Sha256::digest(leaf.leaf_der().as_ref()));
    for fp in BACKENDS {
        let mut good = options(fp, "node.test");
        good.fingerprint = Some(pin.clone());
        let (conn, _s) = dial(good, stranger.trust(), &leaf, &ServerSpec::default(), "").await;
        echo(&mut conn.unwrap(), b"pinned").await;

        let mut bad = options(fp, "node.test");
        bad.fingerprint = Some("11".repeat(32));
        let (conn, _s) = dial(bad, ca.trust(), &leaf, &ServerSpec::default(), "").await;
        let err = conn.err().unwrap();
        assert!(err.to_string().contains("do not match"), "{fp:?}: {err}");
    }
}

#[tokio::test]
async fn name_cert_verify_checks_the_named_host() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["real.test"]);
    for fp in BACKENDS {
        let mut opts = options(fp, "front.test");
        opts.name_cert_verify = Some("real.test".into());
        let (conn, _s) = dial(opts, ca.trust(), &leaf, &ServerSpec::default(), "").await;
        echo(&mut conn.unwrap(), b"fronted").await;

        let mut wrong = options(fp, "real.test");
        wrong.name_cert_verify = Some("elsewhere.test".into());
        let (conn, _s) = dial(wrong, ca.trust(), &leaf, &ServerSpec::default(), "").await;
        assert!(conn.is_err(), "{fp:?}");
    }
}

#[tokio::test]
async fn sni_follows_the_option_then_the_target() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["sni.test"]);
    for fp in BACKENDS {
        let mut opts = TlsOptions {
            client_fingerprint: fp,
            ..TlsOptions::default()
        };
        let (conn, server) = dial(
            opts.clone(),
            ca.trust(),
            &leaf,
            &ServerSpec::default(),
            "sni.test",
        )
        .await;
        echo(&mut conn.unwrap(), b"x").await;
        assert_eq!(
            server.await.unwrap().unwrap().sni.as_deref(),
            Some("sni.test")
        );

        opts.server_name = Some("sni.test".into());
        let (conn, server) = dial(
            opts,
            ca.trust(),
            &leaf,
            &ServerSpec::default(),
            "198.51.100.1",
        )
        .await;
        echo(&mut conn.unwrap(), b"x").await;
        assert_eq!(
            server.await.unwrap().unwrap().sni.as_deref(),
            Some("sni.test")
        );
    }
}

#[tokio::test]
async fn ip_targets_send_no_sni_and_match_ip_sans() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["203.0.113.9", "2001:db8::9"]);
    for fp in BACKENDS {
        for target in ["203.0.113.9", "[2001:db8::9]"] {
            let opts = TlsOptions {
                client_fingerprint: fp,
                ..TlsOptions::default()
            };
            let (conn, server) =
                dial(opts, ca.trust(), &leaf, &ServerSpec::default(), target).await;
            echo(
                &mut conn.unwrap_or_else(|err| panic!("{fp:?} {target}: {err}")),
                b"x",
            )
            .await;
            let seen = server.await.unwrap().unwrap();
            assert_eq!(seen.sni, None, "{fp:?} {target}");
        }
    }
}

#[tokio::test]
async fn an_empty_server_name_with_no_fallback_is_an_error() {
    let ca = Ca::new();
    let connector = TlsConnector::new(TlsOptions::default(), ca.trust()).unwrap();
    let (client, _server) =
        echo_server(server_config(&ca.leaf(&["a.test"]), &ServerSpec::default()));
    let err = connector.connect(client, "").await.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn client_certificates_reach_the_server() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let client = rcgen::generate_simple_self_signed(vec!["client.test".to_owned()]).unwrap();
    let spec = ServerSpec {
        request_client_cert: true,
        ..ServerSpec::default()
    };
    for fp in BACKENDS {
        let mut opts = options(fp, "node.test");
        opts.certificate = Some(client.cert.pem());
        opts.private_key = Some(client.signing_key.serialize_pem());
        let (conn, server) = dial(opts, ca.trust(), &leaf, &spec, "").await;
        let mut conn = conn.unwrap();
        echo(&mut conn, b"mtls").await;
        drop(conn);
        let seen = server.await.unwrap().unwrap();
        assert_eq!(
            seen.client_cert.as_deref(),
            Some(client.cert.der().as_ref()),
            "{fp:?}"
        );
    }
}

#[tokio::test]
async fn tls12_servers_work_and_report_their_version() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let config = {
        let provider = crate::policy::provider();
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(leaf.chain.clone(), leaf.key())
            .unwrap();
        Arc::new(config)
    };
    for fp in BACKENDS {
        let connector = TlsConnector::new(options(fp, "node.test"), ca.trust()).unwrap();
        let (client, _server) = echo_server(config.clone());
        let mut conn = connector.connect(client, "").await.unwrap();
        assert!(!conn.is_tls13(), "{fp:?}");
        echo(&mut conn, b"twelve").await;
    }
}

#[tokio::test]
async fn quic_and_http_configs_share_the_policy() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let name = rustls_pki_types::ServerName::try_from("node.test").unwrap();

    let quic = crate::quic_client_config(&options(None, "node.test"), ca.trust(), &["h3"]).unwrap();
    assert_eq!(quic.alpn_protocols, vec![b"h3".to_vec()]);
    let tls12 = {
        let mut config = rustls::ServerConfig::builder_with_provider(crate::policy::provider())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(leaf.chain.clone(), leaf.key())
            .unwrap();
        config.alpn_protocols = vec![b"h3".to_vec()];
        Arc::new(config)
    };
    let (client, _s) = tokio::io::duplex(1 << 16);
    let (far, near) = tokio::io::duplex(1 << 16);
    drop(client);
    tokio::spawn(async move {
        let _ = tokio_rustls::TlsAcceptor::from(tls12).accept(far).await;
    });
    let refused = tokio_rustls::TlsConnector::from(quic.clone())
        .connect(name.clone(), near)
        .await;
    assert!(refused.is_err());

    let http = crate::http_client_config(ca.trust(), false, &["http/1.1"]).unwrap();
    assert_eq!(http.alpn_protocols, vec![b"http/1.1".to_vec()]);
    let (far, near) = tokio::io::duplex(1 << 16);
    let config = server_config(&leaf, &ServerSpec::default());
    tokio::spawn(async move {
        let _ = tokio_rustls::TlsAcceptor::from(config).accept(far).await;
    });
    tokio_rustls::TlsConnector::from(http)
        .connect(name.clone(), near)
        .await
        .unwrap();

    let stranger = Ca::new().leaf(&["node.test"]);
    for (skip, expect_ok) in [(false, false), (true, true)] {
        let http = crate::http_client_config(ca.trust(), skip, &[]).unwrap();
        let (far, near) = tokio::io::duplex(1 << 16);
        let config = server_config(&stranger, &ServerSpec::default());
        tokio::spawn(async move {
            let _ = tokio_rustls::TlsAcceptor::from(config).accept(far).await;
        });
        let result = tokio_rustls::TlsConnector::from(http)
            .connect(name.clone(), near)
            .await;
        assert_eq!(result.is_ok(), expect_ok, "skip={skip}");
    }
}

#[tokio::test]
async fn a_peer_that_is_not_tls_fails_cleanly() {
    let ca = Ca::new();
    for fp in BACKENDS {
        let connector = TlsConnector::new(options(fp, "node.test"), ca.trust()).unwrap();
        let (client, mut server) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut sink = [0u8; 4096];
            let _ = server.read(&mut sink).await;
            let _ = server.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            let _ = server.shutdown().await;
        });
        assert!(
            connector.connect(Box::new(client), "").await.is_err(),
            "{fp:?}"
        );
    }
}

#[tokio::test]
async fn a_certificate_message_near_the_rustls_limit_completes_on_every_backend() {
    let ca = Ca::new();
    let names: Vec<String> = (0..3300).map(|n| format!("n{n:05}.node.test")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let leaf = ca.leaf(&names);
    let size: usize = leaf.chain.iter().map(|cert| cert.as_ref().len()).sum();
    assert!((56 * 1024..0xffff - 1024).contains(&size), "{size}");
    for fp in BACKENDS {
        let (conn, _server) = dial(
            options(fp, "n00000.node.test"),
            ca.trust(),
            &leaf,
            &ServerSpec::default(),
            "ignored",
        )
        .await;
        echo(&mut conn.unwrap(), b"ping").await;
    }
}
