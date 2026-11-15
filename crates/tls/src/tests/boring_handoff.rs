use std::io::{Read, Write};
use std::net::TcpStream as StdTcp;
use std::sync::Arc;

use boring::pkey::PKey;
use boring::ssl::{SslAcceptor, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use boring::x509::X509;
use concord_common::{BoxRead, BoxStream, BoxWrite};
use concord_test_support::tcp_pair;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::support::{Ca, Leaf};
use crate::{ClientFingerprint, TlsConn, TlsConnector, TlsOptions};

fn connector(ca: &Ca, fingerprint: ClientFingerprint) -> TlsConnector {
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        client_fingerprint: Some(fingerprint),
        ..TlsOptions::default()
    };
    TlsConnector::new(options, ca.trust()).unwrap()
}

fn chunk() -> Vec<u8> {
    (0..1500u32).map(|i| (i % 251) as u8).collect()
}

async fn send(mut write: impl AsyncWrite + Unpin, total: usize) {
    let chunk = chunk();
    let mut left = total;
    while left > 0 {
        let n = left.min(chunk.len());
        write.write_all(&chunk[..n]).await.unwrap();
        left -= n;
    }
    write.shutdown().await.unwrap();
}

async fn drain(mut read: impl AsyncRead + Unpin) -> usize {
    let mut total = 0;
    let mut buf = vec![0u8; 7000];
    loop {
        let n = read.read(&mut buf).await.unwrap();
        if n == 0 {
            return total;
        }
        assert!(
            buf[..n]
                .iter()
                .enumerate()
                .all(|(i, b)| usize::from(*b) == (total + i) % 1500 % 251)
        );
        total += n;
    }
}

fn split(conn: TlsConn) -> (BoxRead, BoxWrite) {
    (Box::new(conn) as BoxStream).into_split()
}

fn rustls_server(leaf: &Leaf, suite: rustls::SupportedCipherSuite) -> Arc<ServerConfig> {
    let version = match suite {
        rustls::SupportedCipherSuite::Tls13(_) => &rustls::version::TLS13,
        rustls::SupportedCipherSuite::Tls12(_) => &rustls::version::TLS12,
    };
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![suite],
        ..(*crate::policy::provider()).clone()
    };
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(leaf.chain.clone(), leaf.key())
        .unwrap();
    Arc::new(config)
}

/// A fingerprinted handshake leaves BoringSSL for the record layer with the keylogged TLS 1.3
/// secrets or the TLS 1.2 key block, and the record layer then follows the server's
/// KeyUpdates and drops its session tickets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn boring_aead_suites_continue_on_the_record_layer() {
    use rustls::crypto::aws_lc_rs::cipher_suite as cs;
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let connector = connector(&ca, ClientFingerprint::Chrome);
    for suite in [
        cs::TLS13_AES_128_GCM_SHA256,
        cs::TLS13_AES_256_GCM_SHA384,
        cs::TLS13_CHACHA20_POLY1305_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ] {
        let acceptor = tokio_rustls::TlsAcceptor::from(rustls_server(&leaf, suite));
        let (client, server) = tcp_pair().await;
        let (conn, server) = tokio::join!(
            connector.connect(Box::new(client), "node.test"),
            acceptor.accept(server)
        );
        let conn = conn.unwrap();
        let mut server = server.unwrap();
        assert!(matches!(conn, TlsConn::Record(_)), "{suite:?}");
        let tls13 = conn.is_tls13();
        let (read, write) = split(conn);

        let reader = tokio::spawn(drain(read));
        let chunk = chunk();
        for _ in 0..3 {
            for _ in 0..200 {
                server.write_all(&chunk).await.unwrap();
            }
            if tls13 {
                server.get_mut().1.refresh_traffic_keys().unwrap();
            }
            server.flush().await.unwrap();
        }
        server.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), 3 * 200 * 1500, "{suite:?}");
        let total = 1 << 20;
        let writer = tokio::spawn(send(write, total));
        assert_eq!(drain(&mut server).await, total, "{suite:?}");
        writer.await.unwrap();
    }
}

fn rsa_identity() -> (X509, PKey<boring::pkey::Private>) {
    let key = PKey::from_rsa(boring::rsa::Rsa::generate(2048).unwrap()).unwrap();
    let mut name = boring::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "node.test").unwrap();
    let name = name.build();
    let mut cert = boring::x509::X509Builder::new().unwrap();
    cert.set_version(2).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&boring::asn1::Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&boring::asn1::Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, boring::hash::MessageDigest::sha256())
        .unwrap();
    (cert.build(), key)
}

/// No record layer here serves CBC, so such a handshake keeps BoringSSL's stream. Every
/// fingerprint BoringSSL builds is Chrome's, whose only CBC suites use RSA.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_boring_cbc_suite_keeps_boringssl_and_still_splits() {
    let (cert, key) = rsa_identity();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    builder.set_certificate(&cert).unwrap();
    builder.set_private_key(&key).unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    builder.set_cipher_list("ECDHE-RSA-AES128-SHA").unwrap();
    let acceptor = builder.build();

    let options = TlsOptions {
        server_name: Some("node.test".into()),
        client_fingerprint: Some(ClientFingerprint::Chrome),
        skip_cert_verify: true,
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, Ca::new().trust()).unwrap();
    let (client, server) = tcp_pair().await;
    let (conn, server) = tokio::join!(
        connector.connect(Box::new(client), "node.test"),
        tokio_boring::accept(&acceptor, server)
    );
    let server = server.unwrap_or_else(|err| panic!("boring accept failed: {err}"));
    let conn = conn.unwrap();
    assert_eq!(server.ssl().current_cipher().unwrap().protocol_id(), 0xc013);
    assert!(matches!(conn, TlsConn::Boring(_)));
    let (read, write) = split(conn);
    let (server_read, server_write) = tokio::io::split(server);
    let total = 1 << 20;
    let (_, _, client_got, server_got) = tokio::join!(
        tokio::spawn(send(write, total)),
        tokio::spawn(send(server_write, total)),
        tokio::spawn(drain(read)),
        tokio::spawn(drain(server_read)),
    );
    assert_eq!(client_got.unwrap(), total);
    assert_eq!(server_got.unwrap(), total);
}

fn boring_pair(version: SslVersion, ciphers: &str) -> (SslStream<StdTcp>, SslStream<StdTcp>) {
    let (cert, key) = rsa_identity();
    let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    server.set_certificate(&cert).unwrap();
    server.set_private_key(&key).unwrap();
    let mut client = SslConnector::builder(SslMethod::tls()).unwrap();
    client.set_verify(SslVerifyMode::NONE);
    for builder in [&mut *server, &mut *client] {
        builder.set_min_proto_version(Some(version)).unwrap();
        builder.set_max_proto_version(Some(version)).unwrap();
        builder.set_cipher_list(ciphers).unwrap();
    }
    let (acceptor, connector) = (server.build(), client.build());
    let (near, far) = concord_test_support::std_tcp_pair();
    let server = std::thread::spawn(move || acceptor.accept(far).unwrap());
    let client = connector.connect("node.test", near).unwrap();
    (client, server.join().unwrap())
}

fn records(from: &mut SslStream<StdTcp>, to: &mut SslStream<StdTcp>, count: u64) {
    for index in 0..count {
        from.write_all(&[u8::try_from(index).unwrap(); 100])
            .unwrap();
    }
    let mut got = vec![0; usize::try_from(count).unwrap() * 100];
    to.read_exact(&mut got).unwrap();
}

#[test]
fn record_sequences_count_the_records_each_side_sent_and_read() {
    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let (mut client, mut server) = boring_pair(version, "ECDHE-RSA-AES128-GCM-SHA256");
        // A TLS 1.3 server sends its session tickets with its first write; let them pass first.
        records(&mut server, &mut client, 1);
        let client_wrote = client.ssl().write_sequence();
        let server_wrote = server.ssl().write_sequence();
        records(&mut client, &mut server, 5);
        records(&mut server, &mut client, 3);
        assert_eq!(
            client.ssl().write_sequence() - client_wrote,
            5,
            "{version:?}"
        );
        assert_eq!(
            server.ssl().write_sequence() - server_wrote,
            3,
            "{version:?}"
        );
        assert_eq!(
            server.ssl().read_sequence(),
            client.ssl().write_sequence(),
            "{version:?}"
        );
        assert_eq!(
            client.ssl().read_sequence(),
            server.ssl().write_sequence(),
            "{version:?}"
        );
        for ssl in [client.ssl(), server.ssl()] {
            assert!(!ssl.has_pending(), "{version:?}");
            assert!(ssl.shutdown_state().is_empty(), "{version:?}");
        }
    }
}

/// Two copies of the MAC key, write key and fixed IV, as the suite sizes them.
#[test]
fn a_tls12_key_block_is_sized_by_its_suite_and_shared_by_both_ends() {
    for (suite, len) in [
        ("ECDHE-RSA-AES128-GCM-SHA256", 2 * (16 + 4)),
        ("ECDHE-RSA-AES256-GCM-SHA384", 2 * (32 + 4)),
        ("ECDHE-RSA-CHACHA20-POLY1305", 2 * (32 + 12)),
    ] {
        let (client, server) = boring_pair(SslVersion::TLS1_2, suite);
        let block = client.ssl().key_block().unwrap();
        assert_eq!(block.len(), len, "{suite}");
        assert_eq!(server.ssl().key_block().unwrap(), block, "{suite}");
    }
}
