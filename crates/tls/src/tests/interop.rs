//! Manual interop against mihomo's own REALITY server (`utls.RealityServer`).
//! Start the Go harness, then run with `CONCORD_REALITY_INFO` pointing at the
//! `reality-info.json` it writes.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::fingerprints::ClientFingerprint;
use crate::{RealityOptions, TlsConnector, TlsOptions, TrustStore};

struct Info {
    addr: String,
    public_key: String,
    short_id: String,
    sni: String,
    dest_cert: String,
}

fn field(json: &str, key: &str) -> String {
    let marker = format!("\"{key}\":\"");
    let start = json.find(&marker).unwrap() + marker.len();
    let end = json[start..].find('"').unwrap();
    json[start..start + end].to_owned()
}

fn info() -> Info {
    let path = std::env::var_os("CONCORD_REALITY_INFO").expect("CONCORD_REALITY_INFO is not set");
    let json = std::fs::read_to_string(path).unwrap();
    Info {
        addr: field(&json, "addr"),
        public_key: field(&json, "public_key"),
        short_id: field(&json, "short_id"),
        sni: field(&json, "sni"),
        dest_cert: field(&json, "dest_cert"),
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "loopback interop against the Go harness"
)]
async fn tcp(addr: &str) -> concord_common::BoxStream {
    Box::new(tokio::net::TcpStream::connect(addr).await.unwrap())
}

fn connector(
    info: &Info,
    fp: ClientFingerprint,
    mlkem: bool,
    short_id: Option<&str>,
) -> TlsConnector {
    let reality =
        RealityOptions::parse(&info.public_key, short_id.unwrap_or(&info.short_id), mlkem).unwrap();
    TlsConnector::new(
        TlsOptions {
            server_name: Some(info.sni.clone()),
            client_fingerprint: Some(fp),
            reality: Some(reality),
            ..TlsOptions::default()
        },
        TrustStore::from_parts(Vec::new(), b"", Vec::new()),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "needs the Go REALITY harness"]
async fn go_reality_server_accepts_every_fingerprint() {
    let info = info();
    let payload: Vec<u8> = (0..1_500_000u32).map(|i| (i % 251) as u8).collect();
    let combos = [
        (ClientFingerprint::Chrome, true),
        (ClientFingerprint::Chrome, false),
        (ClientFingerprint::Chrome120, false),
        (ClientFingerprint::Firefox, false),
        (ClientFingerprint::Firefox120, false),
        (ClientFingerprint::Safari, false),
        (ClientFingerprint::Safari16, false),
        (ClientFingerprint::Ios, false),
        (ClientFingerprint::Edge, false),
        (ClientFingerprint::Qq, false),
        (ClientFingerprint::Android, false),
        (ClientFingerprint::Random, true),
    ];
    for (fp, mlkem) in combos {
        let conn = connector(&info, fp, mlkem, None);
        let mut stream = conn
            .connect(tcp(&info.addr).await, "ignored")
            .await
            .unwrap_or_else(|err| panic!("{fp} mlkem={mlkem}: {err}"));
        if let crate::TlsConn::Reality(inner) = &stream {
            eprintln!(
                "{fp} mlkem={mlkem} group={:04x}",
                inner.key_exchange_group()
            );
        }
        let (mut reader, mut writer) = tokio::io::split(&mut stream);
        let send = payload.clone();
        let writing = async move {
            for chunk in send.chunks(40_000) {
                writer.write_all(chunk).await.unwrap();
            }
            writer.flush().await.unwrap();
        };
        let reading = async {
            let mut got = vec![0u8; payload.len()];
            reader.read_exact(&mut got).await.unwrap();
            got
        };
        let (_, got) = tokio::join!(writing, reading);
        assert_eq!(got, payload, "{fp} mlkem={mlkem}");
        eprintln!("interop ok: {fp} mlkem={mlkem}");
    }
}

#[tokio::test]
#[ignore = "needs the Go REALITY harness"]
async fn go_reality_server_refuses_what_it_should() {
    let info = info();
    let wrong_short = connector(&info, ClientFingerprint::Chrome, true, Some("0000"));
    let err = wrong_short
        .connect(tcp(&info.addr).await, "")
        .await
        .err()
        .unwrap();
    eprintln!("wrong short id: {err}");

    let mut other_key = RealityOptions::parse(&info.public_key, &info.short_id, true).unwrap();
    other_key.public_key[0] ^= 1;
    let connector = TlsConnector::new(
        TlsOptions {
            server_name: Some(info.sni.clone()),
            client_fingerprint: Some(ClientFingerprint::Chrome),
            reality: Some(other_key),
            ..TlsOptions::default()
        },
        TrustStore::from_parts(Vec::new(), b"", Vec::new()),
    )
    .unwrap();
    let err = connector
        .connect(tcp(&info.addr).await, "")
        .await
        .err()
        .unwrap();
    eprintln!("wrong public key: {err}");
}

#[tokio::test]
#[ignore = "needs the Go REALITY harness"]
async fn go_cover_site_gets_a_spider_visit() {
    let info = info();
    let pem = std::fs::read_to_string(&info.dest_cert).unwrap();
    let trust = TrustStore::from_parts(Vec::new(), b"", crate::parse_certificates(&pem));
    let reality = RealityOptions::parse(&info.public_key, "0000", true).unwrap();
    let connector = TlsConnector::new(
        TlsOptions {
            server_name: Some(info.sni.clone()),
            client_fingerprint: Some(ClientFingerprint::Chrome),
            reality: Some(reality),
            ..TlsOptions::default()
        },
        trust,
    )
    .unwrap();
    let err = connector
        .connect(tcp(&info.addr).await, "")
        .await
        .err()
        .unwrap();
    assert!(
        err.to_string().contains("REALITY authentication failed"),
        "{err}"
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}
