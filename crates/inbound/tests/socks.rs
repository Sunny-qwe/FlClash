mod common;

use common::*;
use concord_common::{Address, InboundKind, Network};
use concord_inbound::{ListenSpec, ListenerKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn with_auth(mut spec: ListenSpec) -> ListenSpec {
    spec.authentication = vec![("alice".into(), "secret".into())];
    spec
}

#[tokio::test]
async fn socks5_connect_reaches_the_handler_and_relays_both_ways() {
    let run = start(mixed(), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    let mut stream = socks5_session(addr, "example.com", 443).await;
    stream.write_all(b"ping").await.unwrap();
    assert_eq!(read_exact(&mut stream, 4).await, b"ping");

    let meta = run.fake.flow(0);
    assert_eq!(meta.network, Network::Tcp);
    assert_eq!(meta.inbound.kind, InboundKind::Socks5);
    assert_eq!(&*meta.inbound.name, "DEFAULT-MIXED");
    assert_eq!(meta.inbound.user, None);
    assert_eq!(meta.inbound.addr, Some(addr));
    assert_eq!(meta.src, stream.local_addr().unwrap());
    assert_eq!(meta.dst, Address::new("example.com", 443));
}

#[tokio::test]
async fn socks5_payload_sent_with_the_request_reaches_the_handler() {
    let run = start(mixed(), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    let mut stream = connect(addr).await;
    stream.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, [5, 0]);
    let mut request = socks5_connect_domain("example.com", 443);
    request.extend_from_slice(b"early");
    stream.write_all(&request).await.unwrap();
    let reply = read_exact(&mut stream, 10).await;
    assert_eq!(reply.get(..4), Some(&[5, 0, 0, 1][..]));
    assert_eq!(read_exact(&mut stream, 5).await, b"early");
}

#[tokio::test]
async fn socks5_trims_a_trailing_dot_and_unmaps_ipv6_literals() {
    let run = start(mixed(), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    drop(socks5_session(addr, "example.com.", 80).await);
    let mut stream = connect(addr).await;
    stream.write_all(&[5, 1, 0]).await.unwrap();
    read_exact(&mut stream, 2).await;
    let mut request = vec![5, 1, 0, 4];
    request.extend_from_slice(
        &"::ffff:10.1.2.3"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    request.extend_from_slice(&[0, 53]);
    stream.write_all(&request).await.unwrap();
    read_exact(&mut stream, 10).await;
    wait_for(|| run.fake.flow_count() == 2).await;
    assert_eq!(run.fake.flow(0).dst, Address::new("example.com", 80));
    assert_eq!(run.fake.flow(1).dst, Address::new("10.1.2.3", 53));
}

#[tokio::test]
async fn socks5_password_auth_accepts_and_records_the_user() {
    let run = start(with_auth(mixed()), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    let mut stream = connect(addr).await;
    stream.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, [5, 2]);
    let mut auth = vec![1, 5];
    auth.extend_from_slice(b"alice");
    auth.push(6);
    auth.extend_from_slice(b"secret");
    stream.write_all(&auth).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, [1, 0]);
    stream
        .write_all(&socks5_connect_domain("a.test", 80))
        .await
        .unwrap();
    read_exact(&mut stream, 10).await;
    stream.write_all(b"x").await.unwrap();
    assert_eq!(read_exact(&mut stream, 1).await, b"x");
    assert_eq!(run.fake.flow(0).inbound.user.as_deref(), Some("alice"));
}

#[tokio::test]
async fn socks5_wrong_password_is_refused_and_never_reaches_the_handler() {
    let run = start(with_auth(mixed()), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    let mut stream = connect(addr).await;
    stream.write_all(&[5, 1, 2]).await.unwrap();
    read_exact(&mut stream, 2).await;
    let mut auth = vec![1, 5];
    auth.extend_from_slice(b"alice");
    auth.push(3);
    auth.extend_from_slice(b"bad");
    stream.write_all(&auth).await.unwrap();
    assert_eq!(read_exact(&mut stream, 2).await, [1, 1]);
    assert!(read_to_close(&mut stream).await.is_empty());
    assert_eq!(run.fake.flow_count(), 0);
}

#[tokio::test]
async fn socks5_bind_is_closed_without_a_reply() {
    let run = start(mixed(), Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Mixed).await).await;
    stream.write_all(&[5, 1, 0]).await.unwrap();
    read_exact(&mut stream, 2).await;
    stream
        .write_all(&[5, 2, 0, 1, 1, 2, 3, 4, 0, 80])
        .await
        .unwrap();
    assert!(read_to_close(&mut stream).await.is_empty());
    assert_eq!(run.fake.flow_count(), 0);
}

#[tokio::test]
async fn socks4_and_4a_connect_on_the_socks_listener() {
    let spec = ListenSpec {
        socks_port: Some(0),
        ..Default::default()
    };
    let run = start(spec, Fake::echo()).await;
    let addr = run.addr(ListenerKind::Socks).await;

    let mut four = connect(addr).await;
    four.write_all(&[4, 1, 0x01, 0xbb, 1, 2, 3, 4, b'u', 0])
        .await
        .unwrap();
    assert_eq!(read_exact(&mut four, 8).await, [0, 90, 1, 0xbb, 1, 2, 3, 4]);
    four.write_all(b"hi").await.unwrap();
    assert_eq!(read_exact(&mut four, 2).await, b"hi");

    let mut four_a = connect(addr).await;
    let mut request = vec![4, 1, 0, 80, 0, 0, 0, 1, 0];
    request.extend_from_slice(b"host.test\0");
    four_a.write_all(&request).await.unwrap();
    assert_eq!(read_exact(&mut four_a, 8).await, [0, 90, 0, 80, 0, 0, 0, 1]);
    four_a.write_all(b"yo").await.unwrap();
    assert_eq!(read_exact(&mut four_a, 2).await, b"yo");

    let first = run.fake.flow(0);
    assert_eq!(first.inbound.kind, InboundKind::Socks4);
    assert_eq!(&*first.inbound.name, "DEFAULT-SOCKS");
    assert_eq!(first.inbound.user.as_deref(), Some("u"));
    assert_eq!(first.dst, Address::new("1.2.3.4", 443));
    assert_eq!(run.fake.flow(1).dst, Address::new("host.test", 80));
}

#[tokio::test]
async fn socks4_with_auth_configured_replies_93() {
    let spec = ListenSpec {
        socks_port: Some(0),
        ..with_auth(Default::default())
    };
    let run = start(spec, Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Socks).await).await;
    stream
        .write_all(&[4, 1, 0, 80, 1, 2, 3, 4, b'a', 0])
        .await
        .unwrap();
    assert_eq!(read_exact(&mut stream, 8).await, [0, 93, 0, 80, 1, 2, 3, 4]);
    assert_eq!(run.fake.flow_count(), 0);
}

#[tokio::test]
async fn the_socks_listener_drops_anything_that_is_not_socks() {
    let spec = ListenSpec {
        socks_port: Some(0),
        ..Default::default()
    };
    let run = start(spec, Fake::echo()).await;
    let mut stream = connect(run.addr(ListenerKind::Socks).await).await;
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert!(read_to_close(&mut stream).await.is_empty());
}

#[tokio::test]
async fn a_malformed_client_kills_only_its_own_connection() {
    let run = start(mixed(), Fake::echo()).await;
    let addr = run.addr(ListenerKind::Mixed).await;
    let mut bad = connect(addr).await;
    bad.write_all(&[5, 255]).await.unwrap();
    bad.shutdown().await.unwrap();
    let mut buf = Vec::new();
    bad.read_to_end(&mut buf).await.ok();
    let mut good = socks5_session(addr, "ok.test", 80).await;
    good.write_all(b"ok").await.unwrap();
    assert_eq!(read_exact(&mut good, 2).await, b"ok");
}

#[tokio::test]
async fn the_mixed_port_detects_socks4_socks5_connect_and_plain_http() {
    let fake = Fake::new(|meta, stream| {
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(stream);
            if meta.inbound.kind == InboundKind::Http {
                let mut buf = [0u8; 1024];
                let _ = rd.read(&mut buf).await;
                let _ = wr
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = rd.read(&mut buf).await;
            } else {
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            }
        });
    });
    let run = start(mixed(), fake).await;
    let addr = run.addr(ListenerKind::Mixed).await;

    let mut four = connect(addr).await;
    four.write_all(&[4, 1, 0, 80, 1, 2, 3, 4, 0]).await.unwrap();
    read_exact(&mut four, 8).await;
    let mut five = socks5_session(addr, "five.test", 80).await;
    five.write_all(b"5").await.unwrap();
    read_exact(&mut five, 1).await;

    let mut connect_request = connect(addr).await;
    connect_request
        .write_all(b"CONNECT https.test:443 HTTP/1.1\r\nHost: https.test:443\r\n\r\n")
        .await
        .unwrap();
    read_until(&mut connect_request, b"\r\n\r\n").await;

    let mut plain = connect(addr).await;
    plain
        .write_all(b"GET http://plain.test/ HTTP/1.1\r\nHost: plain.test\r\nProxy-Connection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    read_until(&mut plain, b"\r\n\r\n").await;

    wait_for(|| run.fake.flow_count() == 4).await;
    let mut kinds: Vec<_> = (0..4).map(|i| run.fake.flow(i).inbound.kind).collect();
    kinds.sort_by_key(|kind| kind.wire_name());
    assert_eq!(
        kinds,
        [
            InboundKind::Http,
            InboundKind::Https,
            InboundKind::Socks4,
            InboundKind::Socks5
        ]
    );
    for index in 0..4 {
        assert_eq!(&*run.fake.flow(index).inbound.name, "DEFAULT-MIXED");
    }
}
