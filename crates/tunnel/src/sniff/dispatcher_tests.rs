use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::sync::lock;
use tokio::io::{AsyncWriteExt, ReadBuf};

use super::*;
use crate::sniff::testdata::{QUIC_GOOGLE, QUIC_NGINX};
use crate::sniff::testkit::{
    IpFn, MatchFn, Meta, Seen, always, make_client_hello, make_tls_records,
};

enum End {
    Eof,
    Error,
    Stall,
}

/// Hands out one chunk per read, so a sniffer only sees the bytes that have
/// "arrived", like a request spanning several TCP segments.
struct ChunkedReader {
    chunks: VecDeque<Vec<u8>>,
    end: End,
}

impl ChunkedReader {
    fn new(chunks: &[&[u8]]) -> Self {
        ChunkedReader {
            chunks: chunks.iter().map(|c| c.to_vec()).collect(),
            end: End::Eof,
        }
    }

    fn ending(mut self, end: End) -> Self {
        self.end = end;
        self
    }
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(mut chunk) = self.chunks.pop_front() {
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            if n < chunk.len() {
                let rest = chunk.split_off(n);
                self.chunks.push_front(rest);
            }
            return Poll::Ready(Ok(()));
        }
        match self.end {
            End::Eof => Poll::Ready(Ok(())),
            End::Error => Poll::Ready(Err(io::Error::other("reset"))),
            End::Stall => Poll::Pending,
        }
    }
}

type Reply = Box<dyn Fn(&[u8]) -> Result<String, SniffError> + Send + Sync>;

/// Records the size of every buffer it is handed and replies from a script, so
/// the feeding loop is tested without a real protocol.
struct Stub {
    seen: Seen,
    reply: Reply,
}

impl DataSniffer for Stub {
    fn sniff(&self, data: &[u8]) -> Result<String, SniffError> {
        lock(&self.seen).push(data.len());
        (self.reply)(data)
    }
}

fn stub(
    reply: impl Fn(&[u8]) -> Result<String, SniffError> + Send + Sync + 'static,
) -> (Stub, Seen) {
    let seen = Seen::default();
    (
        Stub {
            seen: seen.clone(),
            reply: Box::new(reply),
        },
        seen,
    )
}

fn need(n: usize) -> Result<String, SniffError> {
    Err(SniffError::NeedAtLeast(n))
}

fn with_stubs(mut dispatcher: Dispatcher, stubs: Vec<(Stub, bool)>) -> Dispatcher {
    dispatcher.sniffers = stubs
        .into_iter()
        .map(|(stub, override_dest)| Configured {
            ports: vec![(0, u16::MAX)],
            override_dest,
            transport: Transport::Stream(Box::new(stub)),
        })
        .collect();
    dispatcher
}

fn plain() -> Dispatcher {
    Dispatcher::new(DispatcherConfig::default())
}

fn pure_ip() -> Dispatcher {
    Dispatcher::new(DispatcherConfig {
        enable: true,
        parse_pure_ip: true,
        ..Default::default()
    })
}

fn entry(kind: SnifferKind, override_dest: bool) -> SnifferEntry {
    SnifferEntry {
        kind,
        ports: Vec::new(),
        override_dest,
    }
}

fn real(entries: Vec<SnifferEntry>) -> Dispatcher {
    Dispatcher::new(DispatcherConfig {
        enable: true,
        sniffers: entries,
        parse_pure_ip: true,
        ..Default::default()
    })
}

const SEGMENT: &[u8] = b"0123456789";

fn failures(dispatcher: &Dispatcher, meta: &Meta) -> Option<u8> {
    dispatcher.skip_list().get(&(meta.dst_ip, meta.dst_port))
}

struct Case {
    name: &'static str,
    chunks: Vec<Vec<u8>>,
    reply: fn(&[u8]) -> Result<String, SniffError>,
    host: Option<&'static str>,
    error: Option<SniffError>,
    seen: Vec<usize>,
    chunks_left: usize,
    buffered: usize,
}

fn success_at(sizes: &'static [usize], data: &[u8]) -> Result<String, SniffError> {
    for &want in sizes {
        if data.len() < want {
            return need(want);
        }
    }
    Ok("example.com".into())
}

#[tokio::test(start_paused = true)]
async fn feed_loop() {
    let big = vec![b'x'; 5000 - SEGMENT.len()];
    let cases = vec![
        Case {
            name: "retries until the sniffer reaches a verdict",
            chunks: vec![SEGMENT.to_vec(); 3],
            reply: |d| success_at(&[20, 30], d),
            host: Some("example.com"),
            error: None,
            seen: vec![10, 20, 30],
            chunks_left: 0,
            buffered: 30,
        },
        Case {
            name: "grows the read for a large request",
            chunks: vec![SEGMENT.to_vec(), big],
            reply: |d| success_at(&[5000], d),
            host: Some("example.com"),
            error: None,
            seen: vec![10, 5000],
            chunks_left: 0,
            buffered: 5000,
        },
        Case {
            name: "hands over all buffered data, not just the extra byte",
            chunks: vec![SEGMENT.to_vec(); 3],
            reply: |d| {
                if d.len() < 30 {
                    return need(d.len() + 1);
                }
                Ok("example.com".into())
            },
            host: Some("example.com"),
            error: None,
            seen: vec![10, 20, 30],
            chunks_left: 0,
            buffered: 30,
        },
        Case {
            name: "stops when the request cannot grow",
            chunks: vec![SEGMENT.to_vec(); 3],
            reply: |d| need(d.len()),
            host: None,
            error: Some(SniffError::AllFailed),
            seen: vec![10],
            chunks_left: 2,
            buffered: 10,
        },
        Case {
            name: "stops when the request exceeds the read limit",
            chunks: vec![SEGMENT.to_vec(); 3],
            reply: |_| need(1 << 20),
            host: None,
            error: Some(SniffError::BufferFull),
            seen: vec![10],
            chunks_left: 2,
            buffered: 10,
        },
        Case {
            name: "gives up when the data never completes",
            chunks: vec![SEGMENT.to_vec()],
            reply: |d| need(d.len() + 1),
            host: None,
            error: Some(SniffError::Read),
            seen: vec![10],
            chunks_left: 0,
            buffered: 10,
        },
    ];

    for case in cases {
        let (stub, seen) = stub(case.reply);
        let dispatcher = with_stubs(plain(), vec![(stub, true)]);
        let mut reader = ChunkedReader {
            chunks: case.chunks.into(),
            end: End::Eof,
        };
        let mut head = Vec::new();
        let start = Instant::now();

        let result = dispatcher.sniff_domain(&mut reader, &mut head, 80).await;

        match (case.host, case.error) {
            (Some(host), _) => assert_eq!(result, Ok((host.to_string(), true)), "{}", case.name),
            (None, Some(error)) => assert_eq!(result, Err(error), "{}", case.name),
            (None, None) => unreachable!(),
        }
        assert_eq!(*lock(&seen), case.seen, "{}", case.name);
        assert_eq!(reader.chunks.len(), case.chunks_left, "{}", case.name);
        assert_eq!(head.len(), case.buffered, "{}", case.name);
        assert_eq!(start.elapsed(), Duration::ZERO, "{} waited", case.name);
    }
}

#[tokio::test(start_paused = true)]
async fn successful_sniffer_policy_applies_before_reading_more() {
    let (waiting, waiting_seen) = stub(|d| need(d.len() + 1));
    let (successful, successful_seen) = stub(|_| Ok("example.com".into()));
    let dispatcher = with_stubs(pure_ip(), vec![(waiting, false), (successful, true)]);
    let mut reader = ChunkedReader::new(&[SEGMENT, SEGMENT]);
    let mut meta = Meta::new(80);
    let mut head = Vec::new();

    let sniffed = dispatcher
        .sniff_tcp(&mut reader, &mut head, &mut meta.target())
        .await;

    assert!(sniffed);
    assert_eq!(meta.sniff_host.as_deref(), Some("example.com"));
    assert_eq!(meta.host.as_deref(), Some("example.com"));
    assert_eq!(meta.dst_ip, None);
    assert_eq!(meta.dns_mode, Some(DnsMode::Normal));
    assert_eq!(*lock(&waiting_seen), vec![10]);
    assert_eq!(*lock(&successful_seen), vec![10]);
    assert_eq!(reader.chunks.len(), 1);
    assert_eq!(head, SEGMENT);
}

#[tokio::test(start_paused = true)]
async fn without_override_dest_only_the_sniff_host_is_set() {
    let (found, _) = stub(|_| Ok("example.com".into()));
    let dispatcher = with_stubs(pure_ip(), vec![(found, false)]);
    let mut reader = ChunkedReader::new(&[SEGMENT]);
    let mut meta = Meta::new(80);
    let mut head = Vec::new();

    assert!(
        dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(meta.sniff_host.as_deref(), Some("example.com"));
    assert_eq!(meta.host, None);
    assert!(meta.dst_ip.is_some());
}

#[tokio::test(start_paused = true)]
async fn reads_the_smallest_candidate_request_next() {
    let (slow, slow_seen) = stub(|d| {
        if d.len() < 30 {
            return need(30);
        }
        Ok("slow.example.com".into())
    });
    let (fast, fast_seen) = stub(|d| {
        if d.len() < 20 {
            return need(20);
        }
        Ok("fast.example.com".into())
    });
    let dispatcher = with_stubs(plain(), vec![(slow, false), (fast, false)]);
    let mut reader = ChunkedReader::new(&[SEGMENT, SEGMENT, SEGMENT]);
    let mut head = Vec::new();

    let result = dispatcher.sniff_domain(&mut reader, &mut head, 80).await;

    assert_eq!(result, Ok(("fast.example.com".to_string(), false)));
    assert_eq!(*lock(&slow_seen), vec![10]);
    assert_eq!(*lock(&fast_seen), vec![10, 20]);
    assert_eq!(reader.chunks.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn continues_after_an_invalid_host() {
    let (invalid, invalid_seen) = stub(|_| Ok("not a domain".into()));
    let (valid, valid_seen) = stub(|_| Ok("example.com".into()));
    let dispatcher = with_stubs(plain(), vec![(invalid, false), (valid, false)]);
    let mut reader = ChunkedReader::new(&[SEGMENT]);
    let mut head = Vec::new();

    let result = dispatcher.sniff_domain(&mut reader, &mut head, 80).await;

    assert_eq!(result, Ok(("example.com".to_string(), false)));
    assert_eq!(*lock(&invalid_seen), vec![10]);
    assert_eq!(*lock(&valid_seen), vec![10]);
}

#[tokio::test(start_paused = true)]
async fn a_follow_up_read_failure_keeps_the_head_and_is_not_cached_by_sniff_domain() {
    let (waiting, _) = stub(|d| need(d.len() + 1));
    let dispatcher = with_stubs(pure_ip(), vec![(waiting, false)]);
    let mut reader = ChunkedReader::new(&[SEGMENT]).ending(End::Error);
    let meta = Meta::new(80);
    let mut head = Vec::new();

    let result = dispatcher.sniff_domain(&mut reader, &mut head, 80).await;

    assert_eq!(result, Err(SniffError::Read));
    assert_eq!(head, SEGMENT);
    assert_eq!(failures(&dispatcher, &meta), None);
}

#[tokio::test(start_paused = true)]
async fn an_initial_read_failure_is_cached_once() {
    let (waiting, seen) = stub(|d| need(d.len() + 1));
    let dispatcher = with_stubs(pure_ip(), vec![(waiting, false)]);
    let mut reader = ChunkedReader::new(&[]).ending(End::Error);
    let mut meta = Meta::new(80);
    let mut head = Vec::new();

    let sniffed = dispatcher
        .sniff_tcp(&mut reader, &mut head, &mut meta.target())
        .await;

    assert!(!sniffed);
    assert!(lock(&seen).is_empty());
    assert_eq!(failures(&dispatcher, &meta), Some(1));
    assert!(head.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_forced_initial_read_failure_is_not_cached() {
    let (waiting, _) = stub(|d| need(d.len() + 1));
    let dispatcher = with_stubs(
        Dispatcher::new(DispatcherConfig {
            enable: true,
            force_domain: vec![always()],
            ..Default::default()
        }),
        vec![(waiting, false)],
    );
    let mut reader = ChunkedReader::new(&[]).ending(End::Error);
    let mut meta = Meta::new(80);
    meta.host = Some("forced.example".into());
    let mut head = Vec::new();

    let sniffed = dispatcher
        .sniff_tcp(&mut reader, &mut head, &mut meta.target())
        .await;

    assert!(!sniffed);
    assert_eq!(failures(&dispatcher, &meta), None);
}

#[tokio::test(start_paused = true)]
async fn the_first_byte_gets_one_second_and_the_rest_share_another() {
    let (waiting, _) = stub(|d| need(d.len() + 1));
    let dispatcher = with_stubs(pure_ip(), vec![(waiting, false)]);
    let mut meta = Meta::new(80);
    let mut head = Vec::new();

    let start = Instant::now();
    let mut silent = ChunkedReader::new(&[]).ending(End::Stall);
    assert!(
        !dispatcher
            .sniff_tcp(&mut silent, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(start.elapsed(), Duration::from_secs(1));

    let start = Instant::now();
    let mut slow = ChunkedReader::new(&[SEGMENT]).ending(End::Stall);
    assert!(
        !dispatcher
            .sniff_tcp(&mut slow, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert_eq!(head, SEGMENT);
}

#[tokio::test(start_paused = true)]
async fn six_failures_skip_the_destination_until_a_success() {
    let (failing, _) = stub(|_| Err(SniffError::NotTls));
    let dispatcher = with_stubs(pure_ip(), vec![(failing, false)]);
    let mut meta = Meta::new(80);

    for round in 1..=6 {
        let mut reader = ChunkedReader::new(&[SEGMENT]);
        let mut head = Vec::new();
        assert!(
            !dispatcher
                .sniff_tcp(&mut reader, &mut head, &mut meta.target())
                .await
        );
        assert_eq!(failures(&dispatcher, &meta), Some(round));
    }

    let mut reader = ChunkedReader::new(&[SEGMENT]);
    let mut head = Vec::new();
    assert!(
        !dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(reader.chunks.len(), 1, "a skipped destination is not read");
    assert!(head.is_empty());

    tokio::time::advance(Duration::from_secs(601)).await;
    let mut reader = ChunkedReader::new(&[SEGMENT]);
    assert!(
        !dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(
        reader.chunks.len(),
        0,
        "the age expired, so it is read again"
    );
}

#[tokio::test(start_paused = true)]
async fn forcing_a_domain_bypasses_the_skip_list_and_success_clears_it() {
    let (found, _) = stub(|_| Ok("example.com".into()));
    let dispatcher = with_stubs(
        Dispatcher::new(DispatcherConfig {
            enable: true,
            parse_pure_ip: true,
            force_domain: vec![Arc::new(MatchFn(|d: &str| d == "forced.example"))],
            ..Default::default()
        }),
        vec![(found, false)],
    );
    let mut meta = Meta::new(80);
    for _ in 0..6 {
        dispatcher
            .skip_list()
            .record_failure((meta.dst_ip, meta.dst_port));
    }
    let mut reader = ChunkedReader::new(&[SEGMENT]);
    let mut head = Vec::new();
    assert!(
        !dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    );

    meta.host = Some("forced.example".into());
    let mut reader = ChunkedReader::new(&[SEGMENT]);
    assert!(
        dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(failures(&dispatcher, &meta), None);
}

#[tokio::test(start_paused = true)]
async fn skip_domain_and_non_domain_hosts_are_not_applied() {
    let (found, _) = stub(|_| Ok("blocked.example.com".into()));
    let dispatcher = with_stubs(
        Dispatcher::new(DispatcherConfig {
            enable: true,
            parse_pure_ip: true,
            skip_domain: vec![Arc::new(MatchFn(|d: &str| d.starts_with("blocked.")))],
            ..Default::default()
        }),
        vec![(found, true)],
    );
    let mut meta = Meta::new(80);
    let mut reader = ChunkedReader::new(&[SEGMENT]);
    let mut head = Vec::new();
    assert!(
        !dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(meta.sniff_host, None);
    assert_eq!(meta.host, None);
    assert_eq!(failures(&dispatcher, &meta), None);
}

#[tokio::test(start_paused = true)]
async fn the_override_conditions() {
    let make = |config: DispatcherConfig| {
        let (found, _) = stub(|_| Ok("example.com".into()));
        with_stubs(Dispatcher::new(config), vec![(found, false)])
    };
    let attempt = |dispatcher: Dispatcher, setup: fn(&mut Meta)| async move {
        let mut meta = Meta::new(80);
        setup(&mut meta);
        let mut reader = ChunkedReader::new(&[SEGMENT]);
        let mut head = Vec::new();
        dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    };

    let nothing = DispatcherConfig::default();
    assert!(!attempt(make(nothing), |_| {}).await);

    let pure = DispatcherConfig {
        parse_pure_ip: true,
        ..Default::default()
    };
    assert!(attempt(make(pure), |_| {}).await);
    let pure = DispatcherConfig {
        parse_pure_ip: true,
        ..Default::default()
    };
    assert!(!attempt(make(pure), |m| m.host = Some("known.example".into())).await);

    let mapping = || DispatcherConfig {
        force_dns_mapping: true,
        ..Default::default()
    };
    assert!(attempt(make(mapping()), |m| m.dns_mode = Some(DnsMode::RedirHost)).await);
    assert!(!attempt(make(mapping()), |m| m.dns_mode = Some(DnsMode::FakeIp)).await);
    assert!(!attempt(make(mapping()), |_| {}).await);

    let skip_dst = DispatcherConfig {
        parse_pure_ip: true,
        skip_dst: vec![Arc::new(IpFn(|ip| {
            ip == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
        }))],
        ..Default::default()
    };
    assert!(!attempt(make(skip_dst), |_| {}).await);

    let skip_src = || DispatcherConfig {
        parse_pure_ip: true,
        skip_src: vec![Arc::new(IpFn(|ip| {
            ip == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        }))],
        ..Default::default()
    };
    assert!(!attempt(make(skip_src()), |_| {}).await);

    let mapped_src =
        |m: &mut Meta| m.src_ip = Some(IpAddr::V6(Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped()));
    assert!(!attempt(make(skip_src()), mapped_src).await);
}

#[tokio::test(start_paused = true)]
async fn ports_outside_every_sniffer_are_not_read() {
    let dispatcher = real(vec![entry(SnifferKind::Tls, true)]);
    let mut meta = Meta::new(8443);
    let mut reader = ChunkedReader::new(&[SEGMENT]);
    let mut head = Vec::new();

    assert!(
        !dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(reader.chunks.len(), 1);
    assert_eq!(failures(&dispatcher, &meta), None);
}

#[test]
fn sniffers_are_ordered_tls_http_quic_with_default_ports() {
    let dispatcher = real(vec![
        entry(SnifferKind::Quic, true),
        entry(SnifferKind::Http, true),
        entry(SnifferKind::Tls, true),
    ]);
    let layout: Vec<_> = dispatcher
        .sniffers
        .iter()
        .map(|c| (c.ports.clone(), matches!(c.transport, Transport::Quic)))
        .collect();
    assert_eq!(
        layout,
        vec![
            (vec![(443, 443)], false),
            (vec![(80, 80)], false),
            (vec![(443, 443)], true),
        ]
    );
    assert!(dispatcher.enabled());
    assert!(!plain().enabled());
}

#[test]
fn configured_ports_are_inclusive_ranges() {
    let dispatcher = real(vec![SnifferEntry {
        kind: SnifferKind::Http,
        ports: vec![(8080, 8000), (80, 80)],
        override_dest: false,
    }]);
    let http = &dispatcher.sniffers[0];
    assert!(http.supports_port(8000) && http.supports_port(8080) && http.supports_port(80));
    assert!(!http.supports_port(7999) && !http.supports_port(8081));
}

#[test]
fn domain_name_validity_follows_go() {
    for valid in [
        "example.com",
        "a-b.example.org",
        "xn--80ak6aa92e.com",
        "localhost",
        "_dmarc.example.com",
        "a.b.",
        ".",
    ] {
        assert!(is_domain_name(valid), "{valid}");
    }
    for invalid in [
        "",
        "1.2.3.4",
        "10",
        "not a domain",
        "-a.com",
        "a-.com",
        "a..com",
        ".a.com",
        "exa mple.com",
        "例え.jp",
        &"a".repeat(64),
        &format!("{}.com", "a".repeat(64)),
        &vec!["a".repeat(60); 5].join("."),
    ] {
        assert!(!is_domain_name(invalid), "{invalid}");
    }
    assert!(!is_valid_sniff_host("."));
}

async fn run_real(
    entries: Vec<SnifferEntry>,
    port: u16,
    input: &[u8],
    chunk: usize,
) -> (bool, Meta, Vec<u8>) {
    let dispatcher = real(entries);
    let chunks: Vec<&[u8]> = input.chunks(chunk).collect();
    let mut reader = ChunkedReader::new(&chunks);
    let mut meta = Meta::new(port);
    let mut head = Vec::new();
    let sniffed = dispatcher
        .sniff_tcp(&mut reader, &mut head, &mut meta.target())
        .await;
    (sniffed, meta, head)
}

#[tokio::test(start_paused = true)]
async fn real_protocols_end_to_end() {
    let both = || {
        vec![
            entry(SnifferKind::Tls, true),
            entry(SnifferKind::Http, true),
        ]
    };
    let hello = make_tls_records(&make_client_hello("tls.example.com", 0), &[20, 50]);
    let mut tls_ports = both();
    tls_ports[1].ports = vec![(443, 443)];

    for chunk in [1, 7, 64, 4096] {
        let (sniffed, meta, head) = run_real(tls_ports.clone(), 443, &hello, chunk).await;
        assert!(sniffed, "chunk {chunk}");
        assert_eq!(meta.host.as_deref(), Some("tls.example.com"));
        assert!(hello.starts_with(&head));

        let request = b"GET /index HTTP/1.1\r\nHost: Web.Example.com:8080\r\nAccept: */*\r\n\r\n";
        let (sniffed, meta, head) = run_real(both(), 80, request, chunk).await;
        assert!(sniffed, "chunk {chunk}");
        assert_eq!(meta.sniff_host.as_deref(), Some("web.example.com"));
        assert!(request.starts_with(&head));
    }

    let mut h2 = crate::sniff::http::H2_CLIENT_PREFACE.to_vec();
    h2.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let mut block = vec![0x41, 14];
    block.extend_from_slice(b"h2.example.com");
    h2.extend_from_slice(&[0, 0, block.len() as u8, 1, 4, 0, 0, 0, 1]);
    h2.extend_from_slice(&block);
    for chunk in [1, 5, 4096] {
        let (sniffed, meta, _) = run_real(both(), 80, &h2, chunk).await;
        assert!(sniffed, "chunk {chunk}");
        assert_eq!(meta.host.as_deref(), Some("h2.example.com"));
    }

    let (sniffed, meta, head) = run_real(both(), 80, b"SSH-2.0-OpenSSH_9.6\r\n", 4096).await;
    assert!(!sniffed);
    assert_eq!(meta.host, None);
    assert_eq!(head, b"SSH-2.0-OpenSSH_9.6\r\n");
}

#[tokio::test(start_paused = true)]
async fn replays_the_head_through_a_peeked_stream() {
    use concord_common::PeekedStream;
    use tokio::io::AsyncReadExt;

    let dispatcher = real(vec![entry(SnifferKind::Tls, true)]);
    let (mut client, mut server) = tokio::io::duplex(1 << 16);
    let hello = make_tls_records(&make_client_hello("duplex.example.com", 0), &[]);
    client.write_all(&hello).await.unwrap();
    client.write_all(b"more").await.unwrap();
    client.shutdown().await.unwrap();

    let mut meta = Meta::new(443);
    let mut head = Vec::new();
    assert!(
        dispatcher
            .sniff_tcp(&mut server, &mut head, &mut meta.target())
            .await
    );
    assert_eq!(meta.host.as_deref(), Some("duplex.example.com"));

    let mut replay = PeekedStream::new(head, server);
    let mut all = Vec::new();
    replay.read_to_end(&mut all).await.unwrap();
    assert_eq!(all, [hello.as_slice(), b"more"].concat());
}

#[test]
fn udp_single_packet_is_applied_at_once() {
    let dispatcher = real(vec![entry(SnifferKind::Quic, true)]);
    let mut meta = Meta::new(443);
    let packet = hex::decode(QUIC_GOOGLE[0]).unwrap();

    let outcome = dispatcher.sniff_udp(&packet, &mut meta.target());

    assert!(matches!(outcome, UdpSniff::Done));
    assert_eq!(meta.host.as_deref(), Some("www.google.com"));
    assert_eq!(meta.sniff_host.as_deref(), Some("www.google.com"));
    assert_eq!(meta.dst_ip, None);
    assert_eq!(meta.dns_mode, Some(DnsMode::Normal));
}

#[test]
fn udp_fragmented_handshake_waits_for_more_packets() {
    let dispatcher = real(vec![entry(SnifferKind::Quic, false)]);
    let mut meta = Meta::new(443);
    let first = hex::decode(QUIC_NGINX[0]).unwrap();
    let second = hex::decode(QUIC_NGINX[1]).unwrap();

    let UdpSniff::Quic(mut sniffer) = dispatcher.sniff_udp(&first, &mut meta.target()) else {
        panic!("the first fragment alone cannot finish");
    };
    assert!(!sniffer.finished());
    assert_eq!(meta.host, None);

    sniffer.feed(&second);
    assert!(sniffer.finished());
    assert_eq!(sniffer.result(), Some("quic.nginx.org"));
    sniffer.apply(&mut meta.target());
    assert_eq!(meta.sniff_host.as_deref(), Some("quic.nginx.org"));
    assert_eq!(meta.host, None, "override_dest is off");
    assert!(meta.dst_ip.is_some());
}

#[test]
fn udp_timeout_closes_without_a_result() {
    let dispatcher = real(vec![entry(SnifferKind::Quic, true)]);
    let mut meta = Meta::new(443);
    let first = hex::decode(QUIC_NGINX[0]).unwrap();
    let UdpSniff::Quic(mut sniffer) = dispatcher.sniff_udp(&first, &mut meta.target()) else {
        panic!("the first fragment alone cannot finish");
    };

    sniffer.close();
    sniffer.feed(&hex::decode(QUIC_NGINX[1]).unwrap());
    sniffer.apply(&mut meta.target());

    assert!(sniffer.finished());
    assert_eq!(meta.sniff_host, None);
    assert_eq!(meta.host, None);
}

#[test]
fn udp_is_left_alone_off_the_quic_port_or_without_a_quic_sniffer() {
    let packet = hex::decode(QUIC_GOOGLE[0]).unwrap();
    let dispatcher = real(vec![entry(SnifferKind::Quic, true)]);
    let mut meta = Meta::new(8443);
    assert!(matches!(
        dispatcher.sniff_udp(&packet, &mut meta.target()),
        UdpSniff::Done
    ));
    assert_eq!(meta.host, None);

    let dispatcher = real(vec![entry(SnifferKind::Tls, true)]);
    let mut meta = Meta::new(443);
    assert!(matches!(
        dispatcher.sniff_udp(&packet, &mut meta.target()),
        UdpSniff::Done
    ));
    assert_eq!(meta.host, None);

    let dispatcher = Dispatcher::new(DispatcherConfig {
        enable: true,
        sniffers: vec![entry(SnifferKind::Quic, true)],
        ..Default::default()
    });
    let mut meta = Meta::new(443);
    meta.host = Some("known.example".into());
    assert!(matches!(
        dispatcher.sniff_udp(&packet, &mut meta.target()),
        UdpSniff::Done
    ));
    assert_eq!(meta.host.as_deref(), Some("known.example"));
}

#[test]
fn udp_skip_domain_blocks_the_result() {
    let dispatcher = Dispatcher::new(DispatcherConfig {
        enable: true,
        sniffers: vec![entry(SnifferKind::Quic, true)],
        parse_pure_ip: true,
        skip_domain: vec![Arc::new(MatchFn(|d: &str| d.ends_with("google.com")))],
        ..Default::default()
    });
    let mut meta = Meta::new(443);
    let packet = hex::decode(QUIC_GOOGLE[0]).unwrap();

    assert!(matches!(
        dispatcher.sniff_udp(&packet, &mut meta.target()),
        UdpSniff::Done
    ));
    assert_eq!(meta.host, None);
    assert_eq!(meta.sniff_host, None);
}

#[tokio::test(start_paused = true)]
async fn random_bytes_never_panic_through_the_dispatcher() {
    let mut state = 0xdead_beef_cafe_f00du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let tls = make_tls_records(&make_client_hello("fuzz.example.com", 30), &[10]);
    let dispatcher = Dispatcher::new(DispatcherConfig {
        enable: true,
        sniffers: vec![
            SnifferEntry {
                kind: SnifferKind::Tls,
                ports: vec![(0, u16::MAX)],
                override_dest: true,
            },
            SnifferEntry {
                kind: SnifferKind::Http,
                ports: vec![(0, u16::MAX)],
                override_dest: true,
            },
            SnifferEntry {
                kind: SnifferKind::Quic,
                ports: vec![(0, u16::MAX)],
                override_dest: true,
            },
        ],
        parse_pure_ip: true,
        ..Default::default()
    });
    for round in 0..300 {
        let mut data: Vec<u8> = (0..(next() % 400)).map(|_| next() as u8).collect();
        if round % 2 == 0 {
            data = tls.clone();
            for _ in 0..(next() % 4) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
        }
        let chunk = 1 + (next() as usize % 50);
        let chunks: Vec<&[u8]> = data.chunks(chunk).collect();
        let mut reader = ChunkedReader::new(&chunks);
        let mut meta = Meta::new(80 + round as u16);
        let mut head = Vec::new();
        let _ = dispatcher
            .sniff_tcp(&mut reader, &mut head, &mut meta.target())
            .await;
        assert!(head.len() <= data.len().max(1) + 4096);
        let mut meta = Meta::new(80);
        let _ = dispatcher.sniff_udp(&data, &mut meta.target());
    }
}

#[tokio::test]
async fn the_dispatcher_and_its_futures_cross_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Dispatcher>();
    assert_send_sync::<QuicSniffer>();

    let dispatcher = Arc::new(real(vec![entry(SnifferKind::Tls, true)]));
    let hello = make_tls_records(&make_client_hello("spawned.example.com", 0), &[]);
    let (mut client, mut server) = tokio::io::duplex(4096);
    client.write_all(&hello).await.unwrap();
    let task = tokio::spawn(async move {
        let mut meta = Meta::new(443);
        let mut head = Vec::new();
        let sniffed = dispatcher
            .sniff_tcp(&mut server, &mut head, &mut meta.target())
            .await;
        (sniffed, meta.host)
    });
    let (sniffed, host) = task.await.unwrap();
    assert!(sniffed);
    assert_eq!(host.as_deref(), Some("spawned.example.com"));
}
