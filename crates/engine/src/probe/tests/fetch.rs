use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use concord_common::sync::lock;
use futures_util::stream;
use http::Method;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::probe::Prober;
use crate::probe::ctx::{Ctx, ProbeError};
use crate::probe::fetch::{ProbeRequest, ProbeResult, read_body};
use crate::probe::hits::{HitRecorder, RouteHit};
use crate::probe::testing::{FakeEnv, Resp, exit_name, serve_fn};

pub fn request(url: &str, proxy: &str) -> ProbeRequest {
    let mut request = ProbeRequest::get(url);
    request.proxy = proxy.to_string();
    request.timeout = Duration::from_secs(2);
    request
}

pub async fn run(prober: &Prober, request: ProbeRequest) -> Option<ProbeResult> {
    prober
        .run_probe(&Ctx::new(Duration::from_secs(30)), request)
        .await
}

#[allow(clippy::disallowed_methods, reason = "loopback test server")]
async fn black_hole() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    addr
}

#[tokio::test]
async fn pins_the_named_proxy() {
    let server = serve_fn(|_| Resp {
        status: 403,
        body: b"ip=203.0.113.7\nloc=US\n".to_vec(),
        ..Resp::default()
    })
    .await;
    let env = FakeEnv::new(&["node-a"]);
    let prober = env.prober();
    let mut probe = request(&server.url("/trace"), "node-a");
    probe.headers = vec![("User-Agent".into(), "probe-test".into())];
    probe.max_body = 1024;

    let result = run(&prober, probe).await.unwrap();

    assert_eq!(result.error, None, "{}", result.message);
    assert_eq!(result.status, 403);
    assert_eq!(result.body, "ip=203.0.113.7\nloc=US\n");
    assert_eq!(result.chains, ["node-a"]);
    assert_eq!(result.url, server.url("/trace"));
    let seen = lock(&server.requests);
    assert_eq!(seen[0].header("user-agent"), Some("probe-test"));
    assert_eq!(
        seen[0].header("host"),
        Some(server.addr.to_string().as_str())
    );
}

#[tokio::test]
async fn follows_redirects_and_caps_the_body() {
    let server = serve_fn(|req| {
        if req.path == "/" {
            Resp::status(302).header("Location", "/final")
        } else {
            Resp::ok(&"x".repeat(100))
        }
    })
    .await;
    let env = FakeEnv::new(&["node-a"]);
    let mut probe = request(&server.url(""), "node-a");
    probe.max_body = 8;

    let result = run(&env.prober(), probe).await.unwrap();

    assert_eq!(result.error, None, "{}", result.message);
    assert_eq!(result.status, 200);
    assert_eq!(result.url, server.url("/final"));
    assert_eq!(result.body.len(), 8);
    assert_eq!(result.hits.len(), 1);
}

#[tokio::test]
async fn a_redirect_keeps_the_method_only_for_307_and_308() {
    let server = serve_fn(|req| match req.path.as_str() {
        "/see-other" => Resp::status(303).header("Location", "/landing"),
        "/temporary" => Resp::status(307).header("Location", "/landing"),
        _ => Resp::ok("landed"),
    })
    .await;
    let env = FakeEnv::new(&["node-a"]);
    let prober = env.prober();

    for (path, method, body_kept) in [("/see-other", "GET", false), ("/temporary", "POST", true)] {
        lock(&server.requests).clear();
        let mut probe = request(&server.url(path), "node-a");
        probe.method = Method::POST;
        probe.body = b"payload".to_vec();
        probe.headers = vec![("content-type".into(), "text/plain".into())];
        probe.max_body = 64;

        let result = run(&prober, probe).await.unwrap();

        assert_eq!(result.body, "landed");
        let seen = lock(&server.requests);
        let landing = seen.last().unwrap();
        assert_eq!(landing.method, method, "{path}");
        assert_eq!(landing.body == b"payload", body_kept, "{path}");
        assert_eq!(
            landing.header("content-type").is_some(),
            body_kept,
            "{path}"
        );
    }
}

#[tokio::test]
async fn no_redirect_hands_back_the_location() {
    let server =
        serve_fn(|_| Resp::status(302).header("Location", "https://www.netflix.com/jp-en/")).await;
    let env = FakeEnv::new(&["node-a"]);
    let mut probe = request(&server.url("/title"), "node-a");
    probe.no_redirect = true;

    let result = run(&env.prober(), probe).await.unwrap();

    assert_eq!(result.status, 302);
    assert_eq!(
        result.headers.get("location").unwrap(),
        "https://www.netflix.com/jp-en/"
    );
    assert_eq!(lock(&server.requests).len(), 1);
}

#[tokio::test]
async fn a_redirect_loop_ends_after_ten_hops() {
    let server = serve_fn(|_| Resp::status(302).header("Location", "/")).await;
    let env = FakeEnv::new(&["node-a"]);

    let result = run(&env.prober(), request(&server.url("/"), "node-a"))
        .await
        .unwrap();

    assert_eq!(result.error, Some(ProbeError::Failed));
    assert!(
        result.message.contains("stopped after 10 redirects"),
        "{}",
        result.message
    );
    assert_eq!(lock(&server.requests).len(), 11);
}

#[tokio::test]
async fn the_body_read_stops_once_the_marker_arrives() {
    let marker = "\"currentTerritory\":\"JP\"";
    let (head, tail) = marker.split_at(10);
    let frames = [
        format!("{}{head}", "x".repeat(8 * 1024)),
        format!("{tail}{}", "y".repeat(8 * 1024)),
        "z".repeat(8 * 1024),
    ];
    let total: usize = frames.iter().map(String::len).sum();
    let seen = AtomicUsize::new(0);
    let until = |tail: &str| {
        seen.fetch_add(1, Ordering::SeqCst);
        tail.contains(marker)
    };
    let mut chunks = stream::iter(frames.map(|frame| Ok::<_, ()>(Bytes::from(frame))));
    let mut buffer = Vec::new();

    read_body(&mut chunks, &mut buffer, total, Some(&until)).await;

    let body = String::from_utf8(buffer).unwrap();
    assert!(body.contains(marker), "the marker straddled two frames");
    assert!(body.len() < total);
    assert_eq!(seen.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_body_read_keeps_the_cap_without_a_marker() {
    let page = Bytes::from("x".repeat(3 * 32 * 1024));
    let mut chunks = stream::iter([Ok::<_, ()>(page)]);
    let mut buffer = Vec::new();

    read_body(
        &mut chunks,
        &mut buffer,
        32 * 1024 + 5,
        Some(&|_: &str| false),
    )
    .await;

    assert_eq!(buffer.len(), 32 * 1024 + 5);
}

#[tokio::test]
async fn the_body_read_keeps_what_arrived_before_the_stream_broke() {
    let mut chunks = stream::iter([Ok(Bytes::from("abc")), Err(()), Ok(Bytes::from("def"))]);
    let mut buffer = Vec::new();

    read_body(&mut chunks, &mut buffer, 64, None).await;

    assert_eq!(buffer, b"abc");
}

#[tokio::test]
async fn skips_the_body_when_not_asked() {
    let server = serve_fn(|_| Resp::status(204)).await;
    let env = FakeEnv::new(&["node-a"]);

    let result = run(&env.prober(), request(&server.url(""), "node-a"))
        .await
        .unwrap();

    assert_eq!((result.error, result.status), (None, 204));
    assert_eq!(result.body, "");
}

#[tokio::test]
async fn reports_a_timeout() {
    let addr = black_hole().await;
    let env = FakeEnv::new(&["node-a"]);
    let mut probe = request(&format!("http://{addr}"), "node-a");
    probe.timeout = Duration::from_millis(200);
    let start = Instant::now();

    let result = run(&env.prober(), probe).await.unwrap();

    assert_eq!(
        result.error,
        Some(ProbeError::Timeout),
        "{}",
        result.message
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
#[allow(clippy::disallowed_methods, reason = "loopback test server")]
async fn reports_a_refused_connection_with_the_exit_it_would_have_used() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let env = FakeEnv::new(&["node-a"]);
    let mut probe = request(&format!("http://{addr}"), "node-a");
    probe.timeout = Duration::from_secs(10);

    let result = run(&env.prober(), probe).await.unwrap();

    assert_eq!(result.error, Some(ProbeError::Failed));
    assert_eq!(result.status, 0);
    assert!(!result.message.is_empty());
    assert_eq!(
        result.hits,
        [RouteHit {
            host: addr.to_string(),
            proxy: "node-a".into(),
            exit: exit_name("node-a"),
        }]
    );
}

#[tokio::test]
async fn an_unknown_proxy_is_refused_without_waiting_for_a_slot() {
    let env = FakeEnv::new(&["node-a"]);
    let prober = env.prober();
    let _held = prober.slots.clone().try_acquire_many_owned(10).unwrap();
    let recorder = Arc::new(HitRecorder::default());
    let mut probe = request("http://example.invalid", "missing");
    probe.timeout = Duration::from_millis(1);
    probe.recorder = Some(recorder.clone());

    let result = tokio::time::timeout(Duration::from_secs(1), run(&prober, probe))
        .await
        .expect("queued behind a saturated semaphore")
        .unwrap();

    assert_eq!(result.error, Some(ProbeError::Failed));
    let missing = [RouteHit {
        proxy: "missing".into(),
        ..RouteHit::default()
    }];
    assert_eq!(result.hits, missing);
    assert_eq!(recorder.list(), missing);
}

#[tokio::test]
async fn gives_up_queueing_on_the_deadline() {
    let env = FakeEnv::new(&["node-a"]);
    let prober = env.prober();
    let _held = prober.slots.clone().try_acquire_many_owned(10).unwrap();
    let mut probe = request("http://example.invalid", "node-a");
    probe.timeout = Duration::from_millis(50);

    assert!(run(&prober, probe).await.is_none());
}

#[tokio::test]
async fn routes_through_the_rules_without_a_proxy() {
    let server = serve_fn(|_| Resp::ok("routed")).await;
    let env = FakeEnv::new(&[]);
    let mut probe = request(&server.url(""), "");
    probe.max_body = 64;

    let result = run(&env.prober(), probe).await.unwrap();

    assert_eq!(result.body, "routed");
    assert_eq!(result.chains, ["DIRECT"]);
    assert_eq!(lock(&env.dials)[0].1, None);
    assert_eq!(
        result.hits,
        [RouteHit {
            host: server.addr.to_string(),
            proxy: String::new(),
            exit: exit_name("DIRECT"),
        }]
    );
}

#[tokio::test]
async fn the_chains_of_a_group_come_back_exit_first() {
    let server = serve_fn(|_| Resp::ok("")).await;
    let env = FakeEnv::new(&["group-x", "lb-1"]);

    let result = run(&env.prober(), request(&server.url(""), "group-x"))
        .await
        .unwrap();

    assert_eq!(result.chains, ["node-of-group-x", "group-x"]);
    assert_eq!(result.hits[0].exit, exit_name("node-of-group-x"));
}

#[tokio::test]
async fn waits_out_a_suspended_tunnel() {
    let server = serve_fn(|_| Resp::ok("resumed")).await;
    let env = FakeEnv::new(&[]);
    env.suspended.store(true, Ordering::SeqCst);
    let resume = env.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(150)).await;
        resume.suspended.store(false, Ordering::SeqCst);
    });
    let mut probe = request(&server.url(""), "");
    probe.max_body = 64;

    let result = run(&env.prober(), probe).await.unwrap();

    assert_eq!(result.error, None, "{}", result.message);
    assert_eq!(result.body, "resumed");
}

#[tokio::test]
async fn times_out_while_the_tunnel_stays_suspended() {
    let server = serve_fn(|_| Resp::ok("unreachable")).await;
    let env = FakeEnv::new(&[]);
    env.suspended.store(true, Ordering::SeqCst);
    let mut probe = request(&server.url(""), "");
    probe.timeout = Duration::from_millis(200);

    let result = run(&env.prober(), probe).await.unwrap();

    assert_eq!(result.error, Some(ProbeError::Timeout));
}

#[tokio::test]
async fn a_dropped_probe_still_records_the_hits_it_made() {
    let addr = black_hole().await;
    let env = FakeEnv::new(&["node-a"]);
    let recorder = Arc::new(HitRecorder::default());
    let mut probe = request(&format!("http://{addr}"), "node-a");
    probe.recorder = Some(recorder.clone());
    let prober = env.prober();

    let outcome = tokio::time::timeout(Duration::from_millis(150), run(&prober, probe)).await;

    assert!(outcome.is_err());
    assert_eq!(recorder.list().len(), 1);
    assert_eq!(recorder.list()[0].exit, exit_name("node-a"));
}

#[tokio::test]
async fn the_result_carries_the_route_stamp() {
    let server = serve_fn(|_| Resp::ok("")).await;
    let env = FakeEnv::new(&["node-a"]);
    env.set_stamp(7, 42);

    let result = run(&env.prober(), request(&server.url(""), "node-a"))
        .await
        .unwrap();

    assert_eq!((result.core_epoch, result.route_version), (7, 42));
}

mod tls {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use rustls::ServerConfig;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use concord_tls::TrustStore;

    #[tokio::test]
    #[allow(clippy::disallowed_methods, reason = "loopback test server")]
    async fn https_is_verified_against_the_trust_store() {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "probe test ca");
        let ca_key = KeyPair::generate().unwrap();
        let ca_der = ca_params.self_signed(&ca_key).unwrap().der().clone();
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if tls.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure")
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        let env = FakeEnv::new(&["node-a"]);
        lock(&env.hosts).insert(format!("localhost:{}", addr.port()), addr);
        let url = format!("https://localhost:{}/", addr.port());
        let mut probe = request(&url, "node-a");
        probe.max_body = 64;

        let untrusted = run(&env.prober(), probe.clone()).await.unwrap();
        assert_eq!(untrusted.error, Some(ProbeError::Failed));

        *lock(&env.trust) = TrustStore::from_parts(Vec::new(), b"", vec![ca_der]);
        let trusted = run(&env.prober(), probe).await.unwrap();
        assert_eq!(trusted.error, None, "{}", trusted.message);
        assert_eq!(trusted.body, "secure");
    }
}
