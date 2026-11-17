#![allow(
    clippy::disallowed_methods,
    reason = "loopback DNS servers and dialers for tests"
)]

use super::*;
use std::io;
use std::net::SocketAddr;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use concord_common::{BoxStream, PacketSession};
use futures_util::{FutureExt, poll};
use tokio::net::{TcpListener, TcpStream};

use crate::shared_dial::{Got, Join, SharedDial};

fn live(_: &usize) -> bool {
    true
}

fn pair(got: io::Result<Got<usize>>) -> (usize, bool) {
    let got = got.unwrap();
    (got.value, got.reused)
}

#[tokio::test]
async fn concurrent_callers_share_a_successful_dial() {
    let slot = SharedDial::new();
    let (send, recv) = tokio::sync::oneshot::channel();
    let first = slot.get(live, async {
        recv.await.unwrap();
        Ok(7)
    });
    tokio::pin!(first);
    assert!(poll!(&mut first).is_pending());
    let mut waiters: Vec<_> = (0..16)
        .map(|_| slot.get(live, async { panic!("duplicate dial") }).boxed())
        .collect();
    for waiter in &mut waiters {
        assert!(poll!(waiter).is_pending());
    }
    send.send(()).unwrap();
    assert_eq!(pair(first.await), (7, false));
    for waiter in waiters {
        assert_eq!(pair(waiter.await), (7, false));
    }
    assert_eq!(
        pair(slot.get(live, async { panic!("cached") }).await),
        (7, true)
    );
}

#[tokio::test]
async fn only_the_waiting_batch_shares_a_dial_error() {
    let slot = SharedDial::new();
    let (send, recv) = tokio::sync::oneshot::channel();
    let first = slot.get(live, async {
        recv.await.unwrap();
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "dial failed",
        ))
    });
    tokio::pin!(first);
    assert!(poll!(&mut first).is_pending());
    let mut waiters: Vec<_> = (0..16)
        .map(|_| {
            slot.get(live, async { panic!("duplicate failed dial") })
                .boxed()
        })
        .collect();
    for waiter in &mut waiters {
        assert!(poll!(waiter).is_pending());
    }
    send.send(()).unwrap();
    let first = first.await.err().unwrap();
    // A new caller can succeed before the old waiters consume their error.
    assert_eq!(pair(slot.get(live, async { Ok(9) }).await), (9, false));
    for waiter in waiters {
        let err = waiter.await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(err.to_string(), "dial failed");
        let shared = |err: &io::Error| {
            Arc::as_ptr(
                err.get_ref()
                    .unwrap()
                    .downcast_ref::<Arc<io::Error>>()
                    .unwrap(),
            )
        };
        assert_eq!(shared(&first), shared(&err));
    }
}

#[tokio::test]
async fn cancelling_the_dial_releases_waiters_and_allows_another_dial() {
    let slot = SharedDial::new();
    let mut first = slot.get(live, std::future::pending()).boxed();
    assert!(poll!(&mut first).is_pending());
    let mut waiter = slot.get(live, async { panic!("duplicate dial") }).boxed();
    assert!(poll!(&mut waiter).is_pending());
    drop(first);
    assert_eq!(
        waiter.await.err().unwrap().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(pair(slot.get(live, async { Ok(1) }).await), (1, false));
    assert_eq!(slot.take(), Some(1));
    assert_eq!(pair(slot.get(live, async { Ok(2) }).await), (2, false));
}

#[tokio::test]
async fn an_uncached_sender_keeps_its_own_connection() {
    let slot = SharedDial::<usize>::new();
    for _ in 0..2 {
        match slot.join(live).await.unwrap() {
            Join::Dial(turn) => turn.release(),
            Join::Ready(_) => panic!("nothing was published"),
        }
    }
}

#[tokio::test]
async fn a_released_turn_hands_the_next_dial_to_a_waiter() {
    let slot = SharedDial::<usize>::new();
    let Join::Dial(turn) = slot.join(live).await.unwrap() else {
        panic!("nothing was published");
    };
    let mut waiter = slot.get(live, async { Ok(3) }).boxed();
    assert!(poll!(&mut waiter).is_pending());
    turn.release();
    assert_eq!(pair(waiter.await), (3, false));
}

#[tokio::test]
async fn a_dead_session_is_dropped_and_dialled_again() {
    let slot = SharedDial::new();
    assert_eq!(pair(slot.get(live, async { Ok(1) }).await), (1, false));
    assert_eq!(
        pair(slot.get(|n| *n != 1, async { Ok(2) }).await),
        (2, false)
    );
    assert_eq!(slot.take(), Some(2));
}

struct CountingDialer {
    server: SocketAddr,
    udp: Arc<UdpDialer>,
    attempts: AtomicUsize,
    fail: AtomicBool,
}

impl CountingDialer {
    fn attempt(&self) -> io::Result<()> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail.swap(false, Ordering::SeqCst) {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "first dial failed",
            ))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl crate::UpstreamDialer for CountingDialer {
    fn knows(&self, via: &str) -> bool {
        via == "node"
    }

    async fn connect(&self, _via: &str, _target: &Address) -> io::Result<BoxStream> {
        self.attempt()?;
        Ok(Box::new(TcpStream::connect(self.server).await?))
    }

    async fn bind_udp(&self, via: &str, target: &Address) -> io::Result<Arc<dyn PacketSession>> {
        self.attempt()?;
        crate::UpstreamDialer::bind_udp(&*self.udp, via, target).await
    }
}

async fn serve_h2() -> SocketAddr {
    use base64::Engine;
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await.unwrap();
                let service = hyper::service::service_fn(
                    |req: http::Request<hyper::body::Incoming>| async move {
                        let query = req.uri().query().unwrap().strip_prefix("dns=").unwrap();
                        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(query)
                            .unwrap();
                        let req = Message::from_vec(&bytes).unwrap();
                        let reply = answer_with(Ipv4Addr::new(10, 0, 2, 1))(&req).unwrap();
                        Ok::<_, std::convert::Infallible>(http::Response::new(
                            http_body_util::Full::new(bytes::Bytes::from(reply.to_vec().unwrap())),
                        ))
                    },
                );
                let _ =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
            });
        }
    });
    addr
}

async fn upstream(protocol: &str, fail: bool) -> (Arc<crate::Resolver>, Arc<CountingDialer>) {
    let handler = answer_with(Ipv4Addr::new(10, 0, 2, 1));
    let addr = match protocol {
        "doq" => serve_quic(handler).await.addr,
        "h3" => serve_h3(handler).await.addr,
        "h2" => serve_h2().await,
        "h1" => serve_doh(handler).await.addr,
        _ => panic!("unknown protocol"),
    };
    let url = match protocol {
        "doq" => format!("quic://{addr}#node&skip-cert-verify=true"),
        "h1" => format!("http://{addr}/dns-query#node"),
        "h3" => format!("https://{addr}/dns-query#node&skip-cert-verify=true&h3=true"),
        _ => format!("https://{addr}/dns-query#node&skip-cert-verify=true"),
    };
    let dialer = Arc::new(CountingDialer {
        server: addr,
        udp: UdpDialer::new(&["node"]),
        attempts: AtomicUsize::new(0),
        fail: AtomicBool::new(fail),
    });
    let sink = Arc::new(Sink::default());
    let mut deps = deps(&sink);
    deps.dialer = Arc::downgrade(&dialer) as Weak<dyn crate::UpstreamDialer>;
    let resolver = crate::Resolver::new(&config(&[url]), &HostsConfig::default(), deps).unwrap();
    (resolver, dialer)
}

#[tokio::test]
async fn concurrent_different_names_dial_once_on_each_encrypted_transport() {
    for protocol in ["h2", "h3", "doq"] {
        let (resolver, dialer) = upstream(protocol, false).await;
        let queries = (0..16).map(|i| {
            let resolver = Arc::clone(&resolver);
            async move { lookup_v4(&resolver, &format!("name-{i}.test")).await }
        });
        for reply in futures_util::future::join_all(queries).await {
            assert_eq!(reply.unwrap(), vec![ip("10.0.2.1")], "{protocol}");
        }
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1, "{protocol}");
    }
}

#[tokio::test]
async fn each_encrypted_transport_dials_again_after_a_failed_query() {
    for protocol in ["h2", "h3", "doq"] {
        let (resolver, dialer) = upstream(protocol, true).await;
        let client = resolver
            .clients
            .iter()
            .find(|client| {
                client.address().starts_with("https://") || client.address().starts_with("quic://")
            })
            .unwrap();
        let cx = crate::dialer::Cx {
            initiator: Initiator::App,
        };
        let first = crate::msg::build_query("first.test", RecordType::A).unwrap();
        let err = client.exchange(&first, cx).await.unwrap_err();
        assert!(
            err.to_string().contains("first dial failed"),
            "{protocol}: {err}"
        );
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1, "{protocol}");
        let next = crate::msg::build_query("next.test", RecordType::A).unwrap();
        let reply = client.exchange(&next, cx).await.unwrap();
        assert_eq!(crate::msg::answer_ips(&reply), vec![ip("10.0.2.1")]);
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 2, "{protocol}");
    }
}

#[tokio::test]
async fn concurrent_http1_queries_keep_independent_senders() {
    let (resolver, dialer) = upstream("h1", false).await;
    let queries = (0..16).map(|i| {
        let resolver = Arc::clone(&resolver);
        async move { lookup_v4(&resolver, &format!("name-{i}.test")).await }
    });
    for reply in futures_util::future::join_all(queries).await {
        assert_eq!(reply.unwrap(), vec![ip("10.0.2.1")]);
    }
    assert_eq!(dialer.attempts.load(Ordering::SeqCst), 16);
}
