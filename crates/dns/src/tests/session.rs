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
use tokio::net::{TcpListener, TcpStream};

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
