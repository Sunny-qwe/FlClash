#![allow(
    clippy::disallowed_methods,
    reason = "the clients and origins here are the outside world, not the core's own sockets"
)]

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{CoreEvent, CoreOptions, EventSink, ResourcePhase, ResourceUpdate};
use concord_engine::{Engine, EngineConfig, ProxyView, RouteHit, SetupRequest, UpdateRequest};
use concord_platform::NativePlatform;
use concord_test_support::{tcp_echo, udp_echo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Events {
    seen: Mutex<Vec<CoreEvent>>,
}

impl EventSink for Events {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        lock(&self.seen).push(event);
    }
}

impl Events {
    fn phases(&self, wanted: &str) -> Vec<ResourcePhase> {
        lock(&self.seen)
            .iter()
            .filter_map(|event| match event {
                CoreEvent::Resource(ResourceUpdate { name, phase, .. }) if &**name == wanted => {
                    Some(phase.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn loaded(&self) -> Vec<String> {
        lock(&self.seen)
            .iter()
            .filter_map(|event| match event {
                CoreEvent::Resource(ResourceUpdate {
                    name,
                    phase: ResourcePhase::Updated | ResourcePhase::Unchanged,
                    ..
                }) => Some(name.to_string()),
                _ => None,
            })
            .collect()
    }
}

/// The core binds its ports later than this picks them. They come from below
/// the ephemeral range, so another test's `bind(0)` or outgoing connection
/// cannot take one in between, and never repeat within the process.
fn free_port() -> u16 {
    static NEXT: OnceLock<AtomicU16> = OnceLock::new();
    let next = NEXT.get_or_init(|| AtomicU16::new(10_000 + (std::process::id() % 20_000) as u16));
    loop {
        let port = next.fetch_add(1, Ordering::Relaxed);
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port));
        let udp = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port));
        if tcp.is_ok() && udp.is_ok() {
            return port;
        }
    }
}

/// Answers each path with its body; anything else is a 404.
async fn http_server(routes: HashMap<&'static str, String>) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let routes = routes.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let head = String::from_utf8_lossy(&head);
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                let response = match routes.get(path.as_str()) {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    }
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, hits)
}

/// A SOCKS5 server that counts what passes through it, to show a flow took a node.
async fn upstream_socks() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; usize::from(greeting[1])];
                client.read_exact(&mut methods).await.ok()?;
                client.write_all(&[5, 0]).await.ok()?;
                let target = read_socks_target(&mut client).await?;
                lock(&log).push(target.clone());
                let mut remote = TcpStream::connect(&target).await.ok()?;
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut remote)
                    .await
                    .ok()
            });
        }
    });
    (port, seen)
}

async fn read_socks_target(stream: &mut TcpStream) -> Option<String> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.ok()?;
    let host = match head[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.ok()?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut name).await.ok()?;
            String::from_utf8(name).ok()?
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.ok()?;
    Some(format!("{host}:{}", u16::from_be_bytes(port)))
}

async fn socks_connect(port: u16, target: SocketAddr) -> std::io::Result<TcpStream> {
    let SocketAddr::V4(target) = target else {
        panic!("tests use IPv4 targets");
    };
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", reply[1])));
    }
    Ok(stream)
}

/// The SOCKS reply goes out before routing, as in mihomo, so a refusal is the
/// stream closing without an answer.
async fn refused(port: u16, target: SocketAddr) -> bool {
    let Ok(mut stream) = socks_connect(port, target).await else {
        return true;
    };
    let _ = stream.write_all(b"ping").await;
    let mut buf = [0u8; 4];
    matches!(
        timeout(PATIENCE, stream.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

async fn round_trip(stream: &mut TcpStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    timeout(PATIENCE, stream.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
}

/// Plain VLESS whose first read must hold the whole request header; it keeps each first read.
async fn vless_server() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let firsts = Arc::new(Mutex::new(Vec::new()));
    let record = firsts.clone();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = client.read(&mut buf).await.unwrap_or(0);
                let first = buf[..n].to_vec();
                lock(&record).push(first.clone());
                let at = 18 + usize::from(first[17]);
                assert_eq!(first[at + 3], 1, "tests use IPv4 targets");
                let port = u16::from_be_bytes([first[at + 1], first[at + 2]]);
                let ip = Ipv4Addr::new(first[at + 4], first[at + 5], first[at + 6], first[at + 7]);
                let Ok(mut target) = TcpStream::connect((ip, port)).await else {
                    return;
                };
                let _ = target.write_all(&first[at + 8..]).await;
                let _ = client.write_all(&[0, 0]).await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
            });
        }
    });
    (port, firsts)
}

async fn greeter_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"hi").await;
                let _ = stream.read(&mut [0u8; 1]).await;
            });
        }
    });
    addr
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    check()
}

struct Rig {
    engine: Arc<Engine>,
    events: Arc<Events>,
    mixed: u16,
    home: tempfile::TempDir,
}

impl Rig {
    fn proxy(&self, name: &str) -> ProxyView {
        self.engine
            .proxy_views()
            .proxies
            .into_iter()
            .find_map(|(key, view)| (key.as_ref() == name).then_some(view))
            .unwrap_or_else(|| panic!("no proxy named {name}"))
    }

    fn selected(&self, group: &str) -> Option<String> {
        match self.proxy(group) {
            ProxyView::Group(group) => group.now,
            ProxyView::Node(_) => None,
        }
    }

    fn kind(&self, name: &str) -> &'static str {
        match self.proxy(name) {
            ProxyView::Group(group) => group.kind,
            ProxyView::Node(node) => node.kind,
        }
    }

    fn new() -> Rig {
        Rig::at(tempfile::tempdir().unwrap())
    }

    fn at(home: tempfile::TempDir) -> Rig {
        let events = Arc::new(Events::default());
        let engine = Engine::new(EngineConfig {
            sink: events.clone(),
            android: false,
            platform: Arc::new(NativePlatform::new()),
        });
        engine.init(home.path().to_str().unwrap(), 0).unwrap();
        Rig {
            engine,
            events,
            mixed: free_port(),
            home,
        }
    }

    async fn apply(&self, config: &str) -> Result<(), concord_engine::Failure> {
        self.apply_with(config, BTreeMap::new()).await
    }

    async fn apply_with(
        &self,
        config: &str,
        selected: BTreeMap<String, String>,
    ) -> Result<(), concord_engine::Failure> {
        self.setup(config, selected, CoreOptions::default()).await
    }

    async fn setup(
        &self,
        config: &str,
        selected: BTreeMap<String, String>,
        options: CoreOptions,
    ) -> Result<(), concord_engine::Failure> {
        let text = format!("mixed-port: {}\n{config}", self.mixed);
        std::fs::write(self.home.path().join("config.yaml"), text).unwrap();
        self.engine
            .setup(SetupRequest {
                base: None,
                selected,
                options,
            })
            .await
    }
}

fn empty_update() -> UpdateRequest {
    UpdateRequest {
        tun: None,
        allow_lan: None,
        mixed_port: None,
        find_process_mode: None,
        mode: None,
        log_level: None,
        ipv6: None,
        tcp_concurrent: None,
        unified_delay: None,
        authentication: None,
        geo_auto_update: None,
        geo_update_interval: None,
        geox_url: BTreeMap::new(),
        options: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_goes_direct_and_shows_in_the_connection_table() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    assert!(eventually(|| rig.engine.connection_count() == 1).await);
    let records = rig.engine.connections();
    let record = records.first().unwrap();
    assert_eq!(record.chains.first().map(AsRef::as_ref), Some("DIRECT"));
    assert_eq!(rig.engine.traffic_total(false).0, 4);

    rig.engine.close_all_connections();
    assert!(eventually(|| rig.engine.connection_count() == 0).await);
    let mut rest = [0u8; 1];
    assert_eq!(
        timeout(PATIENCE, stream.read(&mut rest))
            .await
            .expect("the stream stays open")
            .unwrap_or(0),
        0
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_still_dialing_when_every_connection_closes_is_closed_as_well() {
    let echo = tcp_echo().await;
    let (upstream, _) = upstream_socks().await;
    let gate = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gated = gate.local_addr().unwrap().port();
    let (entered, dialing) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut client, _) = gate.accept().await.unwrap();
        let _ = entered.send(());
        let _ = released.await;
        let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream))
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    });
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {gated}}}\n\
         rules:\n  - MATCH,up\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    timeout(PATIENCE, dialing)
        .await
        .expect("the flow never dialed")
        .unwrap();
    rig.engine.close_all_connections();
    release.send(()).unwrap();
    let mut rest = [0u8; 1];
    let read = timeout(PATIENCE, stream.read(&mut rest)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "the flow that was dialing stayed open"
    );
    assert_eq!(rig.engine.connection_count(), 0);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lazy_header_waits_for_a_slow_client_and_still_lets_a_server_speak_first() {
    let echo = tcp_echo().await;
    let greeter = greeter_server().await;
    let (vless, firsts) = vless_server().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: v, type: vless, server: 127.0.0.1, port: {vless}, uuid: b831381d-6324-4d53-ad4f-8cda48b30811}}\n\
         rules:\n  - MATCH,v\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mut slow = socks_connect(rig.mixed, echo).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    round_trip(&mut slow).await;
    assert!(
        lock(&firsts)[0].ends_with(b"ping"),
        "the header left without the client's first bytes: {:?}",
        lock(&firsts)
    );

    let mut quiet = socks_connect(rig.mixed, greeter).await.unwrap();
    let mut hello = [0u8; 2];
    timeout(PATIENCE, quiet.read_exact(&mut hello))
        .await
        .expect("the server's greeting never came")
        .unwrap();
    assert_eq!(&hello, b"hi");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rules_pick_a_group_and_a_selection_moves_it() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [up, DIRECT]}}\n\
         rules:\n  - DST-PORT,{},G\n  - MATCH,REJECT\n",
        echo.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    assert!(
        rig.engine
            .proxy_views()
            .all
            .iter()
            .any(|name| name.as_ref() == "G")
    );
    assert_eq!(rig.selected("G").as_deref(), Some("up"));
    assert_eq!(rig.kind("G"), "Selector");

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(lock(&seen).len(), 1);
    assert_eq!(lock(&seen)[0], echo.to_string());

    let outcome = rig.engine.select("G", "DIRECT").await;
    assert!(outcome.changed);
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(
        lock(&seen).len(),
        1,
        "the second flow must not pass the node"
    );
    assert_eq!(rig.selected("G").as_deref(), Some("DIRECT"));

    let other = tcp_echo().await;
    assert!(
        refused(rig.mixed, other).await,
        "MATCH,REJECT refuses what no other rule takes"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_selected_map_is_honoured_when_a_config_applies() {
    let (upstream, _) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [up, DIRECT]}}\n\
         rules:\n  - MATCH,G\n"
    );
    let selected = BTreeMap::from([("G".to_string(), "DIRECT".to_string())]);
    rig.apply_with(&config, selected).await.unwrap();
    assert_eq!(rig.selected("G").as_deref(), Some("DIRECT"));
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_config_falls_back_to_direct_and_says_so() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    let failure = rig
        .apply("rules:\n  - NOT-A-RULE,x,DIRECT\n")
        .await
        .unwrap_err();
    assert_eq!(failure.code, "config_rejected");
    assert!(
        failure.message.contains("NOT-A-RULE"),
        "{}",
        failure.message
    );
    rig.engine.start_listeners().await.unwrap();
    assert!(
        socks_connect(rig.mixed, echo).await.is_err(),
        "the default config opens no port"
    );
    assert_eq!(rig.kind("DIRECT"), "Direct");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_geo_file_that_cannot_be_fetched_rejects_the_config() {
    let (server, hits) = http_server(HashMap::new()).await;
    let rig = Rig::new();
    let config = format!(
        "geox-url:\n  mmdb: http://{server}/Country.mmdb\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,DIRECT\n"
    );
    let failure = rig.apply(&config).await.unwrap_err();
    assert_eq!(failure.code, "config_rejected");
    assert!(
        failure.message.contains("can't download MMDB"),
        "{}",
        failure.message
    );
    assert!(failure.message.contains("404"), "{}", failure.message);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn providers_load_over_the_tunnel_and_update_on_request() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let nodes = format!(
        "proxies:\n  - {{name: fetched, type: socks5, server: 127.0.0.1, port: {upstream}}}\n"
    );
    let (server, hits) = http_server(HashMap::from([
        ("/p.yaml", nodes),
        ("/r.txt", format!("{}/32\n", echo.ip())),
    ]))
    .await;
    let rig = Rig::new();
    let config = format!(
        "proxy-providers:\n  sub:\n    type: http\n    url: http://{server}/p.yaml\n    path: providers/p.yaml\n\
         rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n\
         proxy-groups:\n  - {{name: G, type: select, use: [sub]}}\n\
         rules:\n  - RULE-SET,local,G\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    assert!(
        eventually(|| {
            let loaded = rig.events.loaded();
            loaded.iter().any(|name| name == "sub") && loaded.iter().any(|name| name == "local")
        })
        .await,
        "providers did not report loading: {:?}",
        rig.events.loaded()
    );
    let names: Vec<String> = rig
        .engine
        .providers()
        .list()
        .into_iter()
        .map(|view| view.name)
        .collect();
    assert_eq!(names, ["local", "sub"]);
    let rule = rig.engine.providers().get("local").unwrap();
    assert_eq!(rule.kind, "Rule");
    assert_eq!(rule.vehicle_type, "HTTP");
    assert_eq!(rule.count, 1);
    assert!(rig.home.path().join("rules/r.txt").is_file());
    assert_eq!(rig.selected("G").as_deref(), Some("fetched"));

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(lock(&seen).len(), 1);

    let before = hits.load(Ordering::SeqCst);
    rig.engine.providers().update("local").await.unwrap();
    rig.engine.providers().update("sub").await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), before + 2);

    let missing = rig.engine.providers().update("nope").await.unwrap_err();
    assert_eq!(missing.code, "provider_not_found");
    rig.engine.shutdown().await;
}

/// Answers the first request with 503 and every later one with `body`.
async fn flaky_server(body: String) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let body: Arc<str> = body.into();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
            let body = body.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let response = if first {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (server, hits)
}

async fn wait_loaded(rig: &Rig, name: &str) -> bool {
    for _ in 0..60 {
        if rig.events.loaded().iter().any(|loaded| loaded == name) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_provider_that_failed_its_first_fetch_is_retried_before_the_interval() {
    let (server, hits) = flaky_server("10.0.0.0/8\n".to_string()).await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n    interval: 3600\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    assert!(
        wait_loaded(&rig, "local").await,
        "the provider was not retried"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(rig.engine.providers().get("local").unwrap().count, 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_provider_without_an_interval_is_not_retried() {
    let (server, hits) = flaky_server(
        "proxies:\n  - {name: fetched, type: socks5, server: 127.0.0.1, port: 1}\n".to_string(),
    )
    .await;
    let rig = Rig::new();
    let config = format!(
        "proxy-providers:\n  sub:\n    type: http\n    url: http://{server}/p.yaml\n    path: providers/p.yaml\n    interval: 0\n\
         proxy-groups:\n  - {{name: G, type: select, use: [sub]}}\n\
         rules:\n  - MATCH,G\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    assert!(!wait_loaded(&rig, "sub").await, "the provider was retried");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_side_load_replaces_a_rule_set_without_a_reapply() {
    let echo = tcp_echo().await;
    let (server, _) = http_server(HashMap::from([("/r.txt", "10.0.0.0/8\n".to_string())])).await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    assert!(eventually(|| rig.events.loaded().iter().any(|name| name == "local")).await);

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    rig.engine
        .providers()
        .side_load("local", format!("{}/32\n", echo.ip()))
        .await
        .unwrap();
    assert!(refused(rig.mixed, echo).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_rule_provider_reloads_when_the_file_is_rewritten() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    let config = "rule-providers:\n  local:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: r.txt\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n";
    rig.apply(config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    assert!(eventually(|| rig.events.loaded().iter().any(|name| name == "local")).await);

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    std::fs::write(
        rig.home.path().join("r.txt"),
        format!("{}/32\n10.0.0.0/8\n", echo.ip()),
    )
    .unwrap();
    let mut rejected = false;
    for _ in 0..100 {
        if refused(rig.mixed, echo).await {
            rejected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(rejected, "the rewritten file was never reloaded");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_rule_provider_serves_its_payload_until_the_file_loads() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: file\n    behavior: ipcidr\n    format: text\n    path: r.txt\n    payload:\n      - {}/32\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n",
        echo.ip()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    assert!(refused(rig.mixed, echo).await);

    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    let mut open = false;
    for _ in 0..100 {
        if !refused(rig.mixed, echo).await {
            open = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(open, "the loaded file never replaced the payload");
    rig.engine.shutdown().await;
}

/// Answers the first request with `body` and never answers another.
async fn answers_once(body: String) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut first = true;
        while let Ok((mut stream, _)) = listener.accept().await {
            let answer = std::mem::take(&mut first).then(|| body.clone());
            tokio::spawn(async move {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let Some(body) = answer else {
                    return std::future::pending().await;
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    server
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reapplied_rule_set_keeps_matching_while_it_loads_again() {
    let echo = tcp_echo().await;
    let server = answers_once(format!("{}/32\n", echo.ip())).await;
    let rig = Rig::new();
    let config = |path: &str| {
        format!(
            "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/{path}\n    path: rules/{path}\n\
             rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
        )
    };
    rig.apply(&config("r.txt")).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    assert!(eventually(|| rig.events.loaded().iter().any(|name| name == "local")).await);
    assert!(refused(rig.mixed, echo).await);

    std::fs::remove_file(rig.home.path().join("rules/r.txt")).unwrap();
    rig.apply(&config("r.txt")).await.unwrap();
    assert!(
        refused(rig.mixed, echo).await,
        "the rule set was empty while it was fetched again"
    );

    rig.apply(&config("s.txt")).await.unwrap();
    assert!(
        !refused(rig.mixed, echo).await,
        "a provider with another source kept the old set"
    );
    rig.engine.shutdown().await;
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

fn last_a_record(answer: &[u8]) -> [u8; 4] {
    assert_eq!(&answer[..2], &[0x12, 0x34]);
    assert!(answer[6] != 0 || answer[7] != 0, "no answers: {answer:?}");
    answer[answer.len() - 4..].try_into().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dns_listener_answers_from_hosts_over_udp_and_tcp() {
    let port = free_port();
    let rig = Rig::new();
    let config = format!(
        "hosts:\n  a.test: 1.2.3.4\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: redir-host\n  nameserver:\n    - 127.0.0.1:1\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&dns_query("a.test"), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no UDP answer")
        .unwrap();
    assert_eq!(last_a_record(&buf[..len]), [1, 2, 3, 4]);

    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let query = dns_query("a.test");
    let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await.unwrap();
    let mut prefix = [0u8; 2];
    timeout(PATIENCE, stream.read_exact(&mut prefix))
        .await
        .expect("no TCP answer")
        .unwrap();
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(last_a_record(&answer), [1, 2, 3, 4]);

    let again = format!(
        "hosts:\n  a.test: 5.6.7.8\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: redir-host\n  nameserver:\n    - 127.0.0.1:1\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&again).await.unwrap();
    socket
        .send_to(&dns_query("a.test"), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no answer after a reapply")
        .unwrap();
    assert_eq!(last_a_record(&buf[..len]), [5, 6, 7, 8]);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_through_socks_reaches_its_target_and_back() {
    let echo = udp_echo().await;
    let SocketAddr::V4(echo_v4) = echo else {
        panic!("IPv4 expected")
    };
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&echo_v4.ip().octets());
    packet.extend_from_slice(&echo_v4.port().to_be_bytes());
    packet.extend_from_slice(b"datagram");
    socket.send_to(&packet, relay).await.unwrap();

    let mut buf = [0u8; 256];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    assert_eq!(&buf[len - 8..len], b"datagram");
    assert_eq!(&buf[4..8], &echo_v4.ip().octets());
    assert!(eventually(|| rig.engine.connection_count() >= 1).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_update_changes_the_mode_and_the_route_stamp() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,REJECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    assert!(refused(rig.mixed, echo).await);

    let before = rig.engine.watch_route(true).stamp;
    let mut request = empty_update();
    request.mode = Some("direct".to_string());
    rig.engine.update(request).await.unwrap();
    let after = rig.engine.watch_route(true).stamp;
    assert_eq!(after.epoch, before.epoch);
    assert!(after.version > before.version);

    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;

    let mut request = empty_update();
    request.ipv6 = Some(false);
    rig.engine.update(request).await.unwrap();
    let moved = rig.engine.watch_route(false).stamp;
    assert_eq!(
        moved.epoch,
        after.epoch + 1,
        "IPv6 moves a direct dial's exit"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_before_any_config_is_refused() {
    let rig = Rig::new();
    let failure = rig.engine.update(empty_update()).await.unwrap_err();
    assert_eq!(failure.message, "config is not applied");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listeners_follow_the_start_and_stop_calls() {
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_err(),
        "a config alone opens no port"
    );
    rig.engine.start_listeners().await.unwrap();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_ok()
    );
    rig.engine.stop_listeners().await.unwrap();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_err()
    );
    rig.engine.start_listeners().await.unwrap();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
            .await
            .is_ok()
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delay_tests_read_the_node_and_name_what_failed() {
    let (server, _) = http_server(HashMap::from([("/ok", "ok".to_string())])).await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         rules:\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();

    let url = format!("http://{server}/ok");
    let good = rig.engine.test_delay("up", &url, 3000).await;
    assert!(good.value > 0, "{good:?}");
    assert_eq!(lock(&seen).len(), 1);

    let unknown = rig.engine.test_delay("nope", &url, 3000).await;
    assert_eq!(unknown.value, -2);

    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_probe_reports_where_it_left_and_the_route_can_be_rechecked() {
    let (server, _) = http_server(HashMap::from([("/ip", "203.0.113.7".to_string())])).await;
    let (upstream, _) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [up, DIRECT]}}\n\
         rules:\n  - MATCH,G\n"
    );
    rig.apply(&config).await.unwrap();

    let url = format!("http://{server}/ip");
    let answer = rig
        .engine
        .probe_outbound_ip("G".to_string(), vec![url], 5000)
        .await;
    assert_eq!(answer["body"], "203.0.113.7", "{answer}");
    assert_eq!(answer["chains"], serde_json::json!(["up", "G"]), "{answer}");
    let hits = answer["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "{answer}");
    let hit = RouteHit {
        host: hits[0]["host"].as_str().unwrap().to_string(),
        proxy: hits[0]["proxy"].as_str().unwrap_or("").to_string(),
        exit: hits[0]["exit"].as_str().unwrap().to_string(),
    };
    assert!(hit.exit.starts_with("\"up\" Socks5 "), "{}", hit.exit);

    let (_, held) = rig.engine.check_routes(vec![vec![hit.clone()]]).await;
    assert_eq!(held, [true]);

    rig.engine.select("G", "DIRECT").await;
    let (_, held) = rig.engine.check_routes(vec![vec![hit]]).await;
    assert_eq!(held, [false], "the selection moved the exit");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_core_that_shut_down_can_start_over() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    rig.engine.shutdown().await;
    assert!(!rig.engine.is_initialized());
    assert!(
        rig.apply("rules:\n  - MATCH,DIRECT\n").await.is_err(),
        "setup before init"
    );

    rig.engine
        .init(rig.home.path().to_str().unwrap(), 0)
        .unwrap();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_in_a_group_moves_on_to_the_next_rule() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [PASS, up]}}\n\
         rules:\n  - DST-PORT,{},G\n  - DST-PORT,{},up\n  - MATCH,REJECT\n",
        echo.port(),
        echo.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(lock(&seen).len(), 1);
    let records = rig.engine.connections();
    assert_eq!(
        records[0].chains.first().map(AsRef::as_ref),
        Some("up"),
        "the group passed, so the second rule's node carries it"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_skips_a_rule_whose_outbound_has_no_udp() {
    let echo = udp_echo().await;
    let SocketAddr::V4(echo_v4) = echo else {
        panic!("IPv4 expected")
    };
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: web, type: http, server: 127.0.0.1, port: {}}}\n\
         rules:\n  - NETWORK,UDP,web\n  - MATCH,DIRECT\n",
        free_port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    let relay = SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&echo_v4.ip().octets());
    packet.extend_from_slice(&echo_v4.port().to_be_bytes());
    packet.extend_from_slice(b"datagram");
    socket.send_to(&packet, relay).await.unwrap();
    let mut buf = [0u8; 256];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no UDP reply")
        .unwrap();
    assert_eq!(&buf[len - 8..len], b"datagram");
    assert!(eventually(|| rig.engine.connection_count() >= 1).await);
    let chains = rig.engine.connections()[0].chains.clone();
    assert_eq!(chains.first().map(AsRef::as_ref), Some("DIRECT"));
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_refuses_a_loop_back_into_the_core() {
    let echo = tcp_echo().await;
    let SocketAddr::V4(echo_v4) = echo else {
        panic!("IPv4 expected")
    };
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    let own = SocketAddr::from((Ipv4Addr::LOCALHOST, rig.mixed));
    let mut stream = socks_connect(rig.mixed, own).await.unwrap();

    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    timeout(PATIENCE, stream.read_exact(&mut method))
        .await
        .expect("the nested greeting was not answered")
        .unwrap();
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&echo_v4.ip().octets());
    request.extend_from_slice(&echo_v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let _ = stream.write_all(b"ping").await;

    let mut seen = Vec::new();
    let _ = timeout(PATIENCE, stream.read_to_end(&mut seen))
        .await
        .expect("the nested flow was left open");
    assert!(
        !seen.windows(4).any(|window| window == b"ping"),
        "the nested flow came out of DIRECT: {seen:?}"
    );
    drop(stream);
    assert!(eventually(|| rig.engine.connection_count() == 0).await);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fake_ip_flow_is_routed_by_the_name_behind_it() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let port = free_port();
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - 127.0.0.1:1\n\
         rules:\n  - DOMAIN,faked.test,up\n  - MATCH,REJECT\n"
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&dns_query("faked.test"), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no fake-ip answer")
        .unwrap();
    let fake = Ipv4Addr::from(last_a_record(&buf[..len]));
    assert_eq!(fake.octets()[..2], [198, 18], "{fake}");

    let target = SocketAddr::from((fake, echo.port()));
    let mut stream = socks_connect(rig.mixed, target).await.unwrap();
    let _ = stream.write_all(b"x").await;
    assert!(
        eventually(|| !lock(&seen).is_empty()).await,
        "the flow never reached the node"
    );
    assert_eq!(lock(&seen)[0], format!("faked.test:{}", echo.port()));
    rig.engine.shutdown().await;
}

async fn fake_ip_of(port: u16, host: &str) -> Ipv4Addr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&dns_query(host), (Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = timeout(PATIENCE, socket.recv_from(&mut buf))
        .await
        .expect("no fake-ip answer")
        .unwrap();
    Ipv4Addr::from(last_a_record(&buf[..len]))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stored_fake_ips_outlive_a_restart() {
    let port = free_port();
    let config = format!(
        "profile:\n  store-fake-ip: true\n\
         dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - 127.0.0.1:1\n"
    );
    let rig = Rig::new();
    rig.apply(&config).await.unwrap();
    let kept = fake_ip_of(port, "kept.test").await;
    rig.engine.shutdown().await;
    let Rig { engine, home, .. } = rig;
    drop(engine);

    let rig = Rig::at(home);
    rig.apply(&config).await.unwrap();
    assert_ne!(fake_ip_of(port, "new.test").await, kept);
    assert_eq!(fake_ip_of(port, "kept.test").await, kept);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sniffed_name_is_what_rules_see() {
    let (server, _) = http_server(HashMap::from([("/", "hello".to_string())])).await;
    let (upstream, seen) = upstream_socks().await;
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\n\
         sniffer:\n  enable: true\n  parse-pure-ip: true\n  sniff:\n    HTTP:\n      ports: [{}]\n      override-destination: false\n\
         rules:\n  - DOMAIN,sniffed.test,up\n  - MATCH,REJECT\n",
        server.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mut stream = socks_connect(rig.mixed, server).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: sniffed.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut body = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut body))
        .await
        .expect("no HTTP answer")
        .unwrap();
    assert!(String::from_utf8_lossy(&body).ends_with("hello"));
    assert_eq!(
        lock(&seen)[0],
        server.to_string(),
        "without override-destination the node dials the original address"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_flows_leave_nothing_behind() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo = listener.local_addr().unwrap();
    let origin = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..200 {
            let (mut stream, _) = listener.accept().await.unwrap();
            tasks.spawn(async move {
                let (mut read, mut write) = stream.split();
                tokio::io::copy(&mut read, &mut write)
                    .await
                    .expect("echo copy");
                write.shutdown().await.expect("origin half-close");
            });
        }
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
    });
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    // macOS caps a listen backlog at kern.ipc.somaxconn, 128 by default; 200 simultaneous
    // connects can overflow the mixed listener's accept queue before it drains it.
    let handshakes = Arc::new(tokio::sync::Semaphore::new(128));
    let mut tasks = Vec::new();
    for _ in 0..200 {
        let mixed = rig.mixed;
        let handshakes = handshakes.clone();
        tasks.push(tokio::spawn(async move {
            timeout(PATIENCE, async {
                let permit = handshakes.acquire().await.expect("semaphore open");
                let mut stream = socks_connect(mixed, echo).await.expect("SOCKS connect");
                drop(permit);
                let payload = vec![7u8; 64 * 1024];
                let (mut read, mut write) = stream.split();
                let send = async {
                    write.write_all(&payload).await.expect("payload send");
                    write.shutdown().await.expect("client half-close");
                };
                let mut echoed = vec![0u8; payload.len()];
                let receive = async {
                    read.read_exact(&mut echoed).await.expect("echo payload");
                    let mut trailing = [0u8; 1];
                    assert_eq!(read.read(&mut trailing).await.expect("echo EOF"), 0);
                };
                tokio::join!(send, receive);
                assert_eq!(echoed, payload);
            })
            .await
            .expect("full flow (connect, payload, half-close, EOF) stalled");
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    timeout(PATIENCE, origin)
        .await
        .expect("echo tasks did not finish")
        .unwrap();
    assert!(
        eventually(|| rig.engine.connection_count() == 0).await,
        "{} connections left",
        rig.engine.connection_count()
    );
    assert_eq!(rig.engine.traffic_total(false).0, 200 * 64 * 1024);
    rig.engine.shutdown().await;
}

/// A bare hostname covers 443 and 80 only, and the origins here are on free ports.
fn mitm_section(port: u16, lines: &str) -> String {
    format!("mitm:\n  enable: true\n  hostname: ['mitm.test:{port}']\n{lines}")
}

/// An HTTP/1.1 exchange through the core over SOCKS, as a client that names the host.
async fn http_through(mixed: u16, target: SocketAddr, host: &str, path: &str) -> String {
    let SocketAddr::V4(v4) = target else {
        panic!("IPv4 expected")
    };
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed))
        .await
        .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: {host}:{}\r\nConnection: close\r\n\r\n",
                v4.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    // Linux resets a socket closed with the request unread, as when the host does not resolve.
    let _ = timeout(PATIENCE, stream.read_to_end(&mut response))
        .await
        .expect("no HTTP answer");
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_rewrites_plain_http_on_the_way_through() {
    let (server, _) = http_server(HashMap::from([
        ("/kept", "from the server".to_string()),
        ("/after", "rewritten target".to_string()),
    ]))
    .await;
    let rig = Rig::new();
    let config = format!(
        "hosts:\n  mitm.test: 127.0.0.1\n{}rules:\n  - MATCH,DIRECT\n",
        mitm_section(
            server.port(),
            "  url-rewrite:\n    - ^http://mitm\\.test:\\d+/blocked$ - reject\n    - ^(http://mitm\\.test:\\d+)/before$ $1/after 302\n"
        )
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let body = http_through(rig.mixed, server, "mitm.test", "/kept").await;
    assert!(body.ends_with("from the server"), "{body}");

    let body = http_through(rig.mixed, server, "mitm.test", "/before").await;
    assert!(body.starts_with("HTTP/1.1 302"), "{body}");
    assert!(body.contains("/after"), "{body}");

    let body = http_through(rig.mixed, server, "mitm.test", "/blocked").await;
    assert!(!body.contains("from the server"), "{body}");

    let other = http_through(rig.mixed, server, "not-matched.test", "/kept").await;
    assert!(other.is_empty() || other.starts_with("HTTP"), "{other}");
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_intercepted_request_still_dialing_when_every_connection_closes_gets_no_answer() {
    let (server, _) = http_server(HashMap::from([("/kept", "from the server".to_string())])).await;
    let (upstream, _) = upstream_socks().await;
    let gate = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let gated = gate.local_addr().unwrap().port();
    let (entered, dialing) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let (mut client, _) = gate.accept().await.unwrap();
        let _ = entered.send(());
        let _ = released.await;
        let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream))
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    });
    let rig = Rig::new();
    let config = format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {gated}}}\n\
         mitm:\n  enable: true\n  hostname: ['localhost:{}']\n\
         rules:\n  - MATCH,up\n",
        server.port()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mixed = rig.mixed;
    let answer = tokio::spawn(async move {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed))
            .await
            .unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0, 3, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&server.port().to_be_bytes());
        stream.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await.unwrap();
        let get = format!(
            "GET /kept HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            server.port()
        );
        stream.write_all(get.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = timeout(PATIENCE, stream.read_to_end(&mut response)).await;
        String::from_utf8_lossy(&response).into_owned()
    });
    timeout(PATIENCE, dialing)
        .await
        .expect("the intercepted request never dialed upstream")
        .unwrap();
    rig.engine.close_all_connections();
    release.send(()).unwrap();
    let body = answer.await.unwrap();
    assert!(
        !body.contains("from the server"),
        "the upstream dialled across close_all still answered: {body}"
    );
    assert_eq!(rig.engine.connection_count(), 0);
    rig.engine.shutdown().await;
}

/// An HTTPS server with a certificate no one trusts, which answers every request alike.
async fn tls_server(body: &'static str) -> SocketAddr {
    let certified = rcgen::generate_simple_self_signed(vec!["origin.test".to_string()]).unwrap();
    let key =
        rustls_pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_decrypts_a_listed_host_under_its_own_certificate() {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::RootCertStore;

    let server = tls_server("over tls").await;
    let rig = Rig::new();
    let info = rig.engine.mitm().generate_certificate().unwrap();
    let fingerprint = info["fingerprint"].as_str().unwrap().to_string();
    let certificate_pem = info["pem"].as_str().unwrap().to_string();
    let config = format!(
        "hosts:\n  mitm.test: 127.0.0.1\n{}rules:\n  - MATCH,DIRECT\n",
        mitm_section(
            server.port(),
            &format!(
                "  decrypt-tls: true\n  ca-fingerprint: {fingerprint}\n  skip-server-cert-verify: true\n"
            )
        )
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();

    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(certificate_pem.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let tls = tokio_rustls::TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let SocketAddr::V4(v4) = server else {
        panic!("IPv4 expected")
    };
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, rig.mixed))
        .await
        .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    let host = "mitm.test";
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();

    let mut secured = timeout(
        PATIENCE,
        tls.connect(ServerName::try_from(host).unwrap(), stream),
    )
    .await
    .expect("the handshake with the core stalled")
    .expect("the leaf must chain to the CA the core reported");
    secured
        .write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: mitm.test:{}\r\nConnection: close\r\n\r\n",
                v4.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let _ = timeout(PATIENCE, secured.read_to_end(&mut response))
        .await
        .expect("no answer through the decrypted connection");
    let response = String::from_utf8_lossy(&response);
    assert!(response.ends_with("over tls"), "{response}");

    assert!(
        eventually(|| rig.engine.connection_count() == 0).await,
        "the upstream connection stayed listed"
    );
    rig.engine.shutdown().await;
}

/// An HTTPS origin that keeps its connections open and answers the path and
/// the `X-Mitm` header of each request.
async fn tls_echo_server() -> SocketAddr {
    let certified = rcgen::generate_simple_self_signed(vec!["origin.test".to_string()]).unwrap();
    let key =
        rustls_pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                loop {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8_lossy(&head).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let mitm = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("x-mitm")
                                .then(|| value.trim().to_string())
                        })
                        .unwrap_or_default();
                    let body = format!("{path}|{mitm}");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

type Secured = tokio_rustls::client::TlsStream<TcpStream>;

/// A TLS client through the core over SOCKS that trusts only the CA in `ca_pem`.
async fn tls_through(mixed: u16, host: &str, port: u16, ca_pem: &str) -> std::io::Result<Secured> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName};

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let tls = tokio_rustls::TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, mixed)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    timeout(
        PATIENCE,
        tls.connect(ServerName::try_from(host.to_string()).unwrap(), stream),
    )
    .await
    .map_err(|_| std::io::Error::other("the handshake stalled"))?
}

/// One request on a kept connection: its status and its body.
async fn exchange(stream: &mut Secured, host: &str, port: u16, path: &str) -> (u16, String) {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        timeout(PATIENCE, stream.read_exact(&mut byte))
            .await
            .expect("no answer")
            .unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    (status, String::from_utf8(body).unwrap())
}

fn verify_leaf(ca_pem: &str, leaf_pem: &str, host: &str) -> Result<(), String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let leaf = CertificateDer::from_pem_slice(leaf_pem.as_bytes()).map_err(|e| e.to_string())?;
    let verifier = tokio_rustls::rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    tokio_rustls::rustls::client::danger::ServerCertVerifier::verify_server_cert(
        verifier.as_ref(),
        &leaf,
        &[],
        &ServerName::try_from(host.to_string()).unwrap(),
        &[],
        UnixTime::now(),
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_makes_its_certificate_on_request_and_its_leaves_verify() {
    let rig = Rig::new();
    assert!(rig.engine.mitm().certificate().unwrap().is_none());
    assert!(
        rig.engine.mitm().issue_certificate("check.test").is_err(),
        "a leaf was issued without a CA"
    );
    let generated = rig.engine.mitm().generate_certificate().unwrap();
    let info = rig.engine.mitm().certificate().unwrap().unwrap();
    assert_eq!(info["fingerprint"], generated["fingerprint"]);
    assert!(rig.home.path().join("mitm/ca.crt").exists());
    let leaf = rig.engine.mitm().issue_certificate("check.test").unwrap();
    verify_leaf(info["pem"].as_str().unwrap(), &leaf, "check.test").unwrap();

    let issues = rig
        .engine
        .mitm()
        .validate(serde_json::json!({
            "hostname": ["a.test"],
            "url-rewrite": ["^ok _ reject", "(broken _ reject", "# note"],
        }))
        .unwrap();
    let issues = issues.as_object().unwrap();
    assert_eq!(issues.len(), 1, "{issues:?}");
    let listed = issues["url-rewrite"].as_array().unwrap();
    assert_eq!(
        (listed.len(), &listed[0]["index"]),
        (1, &serde_json::json!(1))
    );
}

async fn decrypting_rig(rules: &str, lines: &str, capture: bool) -> (Rig, SocketAddr, String) {
    let server = tls_echo_server().await;
    let rig = Rig::new();
    let info = rig.engine.mitm().generate_certificate().unwrap();
    let config = format!(
        "hosts:\n  mitm.test: 127.0.0.1\n{}rules:\n{rules}",
        mitm_section(
            server.port(),
            &format!(
                "  ca-fingerprint: {}\n  skip-server-cert-verify: true\n{lines}",
                info["fingerprint"].as_str().unwrap()
            )
        )
    );
    rig.setup(
        &config,
        BTreeMap::new(),
        CoreOptions {
            mitm_capture: capture,
            ..CoreOptions::default()
        },
    )
    .await
    .unwrap();
    rig.engine.start_listeners().await.unwrap();
    (rig, server, info["pem"].as_str().unwrap().to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_captures_the_exchanges_of_a_decrypted_connection() {
    let (rig, server, ca) = decrypting_rig(
        "  - MATCH,DIRECT\n",
        "  url-rewrite: ['/ad$ _ reject']\n  header-rewrite: ['http-request ^https://mitm\\.test header-add X-Mitm yes']\n",
        true,
    )
    .await;
    let port = server.port();
    let mut stream = tls_through(rig.mixed, "mitm.test", port, &ca)
        .await
        .unwrap();
    assert_eq!(exchange(&mut stream, "mitm.test", port, "/ad").await.0, 404);
    assert_eq!(
        exchange(&mut stream, "mitm.test", port, "/page").await,
        (200, "/page|yes".to_string())
    );

    let decrypted = rig
        .engine
        .connections()
        .into_iter()
        .find(|record| record.mitm.load(Ordering::SeqCst))
        .expect("no connection is marked as decrypted");
    let id = decrypted.id.clone();
    let mut list = serde_json::Value::Null;
    assert!(
        eventually(|| {
            list = rig.engine.mitm().exchanges(&id).unwrap();
            list["exchanges"]
                .as_array()
                .is_some_and(|all| all.len() == 1 && all[0].get("pending").is_none())
        })
        .await,
        "exchanges of {id}: {list}"
    );
    assert_eq!(
        (&list["capturing"], &list["closed"]),
        (&serde_json::json!(true), &serde_json::json!(false))
    );
    let exchange_id = list["exchanges"][0]["id"].as_i64().unwrap();
    let found = rig.engine.mitm().exchange(exchange_id).unwrap();
    assert_eq!(found["connection"], serde_json::json!(id));
    assert_eq!(found["status"], 200);
    assert_eq!(
        found["request-header"]["X-Mitm"],
        serde_json::json!(["yes"])
    );
    let body = rig.engine.mitm().body(exchange_id, true).unwrap();
    assert_eq!(body["data"], "L3BhZ2V8eWVz", "base64 of /page|yes");

    drop(stream);
    assert!(
        eventually(|| rig.engine.mitm().exchanges(&id).unwrap()["closed"] == true).await,
        "{id} is still listed open"
    );
    assert_eq!(
        rig.engine.mitm().exchanges(&id).unwrap()["exchanges"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_lists_the_requests_it_answers_or_the_rules_reject() {
    let (rig, server, ca) = decrypting_rig(
        "  - DST-PORT,1,REJECT\n  - MATCH,DIRECT\n",
        "  url-rewrite: ['/ad$ _ reject', '^https://.*/elsewhere$ https://127.0.0.1:1/']\n",
        true,
    )
    .await;
    let port = server.port();
    let mut stream = tls_through(rig.mixed, "mitm.test", port, &ca)
        .await
        .unwrap();
    exchange(&mut stream, "mitm.test", port, "/ad").await;
    exchange(&mut stream, "mitm.test", port, "/elsewhere").await;

    let rejected: Vec<_> = lock(&rig.events.seen)
        .iter()
        .filter_map(|event| match event {
            CoreEvent::Request(record)
                if record.mitm.load(Ordering::SeqCst)
                    && record.chains.iter().map(|c| c.as_ref()).eq(["REJECT"]) =>
            {
                Some(record.clone())
            }
            _ => None,
        })
        .collect();
    let mut listed: Vec<(String, String)> = rejected
        .iter()
        .filter_map(|record| {
            let list = rig.engine.mitm().exchanges(&record.id).unwrap();
            let exchanges = list["exchanges"].as_array()?;
            (exchanges.len() == 1).then(|| {
                (
                    format!("{}({})", record.rule, record.rule_payload),
                    exchanges[0]["url"].as_str().unwrap().to_string(),
                )
            })
        })
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            ("()".to_string(), format!("https://mitm.test:{port}/ad")),
            ("DstPort(1)".to_string(), "https://127.0.0.1:1/".to_string()),
        ]
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_leaves_a_listed_connection_the_rules_reject() {
    let (rig, server, ca) = decrypting_rig("  - MATCH,REJECT\n", "", false).await;
    assert!(
        tls_through(rig.mixed, "mitm.test", server.port(), &ca)
            .await
            .is_err(),
        "a connection the rules reject was answered"
    );
    rig.engine.shutdown().await;
}

impl Association {
    /// Whether a datagram to `host:port`, named as a SOCKS5 domain address or
    /// given as an address, comes back from the echo server behind it.
    async fn echoes_to(&self, host: &str, port: u16) -> bool {
        let mut packet = match host.parse::<Ipv4Addr>() {
            Ok(ip) => {
                let mut packet = vec![0, 0, 0, 1];
                packet.extend_from_slice(&ip.octets());
                packet
            }
            Err(_) => {
                let mut packet = vec![0, 0, 0, 3, u8::try_from(host.len()).unwrap()];
                packet.extend_from_slice(host.as_bytes());
                packet
            }
        };
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(b"datagram");
        let mut buf = [0u8; 256];
        for _ in 0..3 {
            self.socket.send_to(&packet, self.relay).await.unwrap();
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_millis(500), self.socket.recv_from(&mut buf)).await
            {
                return buf[..len].ends_with(b"datagram");
            }
        }
        false
    }
}

/// A nameserver that answers every A query with the loopback address.
async fn loopback_nameserver() -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let Some(end) = buf[12..len]
                .iter()
                .position(|&b| b == 0)
                .map(|at| 12 + at + 5)
            else {
                continue;
            };
            let is_a = buf.get(end - 4..end - 2) == Some(&[0, 1]);
            let mut answer = buf[..end].to_vec();
            answer[2..4].copy_from_slice(&[0x81, 0x80]);
            answer[6..12].copy_from_slice(&[0, u8::from(is_a), 0, 0, 0, 0]);
            if is_a {
                answer
                    .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            let _ = socket.send_to(&answer, from).await;
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_drops_quic_to_a_listed_host_by_name_or_fake_ip() {
    let echo = udp_echo().await;
    let port = echo.port();
    let nameserver = loopback_nameserver().await;
    let dns = free_port();
    let rig = Rig::new();
    let info = rig.engine.mitm().generate_certificate().unwrap();
    let config = format!(
        "dns:\n  enable: true\n  listen: 127.0.0.1:{dns}\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - {nameserver}\n\
         mitm:\n  enable: true\n  hostname: ['quic.test:{port}', 'faked.test:{port}']\n  ca-fingerprint: {}\n\
         rules:\n  - MATCH,DIRECT\n",
        info["fingerprint"].as_str().unwrap()
    );
    rig.apply(&config).await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    let listed_fake = fake_ip_of(dns, "faked.test").await;
    let unlisted_fake = fake_ip_of(dns, "plain.test").await;
    assert_eq!(listed_fake.octets()[..2], [198, 18], "{listed_fake}");

    assert!(
        associate(rig.mixed)
            .await
            .echoes_to(&unlisted_fake.to_string(), port)
            .await,
        "UDP to an unlisted host was dropped"
    );
    assert!(
        !associate(rig.mixed)
            .await
            .echoes_to("quic.test", port)
            .await,
        "QUIC to a listed host went out"
    );
    assert!(
        !associate(rig.mixed)
            .await
            .echoes_to(&listed_fake.to_string(), port)
            .await,
        "QUIC to the fake IP of a listed host went out"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_tasks_follow_the_core_and_reach_the_network() {
    let (server, hits) = http_server(HashMap::from([
        ("/tool", "pong".to_string()),
        ("/engine-started", "ok".to_string()),
        ("/network-changed", "ok".to_string()),
    ]))
    .await;
    let rig = Rig::new();
    let resources = rig.home.path().join("mitm/resources");
    std::fs::create_dir_all(&resources).unwrap();
    std::fs::write(
        resources.join("event.js"),
        format!("$httpClient.get('http://{server}/' + $event.name, () => $done())"),
    )
    .unwrap();
    std::fs::write(
        resources.join("tool.js"),
        format!(
            "$httpClient.get('http://{server}/tool', (error, response, body) => {{ console.log(body); $done({{ title: $trigger }}) }})"
        ),
    )
    .unwrap();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    assert!(
        rig.engine.mitm().run_script("Tool").await.is_err(),
        "a script ran with decryption off"
    );

    rig.apply(
        "mitm:\n  enable: true\n  script:\n    - Started = type=event,event-name=engine-started,script-path=event.js\n    - Network = type=event,event-name=network-changed,script-path=event.js\n    - Tool = type=generic,script-path=tool.js\nrules:\n  - MATCH,DIRECT\n",
    )
    .await
    .unwrap();
    let output = rig.engine.mitm().run_script("Tool").await.unwrap();
    assert_eq!(output["result"], r#"{"title":"button"}"#, "{output}");
    assert_eq!(output["logs"], serde_json::json!(["pong"]));
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    rig.engine.network_changed();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "an event script ran while stopped"
    );
    rig.engine.start_listeners().await.unwrap();
    assert!(
        eventually(|| hits.load(Ordering::SeqCst) == 2).await,
        "engine-started"
    );
    rig.engine.network_changed();
    assert!(
        eventually(|| hits.load(Ordering::SeqCst) == 3).await,
        "network-changed"
    );
    rig.engine.stop_listeners().await.unwrap();
    rig.engine.network_changed();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        3,
        "an event script ran after the stop"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capabilities_report_ss_plugins_and_congestion_controllers() {
    let rig = Rig::new();
    let value = serde_json::to_value(rig.engine.capabilities()).unwrap();
    assert_eq!(
        value["ss-plugins"],
        serde_json::json!(["obfs", "v2ray-plugin", "shadow-tls"])
    );
    assert_eq!(
        value["congestion-controllers"],
        serde_json::json!(["cubic", "reno"])
    );
    rig.engine.shutdown().await;
}

fn ntp_reply(request: &[u8], skew_secs: u64) -> Vec<u8> {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + skew_secs
        + 2_208_988_800;
    let mut reply = vec![0u8; 48];
    reply[0] = 0x24;
    reply[1] = 2;
    reply[24..32].copy_from_slice(&request[40..48]);
    reply[32..40].copy_from_slice(&(unix << 32).to_be_bytes());
    reply[40..48].copy_from_slice(&(unix << 32).to_be_bytes());
    reply
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ntp_section_runs_a_service_that_a_config_without_it_stops() {
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 128];
        while let Ok((len, peer)) = server.recv_from(&mut buf).await {
            if len >= 48 {
                let _ = server.send_to(&ntp_reply(&buf[..len], 7200), peer).await;
            }
        }
    });
    let rig = Rig::new();
    rig.apply(&format!(
        "ntp:\n  enable: true\n  server: 127.0.0.1\n  port: {port}\n  interval: 30\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    let mut offset = 0;
    for _ in 0..100 {
        offset = rig.engine.clock_offset_nanos();
        if offset != 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        (offset - 7_200_000_000_000).abs() < 3_000_000_000,
        "offset {offset}"
    );

    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    for _ in 0..100 {
        if rig.engine.clock_offset_nanos() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rig.engine.clock_offset_nanos(), 0);
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_off_leaves_flows_alone_and_capabilities_say_it_exists() {
    let echo = tcp_echo().await;
    let rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    let mut stream = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut stream).await;
    assert!(rig.engine.capabilities().features.mitm);
    assert!(rig.engine.mitm().certificate().unwrap().is_none());
    rig.engine.shutdown().await;
}

/// A SOCKS5 server with UDP ASSOCIATE that counts the datagrams it relays.
async fn upstream_socks_udp() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let relayed = Arc::new(AtomicUsize::new(0));
    let count = relayed.clone();
    tokio::spawn(async move {
        while let Ok((mut control, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                control.read_exact(&mut greeting).await.ok()?;
                control.write_all(&[5, 0]).await.ok()?;
                let mut head = [0u8; 10];
                control.read_exact(&mut head).await.ok()?;
                let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.ok()?;
                let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                reply.extend_from_slice(&relay.local_addr().ok()?.port().to_be_bytes());
                control.write_all(&reply).await.ok()?;
                let (mut client, mut buf, mut idle) = (None, [0u8; 2048], [0u8; 1]);
                loop {
                    tokio::select! {
                        read = control.read(&mut idle) => {
                            if read.ok()? == 0 {
                                return Some(());
                            }
                        }
                        received = relay.recv_from(&mut buf) => {
                            let (len, from) = received.ok()?;
                            if client.is_none_or(|known| known == from) {
                                client = Some(from);
                                let dst = SocketAddr::from((
                                    Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]),
                                    u16::from_be_bytes([buf[8], buf[9]]),
                                ));
                                count.fetch_add(1, Ordering::SeqCst);
                                relay.send_to(&buf[10..len], dst).await.ok()?;
                            } else if let Some(client) = client {
                                let mut back = vec![0, 0, 0, 1];
                                if let SocketAddr::V4(from) = from {
                                    back.extend_from_slice(&from.ip().octets());
                                    back.extend_from_slice(&from.port().to_be_bytes());
                                }
                                back.extend_from_slice(&buf[..len]);
                                relay.send_to(&back, client).await.ok()?;
                            }
                        }
                    }
                }
            });
        }
    });
    (port, relayed)
}

struct Association {
    _control: TcpStream,
    relay: SocketAddr,
    socket: UdpSocket,
}

async fn associate(port: u16) -> Association {
    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    Association {
        _control: control,
        relay: SocketAddr::from((
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        )),
        socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
    }
}

impl Association {
    async fn echoes(&self, echo: SocketAddr) -> bool {
        let SocketAddr::V4(echo) = echo else {
            panic!("tests use IPv4 targets");
        };
        let mut packet = vec![0, 0, 0, 1];
        packet.extend_from_slice(&echo.ip().octets());
        packet.extend_from_slice(&echo.port().to_be_bytes());
        packet.extend_from_slice(b"datagram");
        let mut buf = [0u8; 256];
        for _ in 0..3 {
            self.socket.send_to(&packet, self.relay).await.unwrap();
            if let Ok(Ok((len, _))) =
                timeout(Duration::from_secs(1), self.socket.recv_from(&mut buf)).await
            {
                return &buf[len - 8..len] == b"datagram";
            }
        }
        false
    }
}

fn via_udp_proxy(proxy: u16) -> String {
    format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {proxy}, udp: true}}\n\
         rules:\n  - MATCH,up\n"
    )
}

/// Applying a second profile must not leave UDP behind, whether the listener keeps
/// its port or moves, and whether the listeners were stopped around the apply.
#[derive(Clone, Copy, Default)]
struct Switch {
    move_port: bool,
    stop_around: bool,
    open_to_lan: bool,
}

async fn udp_after_a_switch(switch: Switch) {
    let (echo, other) = (udp_echo().await, udp_echo().await);
    let (proxy, relayed) = upstream_socks_udp().await;
    let mut rig = Rig::new();
    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    rig.engine.start_listeners().await.unwrap();
    let before = associate(rig.mixed).await;
    assert!(before.echoes(echo).await);
    assert_eq!(relayed.load(Ordering::SeqCst), 0);

    if switch.stop_around {
        rig.engine.stop_listeners().await.unwrap();
    }
    if switch.move_port {
        rig.mixed = free_port();
    }
    let lan = if switch.open_to_lan {
        "allow-lan: true\n"
    } else {
        ""
    };
    rig.apply(&format!("{lan}{}", via_udp_proxy(proxy)))
        .await
        .unwrap();
    if switch.stop_around {
        rig.engine.start_listeners().await.unwrap();
    }

    let fresh = associate(rig.mixed).await;
    assert!(
        fresh.echoes(echo).await,
        "a fresh association gets no reply"
    );
    assert!(
        relayed.load(Ordering::SeqCst) > 0,
        "it did not take the new profile's proxy"
    );

    if !switch.move_port && !switch.stop_around && !switch.open_to_lan {
        assert!(
            before.echoes(other).await,
            "an association from before the switch lost UDP"
        );
    }
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_on_the_same_port() {
    udp_after_a_switch(Switch::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_that_moves_the_port() {
    udp_after_a_switch(Switch {
        move_port: true,
        ..Switch::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_between_a_stop_and_a_start() {
    udp_after_a_switch(Switch {
        stop_around: true,
        ..Switch::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_follows_a_profile_switch_that_opens_the_listener_to_the_lan() {
    udp_after_a_switch(Switch {
        open_to_lan: true,
        ..Switch::default()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_loads_report_their_outcome_only_once_the_apply_lets_them() {
    let rig = Rig::new();
    std::fs::write(
        rig.home.path().join("p.yaml"),
        "proxies:\n  - {name: pn, type: socks5, server: 127.0.0.1, port: 1}\n",
    )
    .unwrap();
    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    let hold = rig.engine.hold_first_loads();
    rig.apply(
        "proxy-providers:\n  sub: {type: file, path: p.yaml}\n\
         rule-providers:\n  local: {type: file, behavior: ipcidr, format: text, path: r.txt}\n\
         proxy-groups:\n  - {name: G, type: select, use: [sub]}\n\
         rules:\n  - RULE-SET,local,G\n  - MATCH,DIRECT\n",
    )
    .await
    .unwrap();
    assert!(
        eventually(|| rig
            .engine
            .providers()
            .list()
            .iter()
            .filter(|view| view.count == 1)
            .count()
            == 2)
        .await,
        "both providers load while every step is held"
    );
    assert!(
        rig.events.phases("sub").is_empty(),
        "{:?}",
        rig.events.phases("sub")
    );
    assert!(
        rig.events.phases("local").is_empty(),
        "{:?}",
        rig.events.phases("local")
    );

    drop(hold);
    let loaded = [ResourcePhase::Updating, ResourcePhase::Updated];
    assert!(
        eventually(|| rig.events.phases("sub") == loaded && rig.events.phases("local") == loaded)
            .await,
        "{:?} {:?}",
        rig.events.phases("sub"),
        rig.events.phases("local")
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_load_a_newer_apply_cuts_short_ends_superseded() {
    let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server = silent.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            held.push(stream);
        }
    });
    let rig = Rig::new();
    rig.apply(&format!(
        "proxy-providers:\n  slow: {{type: http, url: 'http://{server}/p.yaml', path: p.yaml}}\n\
         proxy-groups:\n  - {{name: G, type: select, use: [slow]}}\n\
         rules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    assert!(
        eventually(|| rig.events.phases("slow") == [ResourcePhase::Updating]).await,
        "{:?}",
        rig.events.phases("slow")
    );

    rig.apply("rules:\n  - MATCH,DIRECT\n").await.unwrap();
    let ended = [
        ResourcePhase::Updating,
        ResourcePhase::Failed(concord_common::SUPERSEDED.to_string()),
    ];
    assert!(
        eventually(|| rig.events.phases("slow") == ended).await,
        "{:?}",
        rig.events.phases("slow")
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_provider_reports_every_fetch_whatever_started_it() {
    let (server, _) = flaky_server("10.0.0.0/8\n".to_string()).await;
    let rig = Rig::new();
    let config = format!(
        "rule-providers:\n  local:\n    type: http\n    behavior: ipcidr\n    format: text\n    url: http://{server}/r.txt\n    path: rules/r.txt\n    interval: 1\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n"
    );
    rig.apply(&config).await.unwrap();
    assert!(
        eventually(|| rig.events.phases("local").len() >= 6).await,
        "{:?}",
        rig.events.phases("local")
    );
    let seen = rig.events.phases("local");
    assert!(
        matches!(
            seen[..6],
            [
                ResourcePhase::Updating,
                ResourcePhase::Failed(_),
                ResourcePhase::Updating,
                ResourcePhase::Updated,
                ResourcePhase::Updating,
                ResourcePhase::Unchanged,
            ]
        ),
        "first load, retry, interval: {seen:?}"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_provider_update_and_side_load_from_a_caller_are_reported() {
    let rig = Rig::new();
    std::fs::write(rig.home.path().join("r.txt"), "10.0.0.0/8\n").unwrap();
    rig.apply(
        "rule-providers:\n  local: {type: file, behavior: ipcidr, format: text, path: r.txt}\n\
         rules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n",
    )
    .await
    .unwrap();
    assert!(eventually(|| rig.events.phases("local").len() == 2).await);

    rig.engine.providers().update("local").await.unwrap();
    rig.engine
        .providers()
        .side_load("local", "192.168.0.0/16\n".to_string())
        .await
        .unwrap();
    assert_eq!(
        rig.events.phases("local")[..6],
        [
            ResourcePhase::Updating,
            ResourcePhase::Updated,
            ResourcePhase::Updating,
            ResourcePhase::Unchanged,
            ResourcePhase::Updating,
            ResourcePhase::Updated,
        ]
    );
    rig.engine.shutdown().await;
}
