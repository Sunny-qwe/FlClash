#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "the peers here stand for the outside world, not the core's own sockets"
)]

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use concord_api::{Control, ControlOptions, EventBus};
use concord_engine::{Engine, EngineConfig};
use concord_ipc::{
    AuthError, FramedChannel, FramedReader, FramedWriter, Token, dial, initiate, respond,
};
use concord_platform::NativePlatform;
use concord_rpc::{Incoming, MessageChannel, MessageReader, MessageWriter, Server, ServerConfig};
use concord_test_support::free_port;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(20);
const TOKEN: &str = "00112233445566778899aabbccddeeff";
const OTHER: &str = "ffeeddccbbaa99887766554433221100";

fn token(text: &str) -> Token {
    Token::parse(text).unwrap()
}

struct Peer {
    reader: FramedReader<UnixStream>,
    writer: FramedWriter<UnixStream>,
    next: u64,
    events: Vec<Value>,
}

impl Peer {
    async fn send(&mut self, value: Value) {
        let bytes = serde_json::to_vec(&value).unwrap();
        self.writer.send(bytes).await.ok().unwrap();
    }

    async fn message(&mut self) -> Value {
        match timeout(PATIENCE, self.reader.recv()).await {
            Ok(Ok(Some(Incoming::Message(bytes)))) => serde_json::from_slice(&bytes).unwrap(),
            other => panic!("no message: {other:?}"),
        }
    }

    async fn request(&mut self, method: &str, params: Value) -> u64 {
        self.next += 1;
        let id = self.next;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        id
    }

    async fn response(&mut self, id: u64) -> Value {
        loop {
            let message = self.message().await;
            if message["id"] == json!(id) {
                return message;
            }
            if message["method"] == "$/event" {
                self.events.push(message);
            }
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.request(method, params).await;
        self.response(id).await
    }

    async fn ok(&mut self, method: &str, params: Value) -> Value {
        let answer = self.call(method, params).await;
        assert!(answer.get("error").is_none(), "{method}: {answer}");
        answer["result"].clone()
    }

    async fn event_where(&mut self, mut found: impl FnMut(&Value) -> bool) -> Value {
        let mut index = 0;
        loop {
            if index == self.events.len() {
                let message = self.message().await;
                if message["method"] == "$/event" {
                    self.events.push(message);
                }
                continue;
            }
            if found(&self.events[index]["params"]) {
                return self.events.remove(index)["params"].clone();
            }
            index += 1;
        }
    }
}

struct Core {
    peer: Peer,
    engine: Arc<Engine>,
    bus: Arc<EventBus>,
    serving: tokio::task::JoinHandle<()>,
    dir: tempfile::TempDir,
}

async fn connect(limit: Option<u64>) -> Core {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("host.sock");
    let listener = UnixListener::bind(&socket).unwrap();

    let bus = EventBus::new();
    let engine = Engine::new(EngineConfig {
        sink: bus.clone(),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    let control = Control::new(engine.clone(), bus.clone(), ControlOptions::default());
    let address = socket.to_str().unwrap().to_string();
    let serving = tokio::spawn(async move {
        let mut connection = dial(&address).await.unwrap();
        initiate(&mut connection, &token(TOKEN)).await.unwrap();
        let channel = match limit {
            Some(limit) => FramedChannel::with_limit(connection, limit),
            None => FramedChannel::new(connection),
        };
        let server = Server::with_config(
            control,
            ServerConfig {
                max_message: limit.unwrap_or(concord_proto::MAX_MESSAGE),
            },
        );
        server.serve(channel).await;
    });
    let (mut stream, _) = listener.accept().await.unwrap();
    respond(&mut stream, &token(TOKEN)).await.unwrap();
    let (reader, writer) = FramedChannel::new(stream).split();
    let mut peer = Peer {
        reader,
        writer,
        next: 0,
        events: Vec::new(),
    };
    peer.ok(
        "core.hello",
        json!({"protocol": {"min": 1, "max": 1}, "client": {"name": "test", "version": "0"}}),
    )
    .await;
    Core {
        peer,
        engine,
        bus,
        serving,
        dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_engine_runs_from_hello_to_a_closed_connection_over_the_socket() {
    let Core {
        mut peer,
        engine,
        bus,
        serving,
        dir,
    } = connect(None).await;
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let proxy = free_port();
    std::fs::write(
        home.join("config.yaml"),
        format!(
            "mixed-port: {proxy}\n\
             proxies:\n  - {{name: a, type: socks5, server: 127.0.0.1, port: 1}}\n\
             proxy-groups:\n  - {{name: G, type: select, proxies: [DIRECT, a]}}\n\
             rules:\n  - MATCH,G\n"
        ),
    )
    .unwrap();

    peer.ok("core.init", json!({"home": home.to_str().unwrap()}))
        .await;
    let state = peer.ok("engine.state", json!({})).await;
    assert_eq!(state["snapshot"]["state"], "initialized", "{state}");
    let applied = peer.ok("config.apply", json!({})).await;
    assert_eq!(applied["warnings"], json!([]));

    let groups = peer.ok("proxy.groups", Value::Null).await;
    assert_eq!(groups["order"], json!(["GLOBAL", "G"]));
    let selected = peer
        .ok("proxy.select", json!({"group": "G", "proxy": "DIRECT"}))
        .await;
    assert!(selected["changed"].is_boolean());
    let missing = peer
        .call("proxy.select", json!({"group": "G", "proxy": "nope"}))
        .await;
    assert_eq!(missing["error"]["data"]["kind"], "not_found", "{missing}");

    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 {
                        return;
                    }
                }
            });
        }
    });
    peer.ok("engine.start", json!({})).await;
    let watching = peer
        .ok("connection.watch", json!({"maxBatchMs": 0, "credit": 1000}))
        .await;
    assert_eq!(watching["snapshot"]["connections"], json!([]));
    let traffic = peer
        .ok(
            "traffic.watch",
            json!({"intervalMs": 100, "maxBatchMs": 0, "credit": 1000}),
        )
        .await;
    assert_eq!(traffic["snapshot"]["totalUp"], 0);

    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .unwrap();
    client
        .write_all(
            format!("CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    client.write_all(b"hello").await.unwrap();

    let opened = peer
        .event_where(|params| params["data"][0]["opened"].is_array())
        .await;
    let connection = &opened["data"][0]["opened"][0];
    assert_eq!(connection["destinationPort"], target_port);
    assert_eq!(connection["network"], "tcp");
    let id = connection["id"].as_u64().unwrap();
    peer.event_where(|params| {
        params["data"][0]["counters"]
            .as_array()
            .is_some_and(|counters| {
                counters
                    .iter()
                    .any(|c| c["id"] == id && c["upload"].as_u64() >= Some(5))
            })
    })
    .await;
    peer.event_where(|params| params["data"][0]["up"].is_i64())
        .await;

    drop(client);
    peer.event_where(|params| params["data"][0]["closed"] == json!([id]))
        .await;

    let cancelled = peer.request("delay.test", json!({"proxy": "DIRECT", "url": format!("http://127.0.0.1:{target_port}/slow"), "timeout": 30000})).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    peer.send(json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": cancelled}}))
        .await;
    let answer = peer.response(cancelled).await;
    assert_eq!(answer["error"]["data"]["kind"], "cancelled", "{answer}");

    assert!(bus.subscribers() >= 1);
    drop(peer);
    timeout(Duration::from_secs(10), serving)
        .await
        .expect("serve outlived the socket")
        .unwrap();
    assert_eq!(
        bus.subscribers(),
        0,
        "the disconnect left subscriptions behind"
    );
    engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_above_the_limit_is_answered_with_payload_too_large_and_the_stream_stays_in_step()
{
    let Core { mut peer, .. } = connect(Some(1024 * 1024)).await;
    let big = vec![b'x'; 2 * 1024 * 1024];
    peer.writer.send(big).await.ok().unwrap();

    let answer = peer.message().await;

    assert_eq!(answer["id"], Value::Null, "{answer}");
    assert_eq!(answer["error"]["data"]["kind"], "payload_too_large");
    assert_eq!(answer["error"]["data"]["limit"], 1024 * 1024);
    let after = peer.ok("core.stats", Value::Null).await;
    assert!(after["rss"].as_u64().unwrap() > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_reader_does_not_lose_or_reorder_responses() {
    let Core { mut peer, .. } = connect(None).await;
    let mut ids = Vec::new();
    for _ in 0..200 {
        ids.push(peer.request("core.stats", Value::Null).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut seen = Vec::new();
    for _ in 0..200 {
        let message = peer.message().await;
        seen.push(message["id"].as_u64().unwrap());
    }
    seen.sort_unstable();
    assert_eq!(seen, ids);
}

async fn listener_in(dir: &tempfile::TempDir) -> (UnixListener, String) {
    let path = dir.path().join("stale.sock");
    let listener = UnixListener::bind(&path).unwrap();
    (listener, path.to_str().unwrap().to_owned())
}

fn hello_frame() -> Vec<u8> {
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "core.hello",
        "params": {"protocol": {"min": 1, "max": 1}, "client": {"name": "t", "version": "0"}}
    }))
    .unwrap();
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

#[tokio::test]
async fn a_stale_listener_that_does_not_know_the_token_gets_only_a_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let (listener, address) = listener_in(&dir).await;
    let stale = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = respond(&mut stream, &token(OTHER)).await;
        stream.write_all(&hello_frame()).await.ok();
        let mut rest = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut rest))
            .await
            .ok();
        rest
    });

    let mut connection = dial(&address).await.unwrap();
    let result = initiate(&mut connection, &token(TOKEN)).await;
    drop(connection);

    assert!(matches!(result, Err(AuthError::Rejected)), "{result:?}");
    assert!(stale.await.unwrap().is_empty());
}

#[tokio::test]
async fn a_listener_that_speaks_rpc_without_authenticating_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (listener, address) = listener_in(&dir).await;
    let stale = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(&hello_frame()).await.unwrap();
        let mut received = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut received))
            .await
            .ok();
        received
    });

    let mut connection = dial(&address).await.unwrap();
    let result = initiate(&mut connection, &token(TOKEN)).await;
    drop(connection);

    assert!(result.is_err());
    let received = stale.await.unwrap();
    assert_eq!(received.len(), 4 + 16, "only the opening nonce may leave");
}

#[tokio::test]
async fn a_listener_that_never_answers_is_abandoned_after_the_handshake_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let (listener, address) = listener_in(&dir).await;
    let silent = tokio::spawn(async move { listener.accept().await.unwrap() });

    let mut connection = dial(&address).await.unwrap();
    let started = tokio::time::Instant::now();
    let result = initiate(&mut connection, &token(TOKEN)).await;

    assert!(matches!(result, Err(AuthError::Timeout)), "{result:?}");
    assert!(started.elapsed() < concord_ipc::HANDSHAKE_TIMEOUT + Duration::from_secs(2));
    drop(silent.await.unwrap());
}

#[tokio::test]
async fn a_peer_with_another_token_never_reaches_the_rpc_layer_of_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let (listener, address) = listener_in(&dir).await;
    let wrong = tokio::spawn(async move {
        let mut connection = dial(&address).await.unwrap();
        let result = initiate(&mut connection, &token(OTHER)).await;
        let mut leftover = Vec::new();
        timeout(
            Duration::from_secs(2),
            connection.read_to_end(&mut leftover),
        )
        .await
        .ok();
        (result, leftover)
    });

    let (mut stream, _) = listener.accept().await.unwrap();
    let host = respond(&mut stream, &token(TOKEN)).await;
    drop(stream);

    assert!(host.is_err());
    let (guest, leftover) = wrong.await.unwrap();
    assert!(guest.is_err());
    assert!(leftover.is_empty());
}
