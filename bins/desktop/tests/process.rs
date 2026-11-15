#![allow(
    clippy::disallowed_methods,
    reason = "the host side of the socket is the app, not the core's own dial"
)]

use std::io::{Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use concord_ipc::{Token, respond};

const BINARY: &str = env!("CARGO_BIN_EXE_concord");
const TOKEN: &str = "00112233445566778899aabbccddeeff";
const OTHER: &str = "ffeeddccbbaa99887766554433221100";

fn token(text: &str) -> Token {
    Token::parse(text).unwrap()
}

fn spawn(argument: Option<&str>) -> Child {
    spawn_with(argument, Some(TOKEN))
}

fn spawn_with(argument: Option<&str>, token: Option<&str>) -> Child {
    let mut command = Command::new(BINARY);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(argument) = argument {
        command.arg(argument);
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    if let Some(token) = token {
        let _ = writeln!(stdin, "{token}");
    }
    drop(stdin);
    child
}

fn wait_for_exit(child: &mut Child, within: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

async fn ask<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, call: Value) -> Value {
    let body = serde_json::to_vec(&call).unwrap();
    stream
        .write_all(&(body.len() as u32).to_le_bytes())
        .await
        .unwrap();
    stream.write_all(&body).await.unwrap();
    loop {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let mut payload = vec![0u8; u32::from_le_bytes(header) as usize];
        stream.read_exact(&mut payload).await.unwrap();
        let value: Value = serde_json::from_slice(&payload).unwrap();
        if value.get("id") == call.get("id") {
            return value;
        }
    }
}

async fn hello<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Value {
    ask(
        stream,
        json!({"jsonrpc": "2.0", "id": 1, "method": "core.hello", "params": {
            "protocol": {"min": 1, "max": 1},
            "client": {"name": "test", "version": "0"}}}),
    )
    .await
}

#[test]
fn without_an_address_it_says_so_and_exits_with_one() {
    let mut child = spawn(None);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    let status = child.wait().unwrap();

    assert_eq!(status.code(), Some(1));
    assert!(stderr.contains("Arguments error"), "{stderr}");
}

async fn serve_over_tcp() -> (Child, tokio::net::TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let child = spawn(Some(&port));
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .expect("the core did not dial")
        .unwrap();
    respond(&mut stream, &token(TOKEN)).await.unwrap();
    (child, stream)
}

#[tokio::test]
async fn an_all_digit_address_is_a_loopback_tcp_port_the_core_dials() {
    let (mut child, mut stream) = serve_over_tcp().await;

    let answer = hello(&mut stream).await;

    assert_eq!(answer["result"]["protocol"], 1);
    assert_eq!(answer["result"]["engine"]["state"], "created");
    kill_and_reap(&mut child);
}

#[tokio::test]
async fn the_core_exits_within_three_seconds_of_the_host_disconnecting() {
    let (mut child, mut stream) = serve_over_tcp().await;
    hello(&mut stream).await;

    let dropped = Instant::now();
    drop(stream);
    let status = tokio::task::spawn_blocking(move || {
        let status = wait_for_exit(&mut child, Duration::from_secs(8));
        if status.is_none() {
            kill_and_reap(&mut child);
        }
        status
    })
    .await
    .unwrap();

    assert_eq!(status.map(|status| status.success()), Some(true));
    assert!(dropped.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn the_core_stays_the_process_that_was_started_with_stderr_open_until_it_exits() {
    let (mut child, mut stream) = serve_over_tcp().await;
    let started_pid = child.id();
    let reached_eof = Arc::new(AtomicBool::new(false));
    let flag = reached_eof.clone();
    let mut stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = stderr.read_to_end(&mut sink);
        flag.store(true, Ordering::SeqCst);
    });
    hello(&mut stream).await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "the started process left while serving"
    );
    assert_eq!(child.id(), started_pid);
    assert!(
        !reached_eof.load(Ordering::SeqCst),
        "stderr was closed while the core was serving"
    );

    drop(stream);
    let waited = tokio::task::spawn_blocking(move || {
        let status = wait_for_exit(&mut child, Duration::from_secs(8));
        if status.is_none() {
            kill_and_reap(&mut child);
        }
        reader.join().unwrap();
        status
    })
    .await
    .unwrap();
    assert!(waited.is_some());
    assert!(reached_eof.load(Ordering::SeqCst));
}

#[cfg(unix)]
#[tokio::test]
async fn a_socket_path_is_dialled_and_sigterm_ends_the_core_within_three_seconds() {
    use tokio::net::UnixListener;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut child = spawn(Some(path.to_str().unwrap()));
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .expect("the core did not dial")
        .unwrap();
    respond(&mut stream, &token(TOKEN)).await.unwrap();
    hello(&mut stream).await;

    let signalled = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signalled.success());
    let sent = Instant::now();
    let status = tokio::task::spawn_blocking(move || {
        let status = wait_for_exit(&mut child, Duration::from_secs(8));
        if status.is_none() {
            kill_and_reap(&mut child);
        }
        status
    })
    .await
    .unwrap();

    assert_eq!(status.map(|status| status.success()), Some(true));
    assert!(
        sent.elapsed() < Duration::from_secs(4),
        "{:?}",
        sent.elapsed()
    );
}

fn stderr_of(child: &mut Child) -> String {
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    stderr
}

async fn exit_of(mut child: Child, within: Duration) -> (Option<ExitStatus>, String) {
    tokio::task::spawn_blocking(move || {
        let status = wait_for_exit(&mut child, within);
        if status.is_none() {
            kill_and_reap(&mut child);
        }
        let stderr = stderr_of(&mut child);
        (status, stderr)
    })
    .await
    .unwrap()
}

fn assert_no_token(text: &str) {
    for secret in [TOKEN, OTHER] {
        assert!(!text.contains(secret), "a session token reached: {text}");
    }
}

#[test]
fn without_a_token_on_standard_input_the_core_exits_before_dialling() {
    let mut child = spawn_with(Some("1"), None);
    let stderr = stderr_of(&mut child);

    let status = child.wait().unwrap();

    assert_eq!(status.code(), Some(1));
    assert!(stderr.contains("session token: missing"), "{stderr}");
}

#[test]
fn a_malformed_token_is_refused_without_echoing_it() {
    let mut child = spawn_with(Some("1"), Some("not-a-token-but-secret"));
    let stderr = stderr_of(&mut child);

    assert_eq!(child.wait().unwrap().code(), Some(1));
    assert!(stderr.contains("session token: malformed"), "{stderr}");
    assert!(!stderr.contains("not-a-token-but-secret"));
}

#[tokio::test]
async fn a_listener_that_does_not_know_the_token_gets_nothing_but_a_nonce() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let child = spawn(Some(&port));
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .expect("the core did not dial")
        .unwrap();

    let outcome = respond(&mut stream, &token(OTHER)).await;
    let mut hello_bytes = Vec::new();
    let _ =
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut hello_bytes)).await;
    let (status, stderr) = exit_of(child, Duration::from_secs(8)).await;

    assert!(outcome.is_err());
    assert_eq!(status.and_then(|status| status.code()), Some(1), "{stderr}");
    assert!(stderr.contains("ipc authentication"), "{stderr}");
    assert!(
        hello_bytes.is_empty(),
        "the core kept talking: {hello_bytes:?}"
    );
    assert_no_token(&stderr);
}

#[tokio::test]
async fn a_listener_that_speaks_before_proving_anything_is_never_answered() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let child = spawn(Some(&port));
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .expect("the core did not dial")
        .unwrap();
    let call = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "core.hello", "params": {
            "protocol": {"min": 1, "max": 1}, "client": {"name": "t", "version": "0"}}}))
    .unwrap();
    stream
        .write_all(&(call.len() as u32).to_le_bytes())
        .await
        .unwrap();
    stream.write_all(&call).await.unwrap();

    let mut received = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut received)).await;
    let (status, _) = exit_of(child, Duration::from_secs(8)).await;

    assert_eq!(status.and_then(|status| status.code()), Some(1));
    assert_eq!(received.len(), 4 + 16, "only the opening nonce may leave");
}

#[tokio::test]
async fn a_listener_that_never_answers_ends_the_core_after_the_handshake_timeout() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let child = spawn(Some(&port));
    let (_silent, _) = tokio::time::timeout(Duration::from_secs(20), listener.accept())
        .await
        .expect("the core did not dial")
        .unwrap();
    let accepted = Instant::now();

    let (status, stderr) = exit_of(child, Duration::from_secs(12)).await;

    assert_eq!(status.and_then(|status| status.code()), Some(1), "{stderr}");
    assert!(accepted.elapsed() < concord_ipc::HANDSHAKE_TIMEOUT + Duration::from_secs(3));
    assert!(stderr.contains("did not answer in time"), "{stderr}");
}

#[cfg(unix)]
fn command_line_of(pid: u32) -> String {
    let output = Command::new("ps")
        .args(["-ww", "-o", "command=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[cfg(unix)]
#[tokio::test]
async fn the_token_is_in_neither_the_command_line_nor_the_output_of_a_running_core() {
    let (child, mut stream) = serve_over_tcp().await;
    hello(&mut stream).await;

    let command_line = command_line_of(child.id());
    #[cfg(target_os = "linux")]
    let environment = std::fs::read(format!("/proc/{}/environ", child.id())).unwrap();
    #[cfg(not(target_os = "linux"))]
    let environment: Vec<u8> = Vec::new();
    drop(stream);
    let (status, output) = exit_of(child, Duration::from_secs(8)).await;

    assert!(status.is_some());
    assert!(command_line.contains(BINARY), "{command_line}");
    assert_no_token(&command_line);
    assert_no_token(&String::from_utf8_lossy(&environment));
    assert_no_token(&output);
}

#[tokio::test]
async fn a_release_core_does_not_offer_debug_crash_even_when_asked() {
    if cfg!(feature = "debug") {
        return;
    }
    let (mut child, mut stream) = serve_over_tcp().await;

    let answer = ask(
        &mut stream,
        json!({"jsonrpc": "2.0", "id": 1, "method": "core.hello", "params": {
            "protocol": {"min": 1, "max": 1},
            "client": {"name": "test", "version": "0"},
            "capabilities": ["debug"]}}),
    )
    .await;
    let methods = answer["result"]["methods"].as_array().unwrap();
    let crash = ask(
        &mut stream,
        json!({"jsonrpc": "2.0", "id": 2, "method": "debug.crash"}),
    )
    .await;

    assert!(!methods.contains(&json!("debug.crash")));
    assert_eq!(crash["error"]["data"]["kind"], "unsupported", "{crash}");
    kill_and_reap(&mut child);
}
