#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(
    unsafe_code,
    reason = "restores SIGPIPE's default in this isolated test binary"
)]

use std::io::{ErrorKind, IoSlice};
use std::net::Shutdown;

use concord_test_support::std_tcp_pair;

#[test]
fn a_vectored_send_returns_broken_pipe_with_the_default_signal_disposition() {
    // SAFETY: SIG_DFL is valid, and this test binary runs no other tests.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let (socket, _peer) = std_tcp_pair();
    socket.shutdown(Shutdown::Write).unwrap();
    socket.set_nonblocking(true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    let _entered = runtime.enter();
    let socket = tokio::net::TcpStream::from_std(socket).unwrap();
    let err =
        concord_platform::send_tcp_vectored(&socket, &[IoSlice::new(b"one"), IoSlice::new(b"two")])
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BrokenPipe);
}
