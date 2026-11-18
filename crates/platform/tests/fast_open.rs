#![cfg(target_os = "macos")]
#![allow(
    unsafe_code,
    reason = "reads TCP_CONNECTION_INFO and sets TCP_FASTOPEN on a listener"
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;

use concord_platform::preconnect;
use socket2::{Domain, Socket, Type};

fn set(fd: i32, option: libc::c_int) {
    let on: libc::c_int = 1;
    // SAFETY: pointer and length describe `on`; `fd` is open.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            option,
            std::ptr::from_ref(&on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
}

/// The leading fields of XNU's `struct tcp_connection_info` (`bsd/netinet/tcp.h`), through the
/// word that packs the TFO bits; libc 0.2.191 declares each of those bits as its own `u32`.
#[repr(C)]
#[derive(Default)]
struct ConnectionInfo {
    _state_and_scales: [u8; 4],
    _options_to_rttvar: [u32; 12],
    tfo: u32,
}

const SYN_DATA_SENT: u32 = 1 << 3;
const SYN_DATA_ACKED: u32 = 1 << 4;
const SYN_DATA_RCV: u32 = 1 << 5;

fn tfo_bits(fd: i32) -> u32 {
    let mut info = ConnectionInfo::default();
    let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
    // SAFETY: pointer and length describe `info`, a prefix the kernel fills up to `len`; `fd`
    // is open.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            std::ptr::from_mut(&mut info).cast(),
            &raw mut len,
        )
    };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    info.tfo
}

fn fast_open_listener() -> TcpListener {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    set(socket.as_raw_fd(), 0x218);
    socket
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    socket.listen(16).unwrap();
    set(socket.as_raw_fd(), libc::TCP_FASTOPEN);
    socket.into()
}

fn exchange(listener: &TcpListener, request: &[u8]) -> (u32, u32) {
    let target = listener.local_addr().unwrap();
    let client = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    assert!(preconnect(&client, target).unwrap());
    let mut client = TcpStream::from(client);
    client.write_all(request).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    let mut got = vec![0; request.len()];
    peer.read_exact(&mut got).unwrap();
    assert_eq!(got, request);
    peer.write_all(&got).unwrap();
    client.read_exact(&mut got).unwrap();
    (tfo_bits(client.as_raw_fd()), tfo_bits(peer.as_raw_fd()))
}

#[test]
fn the_first_write_rides_the_syn_once_a_cookie_is_cached() {
    let listener = fast_open_listener();
    exchange(&listener, b"cookie please");
    let (client, server) = exchange(&listener, b"early data");
    assert_ne!(client & SYN_DATA_SENT, 0, "{client:#x}");
    assert_ne!(client & SYN_DATA_ACKED, 0, "{client:#x}");
    assert_ne!(server & SYN_DATA_RCV, 0, "{server:#x}");
}

#[test]
fn a_server_without_fast_open_gets_the_data_after_the_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    for _ in 0..2 {
        let (client, server) = exchange(&listener, b"plain");
        assert_eq!(client & SYN_DATA_ACKED, 0, "{client:#x}");
        assert_eq!(server & SYN_DATA_RCV, 0, "{server:#x}");
    }
}
