use socket2::Socket;

const BUFFER: usize = 7 << 20;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn force(socket: &Socket, option: libc::c_int) -> bool {
    use std::os::fd::AsRawFd;

    let size = libc::c_int::try_from(BUFFER).unwrap_or(libc::c_int::MAX);
    // SAFETY: the pointer and length describe `size`, and the descriptor belongs to `socket`.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&size).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// `*FORCE` ignores `rmem_max` but needs CAP_NET_ADMIN; a plain request is clamped to it.
pub fn grow_udp_buffers(socket: &Socket) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if force(socket, libc::SO_RCVBUFFORCE) && force(socket, libc::SO_SNDBUFFORCE) {
        return;
    }
    let _ = socket.set_recv_buffer_size(BUFFER);
    let _ = socket.set_send_buffer_size(BUFFER);
}

#[cfg(test)]
mod tests {
    use socket2::{Domain, Protocol, Type};

    use super::*;

    #[test]
    fn a_grown_socket_holds_at_least_what_it_did_before() {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let before = socket.recv_buffer_size().unwrap();

        grow_udp_buffers(&socket);

        assert!(socket.recv_buffer_size().unwrap() >= before);
        assert!(socket.send_buffer_size().unwrap() > 0);
    }
}
