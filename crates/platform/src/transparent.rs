use std::io;
use std::net::SocketAddr;

use socket2::Socket;
use tokio::net::TcpStream;

/// Windows keeps SO_REUSEADDR off because there it lets another process take the port.
pub fn prepare_listener(socket: &Socket, dual_stack: bool) -> io::Result<()> {
    if dual_stack {
        socket.set_only_v6(false)?;
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn make_transparent(socket: &Socket, is_v6: bool) -> io::Result<()> {
    if is_v6 {
        socket.set_ip_transparent_v6(true)
    } else {
        socket.set_ip_transparent_v4(true)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn make_transparent(_socket: &Socket, _is_v6: bool) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

/// macOS answers through `DIOCNATLOOK` on `/dev/pf`: IPv4 only, and root.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn original_dst(conn: &TcpStream) -> io::Result<SocketAddr> {
    let local = conn.local_addr()?;
    let socket = socket2::SockRef::from(conn);
    let original = if concord_common::addr::unmap(local.ip()).is_ipv4() {
        socket.original_dst_v4()?
    } else {
        socket.original_dst_v6()?
    };
    original
        .as_socket()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}

#[cfg(target_os = "macos")]
pub fn original_dst(conn: &TcpStream) -> io::Result<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr};

    const DIOCNATLOOK: libc::c_ulong = 0xC054_4417;
    const PF_OUT: u8 = 2;

    #[repr(C)]
    struct NatLook {
        saddr: [u8; 16],
        daddr: [u8; 16],
        rsaddr: [u8; 16],
        rdaddr: [u8; 16],
        sxport: [u8; 4],
        dxport: [u8; 4],
        rsxport: [u8; 4],
        rdxport: [u8; 4],
        af: u8,
        proto: u8,
        proto_variant: u8,
        direction: u8,
    }

    let (peer, local) = (conn.peer_addr()?, conn.local_addr()?);
    let (IpAddr::V4(peer_ip), IpAddr::V4(local_ip)) = (
        concord_common::addr::unmap(peer.ip()),
        concord_common::addr::unmap(local.ip()),
    ) else {
        return Err(io::ErrorKind::Unsupported.into());
    };
    let mut lookup = NatLook {
        saddr: [0; 16],
        daddr: [0; 16],
        rsaddr: [0; 16],
        rdaddr: [0; 16],
        sxport: [0; 4],
        dxport: [0; 4],
        rsxport: [0; 4],
        rdxport: [0; 4],
        af: libc::AF_INET as u8,
        proto: libc::IPPROTO_TCP as u8,
        proto_variant: 0,
        direction: PF_OUT,
    };
    lookup.saddr[..4].copy_from_slice(&peer_ip.octets());
    lookup.daddr[..4].copy_from_slice(&local_ip.octets());
    lookup.sxport[..2].copy_from_slice(&peer.port().to_be_bytes());
    lookup.dxport[..2].copy_from_slice(&local.port().to_be_bytes());

    // SAFETY: the path is NUL-terminated and the returned descriptor is closed below.
    let fd = unsafe { libc::open(c"/dev/pf".as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `lookup` is a live `repr(C)` value of the 84 bytes DIOCNATLOOK encodes.
    let rc = unsafe { libc::ioctl(fd, DIOCNATLOOK, &mut lookup as *mut NatLook) };
    let error = io::Error::last_os_error();
    // SAFETY: `fd` was opened above and is not used after this.
    unsafe { libc::close(fd) };
    if rc != 0 {
        return Err(error);
    }
    let [a, b, c, d] = [
        lookup.rdaddr[0],
        lookup.rdaddr[1],
        lookup.rdaddr[2],
        lookup.rdaddr[3],
    ];
    let port = u16::from_be_bytes([lookup.rdxport[0], lookup.rdxport[1]]);
    Ok(SocketAddr::new(Ipv4Addr::new(a, b, c, d).into(), port))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn original_dst(_conn: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_listener_prepared_for_reuse_binds_a_wildcard() {
        let socket = Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None).unwrap();
        prepare_listener(&socket, true).unwrap();
        socket
            .bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        socket.listen(1).unwrap();
    }

    #[cfg(unix)]
    #[allow(
        clippy::disallowed_methods,
        reason = "the test dials its own loopback listener"
    )]
    #[tokio::test]
    async fn an_unredirected_connection_reports_no_other_destination() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(
            async { std::net::TcpStream::connect(addr).unwrap() },
            listener.accept()
        );
        let (stream, _) = accepted.unwrap();
        // With conntrack loaded, Linux answers with the address the connection reached.
        if let Ok(original) = original_dst(&stream) {
            assert_eq!(original, addr);
        }
        drop(client);
    }
}
