use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};

use socket2::Socket;
use tokio::net::UdpSocket;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;

    use socket2::{Domain, Socket, Type};
    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    use super::TproxyDatagram;

    const IP_ORIGDSTADDR: libc::c_int = 20;
    const IPV6_ORIGDSTADDR: libc::c_int = 74;

    fn set_flag(socket: &Socket, level: libc::c_int, option: libc::c_int) -> io::Result<()> {
        let value: libc::c_int = 1;
        // SAFETY: pointer and length describe `value`; the descriptor belongs to `socket`.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                std::ptr::from_ref(&value).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn prepare(socket: &Socket, is_v6: bool) -> io::Result<()> {
        socket.set_ip_transparent_v4(true)?;
        set_flag(socket, libc::SOL_IP, IP_ORIGDSTADDR)?;
        if is_v6 {
            socket.set_ip_transparent_v6(true)?;
            set_flag(socket, libc::SOL_IPV6, IPV6_ORIGDSTADDR)?;
        }
        // mihomo asks for the TOS byte too and carries on without it when refused.
        if set_flag(socket, libc::SOL_IP, libc::IP_RECVTOS).is_ok() && is_v6 {
            let _ = set_flag(socket, libc::SOL_IPV6, libc::IPV6_RECVTCLASS);
        }
        Ok(())
    }

    /// Bound to a foreign `from` and connected to `to`, so what it sends looks sent by `from`.
    pub fn bind_foreign(from: SocketAddr, to: SocketAddr) -> io::Result<std::net::UdpSocket> {
        if from.is_ipv4() != to.is_ipv4() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let socket = Socket::new(Domain::for_address(from), Type::DGRAM, None)?;
        socket.set_reuse_address(true)?;
        if from.is_ipv6() {
            socket.set_ip_transparent_v6(true)?;
        } else {
            socket.set_ip_transparent_v4(true)?;
        }
        socket.bind(&from.into())?;
        socket.connect(&to.into())?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    }

    fn socket_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
        match i32::from(storage.ss_family) {
            libc::AF_INET => {
                // SAFETY: the family says the storage holds a `sockaddr_in`.
                let sin = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
                Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 => {
                // SAFETY: as above, for `sockaddr_in6`.
                let sin6 = unsafe { &*std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    0,
                    0,
                )))
            }
            _ => None,
        }
    }

    fn receive(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<TproxyDatagram> {
        // SAFETY: both are plain data that `recvmsg` fills in.
        let (mut name, mut msg): (libc::sockaddr_storage, libc::msghdr) =
            unsafe { (zeroed(), zeroed()) };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u64; 64];
        msg.msg_name = (&raw mut name).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[u64; 64]>() as _;
        // SAFETY: every pointer in `msg` is to a buffer that outlives the call.
        let read = unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut msg, 0) };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        let src = socket_addr(&name).ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        let (mut dst, mut tos) = (None, None);
        // SAFETY: the CMSG macros walk what the kernel wrote within `msg_controllen`.
        unsafe {
            let mut header = libc::CMSG_FIRSTHDR(&raw const msg);
            while !header.is_null() {
                let data = libc::CMSG_DATA(header);
                match ((*header).cmsg_level, (*header).cmsg_type) {
                    (libc::SOL_IP, IP_ORIGDSTADDR) => {
                        let sin = std::ptr::read_unaligned(data.cast::<libc::sockaddr_in>());
                        dst = Some(SocketAddr::V4(SocketAddrV4::new(
                            Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                            u16::from_be(sin.sin_port),
                        )));
                    }
                    (libc::SOL_IPV6, IPV6_ORIGDSTADDR) => {
                        let sin6 = std::ptr::read_unaligned(data.cast::<libc::sockaddr_in6>());
                        dst = Some(SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                            u16::from_be(sin6.sin6_port),
                            0,
                            0,
                        )));
                    }
                    (libc::SOL_IP, libc::IP_TOS) => {
                        tos = tos.or(Some(std::ptr::read_unaligned(data.cast::<u8>())));
                    }
                    (libc::SOL_IPV6, libc::IPV6_TCLASS) => {
                        let class = std::ptr::read_unaligned(data.cast::<libc::c_int>());
                        tos = tos.or(Some(class.to_le_bytes()[0]));
                    }
                    _ => {}
                }
                header = libc::CMSG_NXTHDR(&raw const msg, header);
            }
        }
        let dst = dst.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(TproxyDatagram {
            len: read as usize,
            src,
            dst,
            dscp: tos.unwrap_or(0) >> 2,
        })
    }

    pub fn recv(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<TproxyDatagram> {
        socket.try_io(Interest::READABLE, || receive(socket, buf))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[allow(
            clippy::disallowed_methods,
            reason = "the test sends from and to loopback"
        )]
        #[tokio::test]
        async fn a_listener_that_asks_for_it_reports_the_destination_of_each_datagram() {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
            set_flag(&socket, libc::SOL_IP, IP_ORIGDSTADDR).unwrap();
            socket
                .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
                .unwrap();
            socket.set_nonblocking(true).unwrap();
            let listener = UdpSocket::from_std(socket.into()).unwrap();
            let target = listener.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(b"hello", target).await.unwrap();

            listener.readable().await.unwrap();
            let mut buf = [0u8; 64];
            let got = recv(&listener, &mut buf).unwrap();
            assert_eq!(buf.get(..got.len), Some(&b"hello"[..]));
            assert_eq!(got.src, client.local_addr().unwrap());
            assert_eq!(got.dst, target);
        }

        #[allow(
            clippy::disallowed_methods,
            reason = "the test sends from and to loopback"
        )]
        #[test]
        fn a_datagram_without_an_original_destination_is_invalid_data() {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
            socket
                .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
                .unwrap();
            let target = socket.local_addr().unwrap().as_socket().unwrap();
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.send_to(b"x", target).unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut buf = [0u8; 8];
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let err = rt.block_on(async {
                let listener = UdpSocket::from_std(socket.into()).unwrap();
                listener.readable().await.unwrap();
                recv(&listener, &mut buf).unwrap_err()
            });
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
    }
}

/// Lets a `TPROXY` UDP socket receive for foreign addresses and see each original destination.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn prepare_tproxy_udp(socket: &Socket, is_v6: bool) -> io::Result<()> {
    linux::prepare(socket, is_v6)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn prepare_tproxy_udp(_socket: &Socket, _is_v6: bool) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TproxyDatagram {
    pub len: usize,
    pub src: SocketAddr,
    /// The original destination.
    pub dst: SocketAddr,
    pub dscp: u8,
}

/// One datagram with its original destination; `InvalidData` when it has none.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn recv_original_dst(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<TproxyDatagram> {
    linux::recv(socket, buf)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn recv_original_dst(_socket: &UdpSocket, _buf: &mut [u8]) -> io::Result<TproxyDatagram> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_foreign_udp(from: SocketAddr, to: SocketAddr) -> io::Result<StdUdpSocket> {
    linux::bind_foreign(from, to)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn bind_foreign_udp(_from: SocketAddr, _to: SocketAddr) -> io::Result<StdUdpSocket> {
    Err(io::ErrorKind::Unsupported.into())
}
