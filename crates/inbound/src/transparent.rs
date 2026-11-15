use std::io;
use std::net::SocketAddr;

use concord_common::{Address, InboundKind};
pub use concord_platform::TproxyDatagram;
use socket2::Socket;
use tokio::net::{TcpStream, UdpSocket};

use crate::ctx::{ListenCtx, Peer};

pub trait Transparent: Send + Sync + 'static {
    /// `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` on Linux, `DIOCNATLOOK` on macOS.
    fn original_dst(&self, conn: &TcpStream) -> io::Result<SocketAddr>;

    /// `IP_TRANSPARENT`, plus `IPV6_TRANSPARENT` for an IPv6 socket.
    fn make_transparent(&self, socket: &Socket, is_v6: bool) -> io::Result<()>;

    fn prepare_udp(&self, _socket: &Socket, _is_v6: bool) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn recv_udp(&self, _socket: &UdpSocket, _buf: &mut [u8]) -> io::Result<TproxyDatagram> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// A non-blocking socket bound to the foreign `from` and connected to `to`.
    fn reply_socket(&self, _from: SocketAddr, _to: SocketAddr) -> io::Result<std::net::UdpSocket> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

pub(crate) async fn handle_redir(
    ctx: &ListenCtx,
    stream: TcpStream,
    peer: Peer,
    transparent: &dyn Transparent,
) {
    let Ok(original) = transparent.original_dst(&stream) else {
        return;
    };
    let meta = ctx.tcp_meta(InboundKind::Redir, &peer, Address::from(original), None);
    ctx.hand_off(meta, Box::new(stream));
}

pub(crate) fn handle_tproxy(
    ctx: &ListenCtx,
    stream: TcpStream,
    mut peer: Peer,
    listener: SocketAddr,
) {
    let dst = Address::from(peer.local);
    peer.local = listener;
    let meta = ctx.tcp_meta(InboundKind::TProxy, &peer, dst, None);
    ctx.hand_off(meta, Box::new(stream));
}

/// The calls `concord-platform` provides: Linux `SO_ORIGINAL_DST` and
/// `IP_TRANSPARENT`, macOS `DIOCNATLOOK`.
pub struct PlatformTransparent;

impl Transparent for PlatformTransparent {
    fn original_dst(&self, conn: &TcpStream) -> io::Result<SocketAddr> {
        concord_platform::original_dst(conn)
    }

    fn make_transparent(&self, socket: &Socket, is_v6: bool) -> io::Result<()> {
        concord_platform::make_transparent(socket, is_v6)
    }

    fn prepare_udp(&self, socket: &Socket, is_v6: bool) -> io::Result<()> {
        concord_platform::prepare_tproxy_udp(socket, is_v6)
    }

    fn recv_udp(&self, socket: &UdpSocket, buf: &mut [u8]) -> io::Result<TproxyDatagram> {
        concord_platform::recv_original_dst(socket, buf)
    }

    fn reply_socket(&self, from: SocketAddr, to: SocketAddr) -> io::Result<std::net::UdpSocket> {
        concord_platform::bind_foreign_udp(from, to)
    }
}
