use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::addr::Address;
use crate::meta::{FlowMeta, UdpFlow};
use crate::packet::UdpPayload;
use crate::stream::BoxStream;

pub trait FlowHandler: Send + Sync + 'static {
    fn handle_tcp(&self, meta: FlowMeta, stream: BoxStream);

    /// `reply` is borrowed: a handler clones it only when it keeps a different one.
    fn handle_udp(&self, flow: UdpFlow<'_>, payload: UdpPayload<'_>, reply: &Arc<dyn UdpReply>);

    /// An echo request, `message` being the ICMP message without its IP header. `true` means
    /// the handler calls `answer` once the destination has replied; `false` leaves the stack
    /// to answer as if the destination had.
    fn handle_icmp(&self, _dst: IpAddr, _message: &[u8], _answer: IcmpAnswer) -> bool {
        false
    }

    /// Runs `round`, whose `handle_udp` calls on this thread may hold datagrams back so they
    /// leave together when it returns. Rounds do not nest.
    fn udp_round(&self, round: &mut dyn FnMut()) {
        round();
    }
}

/// Puts the echo reply for one request on the device.
pub type IcmpAnswer = Box<dyn FnOnce() + Send>;

pub trait UdpReply: Send + Sync + 'static {
    /// `from` is the address the application sent to, restored from fake-ip.
    fn poll_write_back(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        from: &Address,
    ) -> Poll<io::Result<()>>;

    /// The session behind this reply has ended, so what it holds for the client can go.
    fn session_ended(&self) {}

    /// Hands the receiving side of the session behind this reply to whoever writes its
    /// replies, which then polls `source` instead of the session running a receive task.
    /// `Err` gives `source` back for the session to receive itself.
    fn adopt(&self, source: Arc<dyn ReplySource>) -> Result<(), Arc<dyn ReplySource>> {
        Err(source)
    }
}

/// A session's arriving datagrams, polled by the writer that adopted it.
pub trait ReplySource: Send + Sync + 'static {
    /// Receives until the socket is empty or `out` is full and puts each datagram into `out`.
    /// `Pending` means none arrived and `cx` is woken when one does or when the session ends.
    fn poll_replies(&self, cx: &mut Context<'_>, out: &mut dyn ReplyOut) -> Poll<Replies>;

    /// Offers the writer's own readiness watch for the session's socket.
    fn watch(&self, _watcher: &dyn SocketWatcher) {}
}

/// Read readiness of a socket watched outside Tokio's reactor. It has one waiter, the writer
/// that asked for the watch. Writes are not watched: a sender uses the descriptor directly and
/// never waits, so no other task holds a waker the watch would have to keep alive when the
/// socket moves between pollers.
pub trait SocketWatch: Send + Sync {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Runs a read; `WouldBlock` clears the readiness.
    fn try_read(&self, read: &mut dyn FnMut() -> io::Result<usize>) -> io::Result<usize>;
}

pub trait SocketWatcher {
    /// Watches `socket`, which must already be out of Tokio's reactor, until the watch drops.
    fn watch(&self, socket: Arc<std::net::UdpSocket>) -> io::Result<Arc<dyn SocketWatch>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replies {
    /// `out` is full; more may be waiting, so poll again.
    Received,
    /// Some arrived and the socket is empty; `cx` is woken as for `Pending`.
    Drained,
    /// The session is over and the source can go.
    Ended,
}

pub trait ReplyOut {
    fn room(&self) -> usize;

    /// `from` is the address the application sent to. An error of kind `BrokenPipe` means
    /// the client is gone; any other loses this datagram only.
    fn put(&mut self, payload: &[u8], from: &Address) -> io::Result<()>;
}
