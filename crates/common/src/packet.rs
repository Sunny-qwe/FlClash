use std::cell::RefCell;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};

use crate::addr::Address;
use crate::sync::lock;

/// What one task poll can release at once: a UDP drain or a tunnel send round, 64 datagrams.
const SLAB_LIMIT: usize = 64;

/// Tokio worker threads, read once from the runtime that first returns a buffer. Each worker
/// can release a full batch, so the shared overflow holds one batch per worker.
pub(crate) fn workers() -> usize {
    static WORKERS: OnceLock<usize> = OnceLock::new();
    match WORKERS.get() {
        Some(workers) => *workers,
        None => tokio::runtime::Handle::try_current().map_or(1, |handle| {
            *WORKERS.get_or_init(|| handle.metrics().num_workers().max(1))
        }),
    }
}

thread_local! {
    static SLAB: RefCell<Vec<Box<[u8]>>> = const { RefCell::new(Vec::new()) };
}

/// A packet usually dies on another thread than the one that read it, so without
/// this every reading thread's slab would run dry while the sending ones overflow.
static SHARED: Mutex<Vec<Box<[u8]>>> = Mutex::new(Vec::new());

fn take_storage() -> Box<[u8]> {
    SLAB.try_with(|slab| slab.borrow_mut().pop())
        .ok()
        .flatten()
        .or_else(|| lock(&SHARED).pop())
        .unwrap_or_else(|| vec![0u8; PacketBuf::CAPACITY].into_boxed_slice())
}

fn give_storage(storage: Box<[u8]>) {
    let overflow = SLAB
        .try_with(|slab| {
            let mut slab = slab.borrow_mut();
            if slab.len() < SLAB_LIMIT {
                slab.push(storage);
                None
            } else {
                Some(storage)
            }
        })
        .unwrap_or(None);
    if let Some(storage) = overflow {
        let mut shared = lock(&SHARED);
        if shared.len() < SLAB_LIMIT * workers() {
            shared.push(storage);
        }
    }
}

/// One UDP datagram with room in front of it, so a protocol writes its header in
/// place. Buffers recycle through per-thread slabs, so a packet does not allocate.
pub struct PacketBuf {
    storage: Option<Box<[u8]>>,
    start: usize,
    end: usize,
}

impl PacketBuf {
    pub const CAPACITY: usize = u16::MAX as usize + Self::DEFAULT_HEADROOM;
    /// The longest header a protocol writes in front of a datagram: a Shadowsocks 2022 UDP
    /// header to a 255-byte domain (`proxy::ss::udp`, 24 + 16 + 11 + 259 + 32).
    pub const DEFAULT_HEADROOM: usize = 342;

    pub fn take() -> Self {
        Self::with_headroom(Self::DEFAULT_HEADROOM)
    }

    pub fn with_headroom(headroom: usize) -> Self {
        let start = headroom.min(Self::CAPACITY);
        PacketBuf {
            storage: Some(take_storage()),
            start,
            end: start,
        }
    }

    /// Returns the buffers no thread is holding to the allocator.
    pub fn release_shared() {
        {
            let mut shared = lock(&SHARED);
            *shared = Vec::new();
        }
    }

    pub fn from_slice(payload: &[u8]) -> Self {
        let mut packet = Self::take();
        let end = packet.start + payload.len().min(packet.spare().len());
        if let Some(target) = packet.bytes_mut().get_mut(Self::DEFAULT_HEADROOM..end) {
            target.copy_from_slice(
                payload
                    .get(..end - Self::DEFAULT_HEADROOM)
                    .unwrap_or_default(),
            );
        }
        packet.end = end;
        packet
    }

    fn bytes(&self) -> &[u8] {
        self.storage.as_deref().unwrap_or_default()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.storage.as_deref_mut().unwrap_or_default()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes().get(self.start..self.end).unwrap_or_default()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let (start, end) = (self.start, self.end);
        self.bytes_mut().get_mut(start..end).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }

    pub fn headroom(&self) -> usize {
        self.start
    }

    fn spare(&self) -> &[u8] {
        self.bytes().get(self.end..).unwrap_or_default()
    }

    pub fn spare_mut(&mut self) -> &mut [u8] {
        let end = self.end;
        self.bytes_mut().get_mut(end..).unwrap_or_default()
    }

    pub fn advance(&mut self, n: usize) {
        self.end = (self.end + n).min(Self::CAPACITY);
    }

    pub fn clear(&mut self) {
        self.start = Self::DEFAULT_HEADROOM;
        self.end = Self::DEFAULT_HEADROOM;
    }

    /// Moves the payload when the headroom runs out, which only a mis-sized
    /// `PacketSession::headroom` can cause.
    pub fn prepend(&mut self, n: usize) -> &mut [u8] {
        if self.start < n {
            let len = self.len();
            let target = (n + Self::DEFAULT_HEADROOM).min(Self::CAPACITY.saturating_sub(len));
            let (start, end) = (self.start, self.end);
            self.bytes_mut().copy_within(start..end, target);
            self.start = target;
            self.end = target + len;
        }
        self.start = self.start.saturating_sub(n);
        let (start, take) = (self.start, n.min(self.end - self.start));
        self.bytes_mut()
            .get_mut(start..start + take)
            .unwrap_or_default()
    }

    pub fn consume(&mut self, n: usize) {
        self.start = (self.start + n).min(self.end);
    }

    pub fn truncate(&mut self, len: usize) {
        self.end = (self.start + len).min(self.end);
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        let take = data.len().min(self.spare().len());
        if let (Some(target), Some(source)) = (self.spare_mut().get_mut(..take), data.get(..take)) {
            target.copy_from_slice(source);
        }
        self.advance(take);
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        if let Some(storage) = self.storage.take() {
            give_storage(storage);
        }
    }
}

/// Synchronous poll methods produce no future, so a session costs nothing per packet.
pub trait PacketSession: Send + Sync {
    /// The session may rewrite `pkt` in place; it is consumed only on `Ready`.
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>>;

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>>;

    fn headroom(&self) -> usize {
        0
    }

    fn close(&self) {}

    /// True when [`poll_send_batch`](Self::poll_send_batch) costs less than a
    /// `poll_send` per datagram; only then is it worth holding datagrams back for it.
    fn batches(&self) -> bool {
        false
    }

    /// Sends datagrams from the front of `batch`, in order, and is called only when
    /// [`batches`](Self::batches) is true. `Ready(Ok(n))` with `n > 0` means the first `n`
    /// have left; `Ready(Err(_))` is the first one's error, the rest not tried; `Pending`
    /// means none left and `cx` is woken when one could.
    fn poll_send_batch(
        &self,
        _cx: &mut Context<'_>,
        _batch: &[Datagram<'_>],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }

    /// True when [`poll_recv_batch`](Self::poll_recv_batch) takes several datagrams for
    /// the cost of one `poll_recv`.
    fn recv_batches(&self) -> bool {
        false
    }

    /// Receives into `batch`, replacing what it held, and is called only when
    /// [`recv_batches`](Self::recv_batches) is true. `Ready(Ok(_))` means `batch` holds at
    /// least one datagram; `Pending` means none arrived and `cx` is woken when one does.
    fn poll_recv_batch(
        &self,
        _cx: &mut Context<'_>,
        _batch: &mut RecvBatch,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }

    /// Moves the session's socket readiness to `watcher` when the session has one socket of
    /// its own; anything else keeps what it has.
    fn watch(&self, _watcher: &dyn crate::flow::SocketWatcher) {}
}

/// A datagram handed to a flow handler: borrowed from the reader's buffer, or a buffer the
/// reader gives away. The handler copies a borrowed one only if it keeps it.
pub enum UdpPayload<'a> {
    Borrowed(&'a [u8]),
    Owned(PacketBuf),
}

impl UdpPayload<'_> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            UdpPayload::Borrowed(bytes) => bytes,
            UdpPayload::Owned(packet) => packet.as_slice(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    pub fn into_packet(self) -> PacketBuf {
        match self {
            UdpPayload::Borrowed(bytes) => PacketBuf::from_slice(bytes),
            UdpPayload::Owned(packet) => packet,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Datagram<'a> {
    pub payload: &'a [u8],
    pub dst: SocketAddr,
}

/// Room for one datagram of any size.
pub const RECV_SLOT: usize = 65_536;
const RECV_MIN: usize = 8;
pub const RECV_MAX: usize = 32;

/// Datagrams taken by one receive, in slots the batch keeps between receives. The count
/// to ask for grows when a receive fills every slot and shrinks when it fills fewer than
/// half, between 8 and 32, as sing-tun's `packetSpliceRead` does.
pub struct RecvBatch {
    slots: Box<[u8]>,
    lens: [usize; RECV_MAX],
    from: [Option<SocketAddr>; RECV_MAX],
    filled: usize,
    want: usize,
    /// The next receive's limit, then `RECV_MAX` again: the batch is shared by every session
    /// on its thread.
    cap: usize,
    prepared: usize,
}

impl Default for RecvBatch {
    fn default() -> Self {
        RecvBatch {
            slots: Box::default(),
            lens: [0; RECV_MAX],
            from: [None; RECV_MAX],
            filled: 0,
            want: RECV_MIN,
            cap: RECV_MAX,
            prepared: 0,
        }
    }
}

impl RecvBatch {
    /// Empties the batch and returns the slots the next receive may fill, `RECV_SLOT`
    /// bytes each.
    pub fn prepare(&mut self) -> &mut [u8] {
        if self.slots.is_empty() {
            // One zeroed allocation this large comes from fresh mapped pages, and a page
            // becomes resident only when the kernel writes a datagram into it.
            self.slots = vec![0u8; RECV_MAX * RECV_SLOT].into_boxed_slice();
        }
        self.filled = 0;
        self.prepared = self.want.min(self.cap);
        self.cap = RECV_MAX;
        self.slots
            .get_mut(..self.prepared * RECV_SLOT)
            .unwrap_or_default()
    }

    /// Lets the next receive take at most `most` datagrams, and at least one.
    pub fn limit(&mut self, most: usize) {
        self.cap = most.clamp(1, RECV_MAX);
    }

    /// Records what a receive left in the first `count` slots; a slot without a source
    /// held a datagram that did not fit and is skipped.
    pub fn received(
        &mut self,
        count: usize,
        mut slot: impl FnMut(usize) -> (usize, Option<SocketAddr>),
    ) {
        let count = count.min(self.prepared);
        for index in 0..count {
            let (len, from) = slot(index);
            if let (Some(l), Some(f)) = (self.lens.get_mut(index), self.from.get_mut(index)) {
                *l = len.min(RECV_SLOT);
                *f = from;
            }
        }
        self.filled = count;
        if count == self.want {
            self.want = (self.want * 2).min(RECV_MAX);
        } else if count < self.prepared && count * 2 < self.want {
            self.want = (self.want / 2).max(RECV_MIN);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], SocketAddr)> + '_ {
        (0..self.filled).filter_map(|index| {
            let from = (*self.from.get(index)?)?;
            let start = index * RECV_SLOT;
            let len = *self.lens.get(index)?;
            Some((self.slots.get(start..start + len)?, from))
        })
    }
}

pub async fn send_packet(
    session: &dyn PacketSession,
    pkt: &mut PacketBuf,
    dst: &Address,
) -> io::Result<()> {
    poll_fn(|cx| session.poll_send(cx, pkt, dst)).await
}

/// The buffer is taken only for each poll, so an idle session holds none.
pub async fn recv_packet(session: &dyn PacketSession) -> io::Result<(PacketBuf, Address)> {
    poll_fn(|cx| {
        let mut buf = PacketBuf::take();
        match session.poll_recv(cx, &mut buf) {
            Poll::Ready(Ok(from)) => Poll::Ready(Ok((buf, from))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_past_a_full_slab_reaches_a_shared_pool_a_holder_poisoned() {
        concord_test_support::poison(&SHARED);
        // Every other test thread starts with an empty slab and pops the shared pool, so
        // one round can lose its storage to them before it looks.
        let landed = (0..8).any(|_| {
            std::thread::spawn(|| {
                PacketBuf::release_shared();
                for _ in 0..SLAB_LIMIT {
                    give_storage(vec![0; PacketBuf::CAPACITY].into_boxed_slice());
                }
                let overflow = vec![0; PacketBuf::CAPACITY].into_boxed_slice();
                let pointer = overflow.as_ptr();
                give_storage(overflow);
                lock(&SHARED)
                    .iter()
                    .any(|storage| storage.as_ptr() == pointer)
            })
            .join()
            .unwrap()
        });
        assert!(landed);
    }

    #[test]
    fn prepend_writes_in_front_of_the_payload() {
        let mut packet = PacketBuf::from_slice(b"payload");
        packet.prepend(3).copy_from_slice(b"hdr");
        assert_eq!(packet.as_slice(), b"hdrpayload");
        packet.consume(3);
        assert_eq!(packet.as_slice(), b"payload");
    }

    #[test]
    fn prepend_past_the_headroom_keeps_the_payload() {
        let mut packet = PacketBuf::with_headroom(1);
        packet.extend_from_slice(b"payload");
        packet.prepend(4).copy_from_slice(b"head");
        assert_eq!(packet.as_slice(), b"headpayload");
    }

    #[test]
    fn a_receive_limit_holds_for_one_receive_and_does_not_shrink_the_batch() {
        let mut batch = RecvBatch::default();
        batch.prepare();
        batch.received(RECV_MIN, |_| (1, None));
        let want = RECV_MIN * 2;
        batch.limit(3);
        assert_eq!(batch.prepare().len(), 3 * RECV_SLOT);
        batch.received(3, |_| (1, None));
        assert_eq!(batch.prepare().len(), want * RECV_SLOT);
    }

    #[test]
    fn buffers_are_recycled() {
        let first = PacketBuf::take();
        let address = first.bytes().as_ptr();
        drop(first);
        let second = PacketBuf::take();
        assert_eq!(second.bytes().as_ptr(), address);
    }

    fn fill(batch: &mut RecvBatch, count: usize) -> usize {
        let room = batch.prepare().len() / RECV_SLOT;
        let from = SocketAddr::from(([10, 0, 0, 1], 53));
        batch.received(count.min(room), |index| (index + 1, Some(from)));
        room
    }

    #[test]
    fn a_full_receive_doubles_the_next_and_a_sparse_one_halves_it() {
        let mut batch = RecvBatch::default();
        assert_eq!(fill(&mut batch, 64), 8);
        assert_eq!(fill(&mut batch, 64), 16);
        assert_eq!(fill(&mut batch, 64), 32);
        assert_eq!(fill(&mut batch, 64), 32);
        assert_eq!(fill(&mut batch, 15), 32);
        assert_eq!(fill(&mut batch, 1), 16);
        assert_eq!(fill(&mut batch, 1), 8);
        assert_eq!(fill(&mut batch, 1), 8);
    }

    #[test]
    fn a_slot_without_a_source_is_skipped() {
        let mut batch = RecvBatch::default();
        let slots = batch.prepare();
        slots[RECV_SLOT..RECV_SLOT + 2].copy_from_slice(b"ok");
        let from = SocketAddr::from(([10, 0, 0, 1], 53));
        batch.received(2, |index| {
            if index == 0 {
                (0, None)
            } else {
                (2, Some(from))
            }
        });

        let got: Vec<_> = batch.iter().collect();
        assert_eq!(got, [(&b"ok"[..], from)]);
    }
}
