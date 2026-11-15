//! A channel-backed device for driving the stack without a TUN interface.

use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use concord_common::sync::lock;
use concord_netstack::wire::{
    L4Kind, PROTO_TCP, PROTO_UDP, Parsed, finish, parse_packet, pseudo_header, sum_bytes,
};
use futures_util::task::AtomicWaker;

use crate::device::Device;

struct Ring {
    slots: Vec<Box<[u8]>>,
    lens: Vec<usize>,
    head: usize,
    count: usize,
}

impl Ring {
    fn new(slots: usize, slot_size: usize) -> Self {
        Ring {
            slots: (0..slots)
                .map(|_| vec![0u8; slot_size].into_boxed_slice())
                .collect(),
            lens: vec![0; slots],
            head: 0,
            count: 0,
        }
    }

    fn push(&mut self, packet: &[u8]) -> bool {
        if self.count == self.slots.len() {
            return false;
        }
        let index = (self.head + self.count) % self.slots.len();
        let (Some(slot), Some(len)) = (self.slots.get_mut(index), self.lens.get_mut(index)) else {
            return false;
        };
        let n = packet.len().min(slot.len());
        if let (Some(target), Some(source)) = (slot.get_mut(..n), packet.get(..n)) {
            target.copy_from_slice(source);
        }
        *len = n;
        self.count += 1;
        true
    }

    fn pop(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let slot = self.slots.get(self.head)?;
        let len = *self.lens.get(self.head)?;
        let n = len.min(out.len());
        out.get_mut(..n)?.copy_from_slice(slot.get(..n)?);
        self.head = (self.head + 1) % self.slots.len();
        self.count -= 1;
        Some(n)
    }
}

struct Inner {
    to_stack: Mutex<Ring>,
    from_stack: Mutex<Ring>,
    stack_rx: AtomicWaker,
    stack_tx: AtomicWaker,
    test_rx: AtomicWaker,
}

/// What the stack runs on.
pub struct FakeDevice {
    inner: Arc<Inner>,
}

/// The test's end: writes packets the stack will read, and reads what it wrote.
#[derive(Clone)]
pub struct FakeNet {
    inner: Arc<Inner>,
}

/// Neither end allocates after this returns.
pub fn fake_device(slots: usize, slot_size: usize) -> (FakeDevice, FakeNet) {
    let inner = Arc::new(Inner {
        to_stack: Mutex::new(Ring::new(slots, slot_size)),
        from_stack: Mutex::new(Ring::new(slots, slot_size)),
        stack_rx: AtomicWaker::new(),
        stack_tx: AtomicWaker::new(),
        test_rx: AtomicWaker::new(),
    });
    (
        FakeDevice {
            inner: Arc::clone(&inner),
        },
        FakeNet { inner },
    )
}

impl Device for FakeDevice {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.inner.stack_rx.register(cx.waker());
        match lock(&self.inner.to_stack).pop(buf) {
            Some(n) => Poll::Ready(Ok(n)),
            None => Poll::Pending,
        }
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        self.inner.stack_tx.register(cx.waker());
        if lock(&self.inner.from_stack).push(packet) {
            self.inner.test_rx.wake();
            Poll::Ready(Ok(packet.len()))
        } else {
            Poll::Pending
        }
    }
}

impl FakeDevice {
    pub fn batched(self) -> BatchedFakeDevice {
        BatchedFakeDevice(self)
    }

    /// Also returns how many packets the stack handed over in place.
    pub fn offloading(self) -> (OffloadFakeDevice, Arc<AtomicUsize>) {
        let placed = Arc::new(AtomicUsize::new(0));
        let device = OffloadFakeDevice {
            device: self,
            placed: Arc::clone(&placed),
        };
        (device, placed)
    }
}

/// Completes transport checksums and takes payloads in place, as a Linux TUN with a
/// virtio-net header does.
pub struct OffloadFakeDevice {
    device: FakeDevice,
    placed: Arc<AtomicUsize>,
}

fn complete_checksum(packet: &mut [u8]) {
    let Ok(Parsed::Packet(view)) = parse_packet(packet) else {
        return;
    };
    let (proto, field) = match view.kind {
        L4Kind::Tcp => (PROTO_TCP, 16),
        L4Kind::Udp => (PROTO_UDP, 6),
        L4Kind::Icmp => return,
    };
    let (src, dst, start) = (view.src, view.dst, packet.len() - view.l4.len());
    let Some(l4) = packet.get_mut(start..) else {
        return;
    };
    if let Some(sum) = l4.get_mut(field..field + 2) {
        sum.fill(0);
    }
    let sum = finish(sum_bytes(pseudo_header(src, dst, proto, l4.len()), l4));
    if let Some(slot) = l4.get_mut(field..field + 2) {
        slot.copy_from_slice(&sum.to_be_bytes());
    }
}

impl Device for OffloadFakeDevice {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.device.poll_recv(cx, buf)
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        let mut packet = packet.to_vec();
        complete_checksum(&mut packet);
        self.device.poll_send(cx, &packet)
    }

    fn checksum_offload(&self) -> bool {
        true
    }

    fn try_send_parts(&self, parts: &[IoSlice<'_>], _segment: u16) -> io::Result<usize> {
        let mut packet: Vec<u8> = parts.iter().flat_map(|part| part.iter().copied()).collect();
        complete_checksum(&mut packet);
        let inner = &self.device.inner;
        if !lock(&inner.from_stack).push(&packet) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.placed.fetch_add(1, Ordering::Relaxed);
        inner.test_rx.wake();
        Ok(packet.len())
    }
}

/// Moves several packets per call, as a device with `recvmsg_x`/`sendmsg_x` does.
pub struct BatchedFakeDevice(FakeDevice);

impl Device for BatchedFakeDevice {
    const BATCH: usize = 8;

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, buf)
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_send(cx, packet)
    }

    fn poll_recv_batch(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        stride: usize,
        lens: &mut [usize],
    ) -> Poll<io::Result<usize>> {
        let inner = &self.0.inner;
        inner.stack_rx.register(cx.waker());
        let mut ring = lock(&inner.to_stack);
        let mut count = 0;
        for (slot, len) in buf.chunks_exact_mut(stride).zip(lens.iter_mut()) {
            let Some(n) = ring.pop(slot) else {
                break;
            };
            *len = n;
            count += 1;
        }
        if count == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(count))
        }
    }

    fn poll_send_batch(
        &self,
        cx: &mut Context<'_>,
        packets: &[&[u8]],
        _failed: &mut usize,
    ) -> Poll<usize> {
        let inner = &self.0.inner;
        inner.stack_tx.register(cx.waker());
        let mut ring = lock(&inner.from_stack);
        let sent = packets
            .iter()
            .take_while(|packet| ring.push(packet))
            .count();
        drop(ring);
        if sent == 0 {
            return Poll::Pending;
        }
        inner.test_rx.wake();
        Poll::Ready(sent)
    }
}

/// A device with several queues, each with its own end for the test.
pub struct QueuedFakeDevice(Vec<FakeDevice>);

pub fn fake_queues(
    queues: usize,
    slots: usize,
    slot_size: usize,
) -> (QueuedFakeDevice, Vec<FakeNet>) {
    let (devices, nets) = (0..queues).map(|_| fake_device(slots, slot_size)).unzip();
    (QueuedFakeDevice(devices), nets)
}

impl Device for QueuedFakeDevice {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.0.first() {
            Some(queue) => queue.poll_recv(cx, buf),
            None => Poll::Pending,
        }
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        match self.0.first() {
            Some(queue) => queue.poll_send(cx, packet),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }

    fn into_queues(self) -> Vec<Self> {
        self.0
            .into_iter()
            .map(|queue| QueuedFakeDevice(vec![queue]))
            .collect()
    }
}

impl FakeNet {
    /// `false` when the ring is full.
    pub fn inject(&self, packet: &[u8]) -> bool {
        let pushed = lock(&self.inner.to_stack).push(packet);
        self.inner.stack_rx.wake();
        pushed
    }

    pub fn try_take(&self, out: &mut [u8]) -> Option<usize> {
        let taken = lock(&self.inner.from_stack).pop(out);
        if taken.is_some() {
            self.inner.stack_tx.wake();
        }
        taken
    }

    pub async fn take(&self, out: &mut [u8]) -> usize {
        poll_fn(|cx| {
            self.inner.test_rx.register(cx.waker());
            match self.try_take(out) {
                Some(n) => Poll::Ready(n),
                None => Poll::Pending,
            }
        })
        .await
    }

    pub async fn take_vec(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 70_000];
        let n = self.take(&mut buf).await;
        buf.truncate(n);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packets_cross_in_both_directions_in_order() {
        let (device, net) = fake_device(4, 64);
        assert!(net.inject(b"one"));
        assert!(net.inject(b"two"));
        let mut buf = [0u8; 64];
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            device.poll_recv(&mut cx, &mut buf),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(&buf[..3], b"one");
        assert!(matches!(
            device.poll_send(&mut cx, b"out"),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(net.take_vec().await, b"out");
        assert!(matches!(
            device.poll_recv(&mut cx, &mut buf),
            Poll::Ready(Ok(3))
        ));
        assert!(device.poll_recv(&mut cx, &mut buf).is_pending());
    }

    #[test]
    fn a_full_ring_refuses_and_a_full_send_ring_is_pending() {
        let (device, net) = fake_device(1, 8);
        assert!(net.inject(b"a"));
        assert!(!net.inject(b"b"));
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            device.poll_send(&mut cx, b"x"),
            Poll::Ready(Ok(1))
        ));
        assert!(device.poll_send(&mut cx, b"y").is_pending());
    }
}
