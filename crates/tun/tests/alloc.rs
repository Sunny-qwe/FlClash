#![allow(
    unsafe_code,
    reason = "a counting global allocator wraps the system one"
)]

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use concord_common::stream_buffer::ReadBufferOptions;
use concord_common::{BoxStream, FlowKey, UdpReply};
use concord_tun::testing::{FakeNet, fake_device};
use concord_tun::{FlowSink, IpStack, NetStack, StackOptions};
use support::{TcpPeer, tcp_payload_len, udp_packet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

struct Counting;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static HANDOFF_COUNTING: Cell<bool> = const { Cell::new(false) };
}

fn note(size: usize) {
    if ARMED.load(Ordering::Relaxed) || HANDOFF_COUNTING.try_with(Cell::get).unwrap_or(false) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
    }
}

// SAFETY: forwards every call to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "current_thread")]
async fn owned_stream_buffer_handoffs_do_not_allocate() {
    let _guard = SERIAL.lock().await;
    let mut source = ReadBufferOptions::for_copy(Default::default(), Default::default())
        .unwrap()
        .take();
    source.spare_mut()[..7].copy_from_slice(b"payload");
    source.advance(7).unwrap();
    let pointer = source.as_slice().as_ptr();
    assert!(!ARMED.load(Ordering::SeqCst));
    ALLOCS.store(0, Ordering::SeqCst);
    BYTES.store(0, Ordering::SeqCst);
    HANDOFF_COUNTING.with(|armed| armed.set(true));
    let canary = std::hint::black_box(Box::new(7u8));
    HANDOFF_COUNTING.with(|armed| armed.set(false));
    assert_eq!(ALLOCS.load(Ordering::SeqCst), 1);
    assert_eq!(BYTES.load(Ordering::SeqCst), 1);
    drop(canary);
    ALLOCS.store(0, Ordering::SeqCst);
    BYTES.store(0, Ordering::SeqCst);
    HANDOFF_COUNTING.with(|armed| armed.set(true));
    for _ in 0..10_000 {
        let mut owned = source.take_owned();
        std::hint::black_box(&mut owned);
        source = owned.take_owned();
        std::hint::black_box(&mut source);
    }
    HANDOFF_COUNTING.with(|armed| armed.set(false));
    assert_eq!(ALLOCS.load(Ordering::SeqCst), 0);
    assert_eq!(BYTES.load(Ordering::SeqCst), 0);
    assert_eq!(source.as_slice().as_ptr(), pointer);
    assert_eq!(source.as_slice(), b"payload");
}

fn quiet<R>(work: impl FnOnce() -> R) -> R {
    let was = ARMED.swap(false, Ordering::SeqCst);
    let result = work();
    ARMED.store(was, Ordering::SeqCst);
    result
}

struct Counter(AtomicUsize);

struct EchoSink {
    packets: Arc<Counter>,
    most_reply_owners: Arc<Counter>,
}

impl FlowSink for EchoSink {
    fn tcp(&self, _flow: FlowKey, _stream: BoxStream) {}

    fn udp(&self, flow: FlowKey, payload: &[u8], reply: &Arc<dyn UdpReply>) {
        self.most_reply_owners
            .0
            .fetch_max(Arc::strong_count(reply), Ordering::Relaxed);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let from = concord_common::Address::Socket(flow.dst);
        let _ = reply.poll_write_back(&mut cx, payload, &from);
        self.packets.0.fetch_add(1, Ordering::Relaxed);
    }
}

struct TcpSink(tokio::sync::mpsc::UnboundedSender<BoxStream>);

impl FlowSink for TcpSink {
    fn tcp(&self, _flow: FlowKey, stream: BoxStream) {
        let _ = self.0.send(stream);
    }

    fn udp(&self, _flow: FlowKey, _payload: &[u8], _reply: &Arc<dyn UdpReply>) {}
}

async fn pump_udp(net: &FakeNet, datagram: &[u8], out: &mut [u8], count: usize) {
    for _ in 0..count / 16 {
        for _ in 0..16 {
            assert!(net.inject(datagram));
        }
        let mut replies = 0;
        while replies < 16 {
            tokio::task::yield_now().await;
            while net.try_take(out).is_some() {
                replies += 1;
            }
        }
    }
}

async fn upload_batches(
    net: &FakeNet,
    consumed: &AtomicUsize,
    segments: &[Vec<u8>],
    base: usize,
    out: &mut [u8],
) {
    for (batch, chunk) in segments.chunks(16).enumerate() {
        for segment in chunk {
            assert!(net.inject(segment));
        }
        let want = base + batch * 16_000 + chunk.len() * 1000;
        while consumed.load(Ordering::SeqCst) < want {
            tokio::task::yield_now().await;
        }
        while net.try_take(out).is_some() {}
    }
}

async fn acknowledge_window(
    net: &FakeNet,
    peer: &mut TcpPeer,
    consumed: &AtomicUsize,
    read: &Notify,
) {
    let before = consumed.load(Ordering::SeqCst);
    // The marker's ACK is processed before its payload reaches the stream.
    let marker = quiet(|| peer.data(&[0]));
    assert!(net.inject(&marker), "ACK barrier input ring full");
    while consumed.load(Ordering::SeqCst) == before {
        read.notified().await;
    }
    assert_eq!(
        consumed.load(Ordering::SeqCst),
        before + 1,
        "ACK barrier payload"
    );
}

/// Returns the datagrams handled, the allocations and bytes while armed, and the most owners
/// a reply handle had while the sink held it.
async fn udp_path() -> (usize, usize, usize, usize) {
    let (device, net) = fake_device(256, 2048);
    let packets = Arc::new(Counter(AtomicUsize::new(0)));
    let owners = Arc::new(Counter(AtomicUsize::new(0)));
    let sink = Arc::new(EchoSink {
        packets: Arc::clone(&packets),
        most_reply_owners: Arc::clone(&owners),
    });
    let stop = CancellationToken::new();
    let task = tokio::spawn(NetStack::new(StackOptions::default()).run(device, sink, stop.clone()));
    let datagram = udp_packet(
        "10.0.0.2:5000".parse().unwrap(),
        "8.8.4.4:9999".parse().unwrap(),
        &[7u8; 512],
    );
    let mut out = vec![0u8; 2048];
    pump_udp(&net, &datagram, &mut out, 2048).await;
    let before = packets.0.load(Ordering::Relaxed);
    ARMED.store(false, Ordering::SeqCst);
    ALLOCS.store(0, Ordering::SeqCst);
    BYTES.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    pump_udp(&net, &datagram, &mut out, 8192).await;
    ARMED.store(false, Ordering::SeqCst);
    let handled = packets.0.load(Ordering::Relaxed) - before;
    stop.cancel();
    task.await.unwrap().unwrap();
    (
        handled,
        ALLOCS.load(Ordering::SeqCst),
        BYTES.load(Ordering::SeqCst),
        owners.0.load(Ordering::Relaxed),
    )
}

async fn tcp_path() -> ((usize, usize), (usize, usize)) {
    let (device, net) = fake_device(512, 2048);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let task = tokio::spawn(NetStack::new(StackOptions::default()).run(
        device,
        Arc::new(TcpSink(tx)),
        stop.clone(),
    ));
    let mut peer = TcpPeer::new("10.0.0.2:40000", "93.184.216.34:80");
    let mut out = vec![0u8; 2048];
    assert!(net.inject(&peer.syn()));
    let n = tokio::time::timeout(Duration::from_secs(5), net.take(&mut out))
        .await
        .expect("SYN-ACK deadline");
    let synack = peer.parse(&out[..n]).unwrap();
    peer.absorb(&synack);
    assert!(net.inject(&peer.ack()));
    let stream = rx.recv().await.unwrap();
    let consumed = Arc::new(AtomicUsize::new(0));
    let read = Arc::new(Notify::new());

    let upload: Vec<Vec<u8>> = (0..4400).map(|_| peer.data(&[3u8; 1000])).collect();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let seen = Arc::clone(&consumed);
    let read_done = Arc::clone(&read);
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        while let Ok(n) = reader.read(&mut buf).await {
            if n == 0 {
                break;
            }
            seen.fetch_add(n, Ordering::SeqCst);
            read_done.notify_one();
        }
    });

    upload_batches(&net, &consumed, &upload[..400], 0, &mut out).await;
    ARMED.store(false, Ordering::SeqCst);
    ALLOCS.store(0, Ordering::SeqCst);
    BYTES.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    upload_batches(&net, &consumed, &upload[400..4400], 400_000, &mut out).await;
    ARMED.store(false, Ordering::SeqCst);
    let upload_result = (ALLOCS.load(Ordering::SeqCst), BYTES.load(Ordering::SeqCst));

    let chunk = vec![9u8; 4000];
    let mut total = (0usize, 0usize);
    for phase in 0..24 {
        if phase >= 4 {
            ALLOCS.store(0, Ordering::SeqCst);
            BYTES.store(0, Ordering::SeqCst);
            ARMED.store(true, Ordering::SeqCst);
        }
        for _ in 0..12 {
            writer.write_all(&chunk).await.unwrap();
        }
        let first = peer.ack;
        let delivered = tokio::time::timeout(Duration::from_secs(5), async {
            while peer.ack.wrapping_sub(first) < 48_000 {
                let n = net.take(&mut out).await;
                let raw = out.get(..n).unwrap_or_default();
                if tcp_payload_len(raw) == 0 {
                    continue;
                }
                let seg = quiet(|| peer.parse(raw)).expect("TCP payload segment");
                assert!(
                    seg.seq.wrapping_sub(peer.ack) as i32 <= 0,
                    "out-of-order segment"
                );
                if seg.next_seq().wrapping_sub(peer.ack) as i32 > 0 {
                    peer.ack = seg.next_seq();
                }
                let ack = quiet(|| peer.ack());
                assert!(net.inject(&ack), "ACK input ring full in phase {phase}");
            }
            acknowledge_window(&net, &mut peer, &consumed, &read).await;
            peer.ack.wrapping_sub(first)
        })
        .await;
        ARMED.store(false, Ordering::SeqCst);
        if phase >= 4 {
            total.0 += ALLOCS.load(Ordering::SeqCst);
            total.1 += BYTES.load(Ordering::SeqCst);
        }
        assert_eq!(delivered, Ok(48_000), "phase {phase}");
    }
    stop.cancel();
    task.await.unwrap().unwrap();
    reader_task.abort();
    if let Err(err) = reader_task.await {
        assert!(err.is_cancelled(), "reader task failed: {err}");
    }
    (upload_result, total)
}

#[tokio::test(flavor = "current_thread")]
async fn udp_path_current_thread_does_not_allocate() {
    let _guard = SERIAL.lock().await;
    let (handled, allocs, bytes, owners) = udp_path().await;
    eprintln!("udp current_thread: {handled} datagrams, {allocs} allocations, {bytes} bytes");
    assert_eq!(handled, 8192);
    assert_eq!(allocs, 0);
    assert_eq!(
        owners, 1,
        "the driver lends its reply handle without cloning it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_path_multi_thread_report() {
    let _guard = SERIAL.lock().await;
    let (handled, allocs, bytes, _) = udp_path().await;
    eprintln!("udp multi_thread: {handled} datagrams, {allocs} allocations, {bytes} bytes");
    assert_eq!(handled, 8192);
    assert!(allocs < handled / 100);
}

#[tokio::test(flavor = "current_thread")]
async fn established_tcp_current_thread_does_not_allocate() {
    let _guard = SERIAL.lock().await;
    let (upload, download) = tcp_path().await;
    eprintln!(
        "tcp current_thread: upload 4000 segments {upload:?}, download 20 windows {download:?}"
    );
    assert_eq!(upload.0, 0);
    assert_eq!(download.0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn established_tcp_multi_thread_report() {
    let _guard = SERIAL.lock().await;
    let (upload, download) = tcp_path().await;
    eprintln!(
        "tcp multi_thread: upload 4000 segments {upload:?}, download 20 windows {download:?}"
    );
    let _ = Duration::from_secs(0);
}
