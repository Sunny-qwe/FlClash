//! What the libFuzzer targets in `fuzz/` drive.

use std::cell::RefCell;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use concord_common::BoxStream;
use rustls::crypto::cipher::{MessageEncrypter, OutboundChunks, OutboundPlainMessage};
use rustls::{ContentType, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::ciphers::{tls12_keys, tls13_keys};
use crate::reality::schedule::Suite;
use crate::record::{KeySchedule, Keys, RecordStream};
use crate::record_io::RecordIo;

const CLIENT_SECRET: [u8; 32] = [0x11; 32];
const SERVER_SECRET: [u8; 32] = [0x22; 32];
/// ECDHE-RSA with AES-128-GCM: 16-byte keys and 4-byte fixed IVs.
const TLS12_SUITE: u16 = 0xc02f;
const KEY_UPDATE: u8 = 24;
const MAX_PLAINTEXT: usize = 16 * 1024;
const READ_SIZES: [usize; 8] = [1, 7, 512, 1448, 4096, 16_384, 32_768, 65_536];
const CHUNK_SIZES: [usize; 8] = [1, 3, 5, 100, 1448, 5000, 16_389, 70_000];

/// The server's side of a record stream: it seals what the reader under test opens.
struct Server {
    tls13: bool,
    seq: u64,
    encrypter: Box<dyn MessageEncrypter>,
    schedule: Box<dyn KeySchedule>,
}

impl Server {
    fn seal(&mut self, typ: ContentType, payload: &[u8]) -> Vec<u8> {
        let message = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let Ok(sealed) = self.encrypter.encrypt(message, self.seq) else {
            return Vec::new();
        };
        self.seq += 1;
        sealed.encode()
    }

    fn update_key(&mut self) {
        if let Ok(next) = self.schedule.next_tx() {
            self.encrypter = next;
            self.seq = 0;
        }
    }
}

fn keys(tls13: bool) -> io::Result<(Keys, Server)> {
    let (client, server) = if tls13 {
        (
            tls13_keys(
                Suite::Aes128Gcm,
                CLIENT_SECRET.to_vec(),
                SERVER_SECRET.to_vec(),
                0,
                0,
            )?,
            tls13_keys(
                Suite::Aes128Gcm,
                SERVER_SECRET.to_vec(),
                CLIENT_SECRET.to_vec(),
                0,
                0,
            )?,
        )
    } else {
        // RFC 5246 6.3: client key, server key, client IV, server IV; the peer's block swaps them.
        let block = |key: [u8; 2], iv: [u8; 2]| {
            let [near_key, far_key] = key;
            let [near_iv, far_iv] = iv;
            [
                [near_key; 16].as_slice(),
                &[far_key; 16],
                &[near_iv; 4],
                &[far_iv; 4],
            ]
            .concat()
        };
        (
            tls12_keys(TLS12_SUITE, &block([0x11, 0x22], [0x33, 0x44]), 1, 1)?,
            tls12_keys(TLS12_SUITE, &block([0x22, 0x11], [0x44, 0x33]), 1, 1)?,
        )
    };
    let (seq, encrypter) = server.tx;
    Ok((
        client,
        Server {
            tls13,
            seq,
            encrypter,
            schedule: server.schedule,
        },
    ))
}

struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*first)
    }

    fn length(&mut self) -> usize {
        let high = self.byte().unwrap_or_default();
        let low = self.byte().unwrap_or_default();
        usize::from(u16::from_be_bytes([high, low]))
    }

    fn take(&mut self, len: usize) -> &'a [u8] {
        let (head, rest) = self.0.split_at(len.min(self.0.len()));
        self.0 = rest;
        head
    }
}

/// The wire bytes one input describes, and the application data a correct reader may deliver:
/// every sealed payload in order, of which it delivers a prefix and then stops.
fn script(input: &mut Input<'_>, server: &mut Server) -> (Vec<u8>, Vec<u8>) {
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    let mut counter = 0u8;
    while let Some(op) = input.byte() {
        match op % 8 {
            kind @ 0..=2 => {
                let bound = match kind {
                    0 => 1500,
                    1 => MAX_PLAINTEXT + 1,
                    _ => 20_000,
                };
                let len = input.length() % bound;
                let payload: Vec<u8> = (0..len)
                    .map(|_| {
                        counter = counter.wrapping_add(1);
                        counter
                    })
                    .collect();
                wire.extend(server.seal(ContentType::ApplicationData, &payload));
                expected.extend(payload);
            }
            3 => {
                let request = input.byte().unwrap_or_default() % 3;
                wire.extend(server.seal(ContentType::Handshake, &[KEY_UPDATE, 0, 0, 1, request]));
                if server.tls13 && request < 2 {
                    server.update_key();
                }
            }
            4 => {
                let len = usize::from(input.byte().unwrap_or_default());
                wire.extend(server.seal(ContentType::Handshake, input.take(len)));
            }
            5 => wire.extend(server.seal(ContentType::Alert, input.take(2))),
            6 => {
                let len = usize::from(input.byte().unwrap_or_default());
                wire.extend_from_slice(input.take(len));
            }
            _ => wire.extend_from_slice(&[20, 3, 3, 0, 1, 1]),
        }
    }
    (wire, expected)
}

/// Sizes drawn from a table by a generator the input seeds, so one input always cuts alike.
struct Sizes {
    state: u32,
    table: [usize; 8],
}

impl Sizes {
    fn next(&mut self) -> usize {
        self.state = self.state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let index = usize::try_from(self.state >> 16).unwrap_or_default() % self.table.len();
        self.table.get(index).copied().unwrap_or(1)
    }
}

enum Step {
    Blocked,
    Ended,
}

fn drain(
    stream: &mut RecordStream,
    sizes: &mut Sizes,
    out: &mut Vec<u8>,
    budget: &mut usize,
) -> Step {
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        assert!(*budget > 0, "the reader does not make progress");
        *budget -= 1;
        let mut space = vec![0u8; sizes.next()];
        let mut buf = ReadBuf::new(&mut space);
        match Pin::new(&mut *stream).poll_read(&mut cx, &mut buf) {
            Poll::Pending => return Step::Blocked,
            Poll::Ready(Err(_)) => return Step::Ended,
            Poll::Ready(Ok(())) if buf.filled().is_empty() => return Step::Ended,
            Poll::Ready(Ok(())) => out.extend_from_slice(buf.filled()),
        }
    }
}

/// A loopback connection kept across inputs: a socket pair per input would run the host out
/// of ports. The reader under test gets the bare socket, so it takes its vectored read path.
struct Loopback {
    runtime: tokio::runtime::Runtime,
    near: Arc<TcpStream>,
    far: std::net::TcpStream,
    inputs: u64,
}

struct Bare(Arc<TcpStream>);

impl AsyncRead for Bare {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            std::task::ready!(self.0.poll_read_ready(cx))?;
            match self.0.try_read(out.initialize_unfilled()) {
                Ok(n) => {
                    out.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }
}

impl AsyncWrite for Bare {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl concord_common::Stream for Bare {
    fn tcp(&self) -> Option<&TcpStream> {
        Some(&self.0)
    }
}

impl Loopback {
    #[allow(clippy::disallowed_methods, reason = "a loopback pair for the fuzzer")]
    fn open() -> io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let near = std::net::TcpStream::connect(listener.local_addr()?)?;
        let (far, _) = listener.accept()?;
        near.set_nonblocking(true)?;
        far.set_nodelay(true)?;
        let near = {
            let _entered = runtime.enter();
            Arc::new(TcpStream::from_std(near)?)
        };
        Ok(Loopback {
            runtime,
            near,
            far,
            inputs: 0,
        })
    }

    /// Loopback delivery is not synchronous on every host: waits for the first of what the
    /// peer just wrote.
    fn arrived(&self) -> io::Result<()> {
        self.runtime.block_on(self.near.readable())
    }

    /// Reads on to a mark only this call writes: every input seals with the same keys, so
    /// what one left unread or in flight would open as records in the next.
    fn resync(&mut self) -> io::Result<()> {
        self.inputs += 1;
        let mark = [1u64, 2, 3].map(|round| {
            (self.inputs ^ round)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .to_be_bytes()
        });
        let mark = mark.as_flattened();
        self.far.write_all(mark)?;
        let mut tail = Vec::new();
        let mut scratch = [0u8; 65_536];
        loop {
            self.arrived()?;
            match self.near.try_read(&mut scratch) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    tail.extend_from_slice(scratch.get(..n).unwrap_or_default());
                    if tail.ends_with(mark) {
                        return Ok(());
                    }
                    let stale = tail.len().saturating_sub(mark.len());
                    tail.drain(..stale);
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }
        }
    }
}

thread_local! {
    static LOOPBACK: RefCell<Option<Loopback>> = const { RefCell::new(None) };
}

fn read_over_memory(keys: Keys, wire: &[u8], seed: u32) -> Vec<u8> {
    let (near, mut far) = tokio::io::duplex(wire.len().max(1));
    let near: BoxStream = Box::new(near);
    let mut stream = RecordStream::new(
        RecordIo::unaligned(near),
        keys,
        None,
        Vec::new(),
        Vec::new(),
    );
    let mut cuts = Sizes {
        state: seed,
        table: CHUNK_SIZES,
    };
    let mut reads = Sizes {
        state: !seed,
        table: READ_SIZES,
    };
    let mut out = Vec::new();
    let mut budget = 4 * wire.len() + 64;
    let mut cx = Context::from_waker(Waker::noop());
    let mut rest = wire;
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(cuts.next().min(rest.len()));
        rest = tail;
        let written = Pin::new(&mut far).poll_write(&mut cx, chunk);
        assert!(
            matches!(written, Poll::Ready(Ok(n)) if n == chunk.len()),
            "the in-memory transport is sized for the whole input"
        );
        if matches!(
            drain(&mut stream, &mut reads, &mut out, &mut budget),
            Step::Ended
        ) {
            return out;
        }
    }
    drop(far);
    let end = drain(&mut stream, &mut reads, &mut out, &mut budget);
    assert!(
        matches!(end, Step::Ended),
        "the reader waits past the end of its transport"
    );
    out
}

fn read_over_tcp(keys: Keys, wire: &[u8], seed: u32) -> io::Result<Vec<u8>> {
    LOOPBACK.with_borrow_mut(|slot| {
        let loopback = match slot {
            Some(loopback) => loopback,
            None => slot.insert(Loopback::open()?),
        };
        let out = read_over(loopback, keys, wire, seed);
        if out.is_err() {
            *slot = None;
        }
        out
    })
}

fn read_over(loopback: &mut Loopback, keys: Keys, wire: &[u8], seed: u32) -> io::Result<Vec<u8>> {
    let near: BoxStream = Box::new(Bare(loopback.near.clone()));
    let mut stream = RecordStream::new(
        RecordIo::unaligned(near),
        keys,
        None,
        Vec::new(),
        Vec::new(),
    );
    let mut cuts = Sizes {
        state: seed,
        table: CHUNK_SIZES,
    };
    let mut reads = Sizes {
        state: !seed,
        table: READ_SIZES,
    };
    let mut out = Vec::new();
    let mut budget = 4 * wire.len() + 64;
    let mut rest = wire;
    while !rest.is_empty() {
        let (chunk, tail) = rest.split_at(cuts.next().min(rest.len()));
        rest = tail;
        loopback.far.write_all(chunk)?;
        loopback.arrived()?;
        if matches!(
            drain(&mut stream, &mut reads, &mut out, &mut budget),
            Step::Ended
        ) {
            break;
        }
    }
    drop(stream);
    loopback.resync()?;
    Ok(out)
}

/// Runs a record stream's read side over the bytes `data` describes and checks that it neither
/// panics nor delivers anything but a prefix of the application data that was sealed for it.
///
/// The first byte picks TLS 1.3 or 1.2, an in-memory transport or a bare TCP socket, and raw or
/// scripted bytes; the next four seed how the bytes are cut into arrivals and reads.
pub fn read_records(data: &[u8]) {
    let mut input = Input(data);
    let mode = input.byte().unwrap_or_default();
    let seed = input
        .take(4)
        .iter()
        .fold(0u32, |seed, byte| (seed << 8) | u32::from(*byte));
    let Ok((client, mut server)) = keys(mode & 1 == 0) else {
        return;
    };
    let (wire, expected) = if mode & 4 == 0 {
        script(&mut input, &mut server)
    } else {
        (input.0.to_vec(), Vec::new())
    };
    let out = if mode & 2 == 0 {
        read_over_memory(client, &wire, seed)
    } else {
        match read_over_tcp(client, &wire, seed) {
            Ok(out) => out,
            Err(_) => return,
        }
    };
    assert!(
        expected.starts_with(&out),
        "the reader delivered {} bytes that were not sealed for it in that order",
        out.len()
    );
}
