use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{DuplexStream, duplex};

use super::*;

const MAX: u64 = 1024;

fn halves(stream: DuplexStream) -> (FramedReader<DuplexStream>, FramedWriter<DuplexStream>) {
    FramedChannel::with_limit(stream, MAX).split()
}

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn a_frame_is_written_with_a_little_endian_length() {
    let (near, mut far) = duplex(1024);
    let (_, mut write) = halves(near);

    write.send(b"hello".to_vec()).await.ok().unwrap();

    let mut raw = [0u8; 9];
    far.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw.to_vec(), framed(b"hello"));
}

#[tokio::test]
async fn a_frame_is_read_back() {
    let (near, mut far) = duplex(1024);
    far.write_all(&framed(b"payload")).await.unwrap();
    let (mut read, _) = halves(near);

    assert_eq!(
        read.recv().await.unwrap(),
        Some(Incoming::Message(b"payload".to_vec()))
    );
}

#[tokio::test]
async fn an_oversized_frame_is_skipped_and_the_next_one_still_reads() {
    let (near, mut far) = duplex(1 << 16);
    let big = vec![7u8; MAX as usize + 1];
    far.write_all(&framed(&big)).await.unwrap();
    far.write_all(&framed(b"after")).await.unwrap();
    let (mut read, _) = halves(near);

    assert_eq!(
        read.recv().await.unwrap(),
        Some(Incoming::Oversized { len: MAX + 1 })
    );
    assert_eq!(
        read.recv().await.unwrap(),
        Some(Incoming::Message(b"after".to_vec()))
    );
}

#[tokio::test]
async fn a_truncated_payload_is_an_error_and_a_clean_close_is_none() {
    let (near, mut far) = duplex(1024);
    far.write_all(&10u32.to_le_bytes()).await.unwrap();
    far.write_all(b"abc").await.unwrap();
    drop(far);
    let (mut read, _) = halves(near);
    assert_eq!(
        read.recv().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );

    let (near, far) = duplex(1024);
    drop(far);
    let (mut read, _) = halves(near);
    assert_eq!(read.recv().await.unwrap(), None);
}

#[tokio::test]
async fn an_oversized_message_is_dropped_without_touching_the_wire() {
    let (near, mut far) = duplex(4096);
    let (_, mut write) = halves(near);

    let outcome = write.send(vec![0u8; MAX as usize + 1]).await;

    assert!(matches!(outcome, Err(SendError::Dropped(_))));
    drop(write);
    let mut seen = Vec::new();
    far.read_to_end(&mut seen).await.unwrap();
    assert!(seen.is_empty());
}

struct Stalled;

impl AsyncRead for Stalled {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Stalled {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn a_stall_before_the_first_byte_drops_the_message_after_ten_seconds() {
    let (_, mut write) = tokio::io::split(Stalled);
    let started = Instant::now();

    let outcome = write_frame(&mut write, b"data", MAX).await;

    assert!(matches!(
        outcome,
        Err(SendError::Dropped(err)) if err.kind() == io::ErrorKind::TimedOut
    ));
    assert_eq!(started.elapsed(), WRITE_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn a_frame_that_stalls_midway_is_waited_out_and_arrives_whole() {
    let (near, far) = duplex(6);
    let (_, mut write) = halves(near);
    let writer = tokio::spawn(async move { write.send(b"abcdefghij".to_vec()).await.is_ok() });
    tokio::time::sleep(WRITE_TIMEOUT * 3 + Duration::from_secs(1)).await;
    assert!(!writer.is_finished(), "the write gave up on a live stall");

    let (mut read, _) = halves(far);

    assert_eq!(
        read.recv().await.unwrap(),
        Some(Incoming::Message(b"abcdefghij".to_vec()))
    );
    assert!(writer.await.unwrap());
}

struct FailAfter {
    budget: usize,
}

impl AsyncRead for FailAfter {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for FailAfter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.budget == 0 {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let taken = buf.len().min(self.budget);
        self.budget -= taken;
        Poll::Ready(Ok(taken))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_hard_error_after_part_of_a_frame_breaks_the_connection() {
    let (_, mut write) = tokio::io::split(FailAfter { budget: 6 });
    let outcome = write_frame(&mut write, b"abcdefghij", MAX).await;
    assert!(matches!(outcome, Err(SendError::Broken(_))));
}

#[tokio::test]
async fn a_hard_error_before_any_byte_only_drops_the_message() {
    let (_, mut write) = tokio::io::split(FailAfter { budget: 0 });
    let outcome = write_frame(&mut write, b"abc", MAX).await;
    assert!(matches!(outcome, Err(SendError::Dropped(_))));
}

#[tokio::test]
async fn digits_dial_a_loopback_port_and_anything_else_a_socket() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = tokio::spawn(async move { listener.accept().await.is_ok() });
    let mut connection = dial(&port.to_string()).await.unwrap();
    connection.write_all(b"x").await.unwrap();
    assert!(accepted.await.unwrap());

    assert!(dial("999999").await.is_err());
    assert!(dial("/definitely/not/a/socket").await.is_err());
}
