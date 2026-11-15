use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::AsyncWrite;

/// Holds the tail of a bulk write so the writer seals whole chunks.
///
/// The AEAD writers of the `shadowsocks` crate, like sing-shadowsocks's, seal every write
/// into chunks of at most `chunk` bytes and never join writes, so a copy loop whose buffer
/// is not a multiple of the chunk ends each buffer in a runt chunk that costs the reader
/// a read and an open of its own. Once a write has filled a chunk, a shorter write after
/// it is kept until it can be topped up to a full chunk, and goes out at the latest on
/// `flush` or `shutdown`, as a `BufWriter` would hold it. A write after a flush, or a
/// short write with no full chunk before it, is passed through at once.
pub(crate) struct Tail {
    chunk: usize,
    held: Vec<u8>,
    draining: bool,
    bulk: bool,
}

impl Tail {
    /// A `chunk` of 0 passes everything through, for ciphers that do not frame.
    pub(crate) fn new(chunk: usize) -> Self {
        Tail {
            chunk,
            held: Vec::new(),
            draining: false,
            bulk: false,
        }
    }

    pub(crate) fn poll_write<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.chunk == 0 || data.is_empty() {
            return Pin::new(writer).poll_write(cx, data);
        }
        if ready!(self.poll_forward(cx, writer, data.len()))? {
            let written = ready!(Pin::new(writer).poll_write(cx, data))?;
            self.record_forward(written);
            return Poll::Ready(Ok(written));
        }
        let take = data.len().min(self.chunk - self.held.len());
        self.held
            .extend_from_slice(data.get(..take).unwrap_or_default());
        if self.held.len() == self.chunk {
            self.draining = true;
            if let Poll::Ready(Err(err)) = self.poll_drain(cx, writer) {
                return Poll::Ready(Err(err));
            }
        }
        Poll::Ready(Ok(take))
    }

    pub(crate) fn poll_forward<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
        length: usize,
    ) -> Poll<io::Result<bool>> {
        ready!(self.poll_drain(cx, writer))?;
        Poll::Ready(Ok(
            self.held.is_empty() && (!self.bulk || length >= self.chunk)
        ))
    }

    pub(crate) fn record_forward(&mut self, written: usize) {
        self.bulk = written >= self.chunk;
    }

    pub(crate) fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<io::Result<()>> {
        self.draining = !self.held.is_empty();
        ready!(self.poll_drain(cx, writer))?;
        self.bulk = false;
        Pin::new(writer).poll_flush(cx)
    }

    pub(crate) fn poll_shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<io::Result<()>> {
        self.draining = !self.held.is_empty();
        ready!(self.poll_drain(cx, writer))?;
        Pin::new(writer).poll_shutdown(cx)
    }

    fn poll_drain<W: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        writer: &mut W,
    ) -> Poll<io::Result<()>> {
        while self.draining {
            let written = ready!(Pin::new(&mut *writer).poll_write(cx, &self.held))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.held.drain(..written);
            self.draining = !self.held.is_empty();
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use super::*;

    const CHUNK: usize = 100;

    /// Takes at most one chunk per write, as the `shadowsocks` AEAD writers do.
    #[derive(Default)]
    struct Chunks {
        sizes: Vec<usize>,
        shut: bool,
    }

    impl AsyncWrite for Chunks {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let taken = data.len().min(CHUNK);
            self.sizes.push(taken);
            Poll::Ready(Ok(taken))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shut = true;
            Poll::Ready(Ok(()))
        }
    }

    struct Buffered {
        tail: Tail,
        out: Chunks,
    }

    impl Buffered {
        fn new() -> Self {
            Buffered {
                tail: Tail::new(CHUNK),
                out: Chunks::default(),
            }
        }

        async fn write_all(&mut self, mut data: &[u8]) {
            while !data.is_empty() {
                let written = poll_fn(|cx| self.tail.poll_write(cx, &mut self.out, data))
                    .await
                    .unwrap();
                data = &data[written..];
            }
        }

        async fn flush(&mut self) {
            poll_fn(|cx| self.tail.poll_flush(cx, &mut self.out))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn the_tail_of_a_bulk_write_joins_the_next_write_into_a_whole_chunk() {
        let mut io = Buffered::new();
        io.write_all(&[1; 2 * CHUNK + 8]).await;
        assert_eq!(io.out.sizes, [CHUNK, CHUNK]);
        io.write_all(&[2; 2 * CHUNK - 8 + 5]).await;
        assert_eq!(io.out.sizes, [CHUNK, CHUNK, CHUNK, CHUNK]);
        io.flush().await;
        assert_eq!(io.out.sizes, [CHUNK, CHUNK, CHUNK, CHUNK, 5]);
    }

    #[tokio::test]
    async fn the_tail_leaves_on_flush_and_on_shutdown() {
        let mut io = Buffered::new();
        io.write_all(&[1; CHUNK + 3]).await;
        assert_eq!(io.out.sizes, [CHUNK]);
        io.flush().await;
        assert_eq!(io.out.sizes, [CHUNK, 3]);

        io.write_all(&[1; CHUNK + 4]).await;
        poll_fn(|cx| io.tail.poll_shutdown(cx, &mut io.out))
            .await
            .unwrap();
        assert_eq!(io.out.sizes, [CHUNK, 3, CHUNK, 4]);
        assert!(io.out.shut);
    }

    #[tokio::test]
    async fn short_writes_outside_a_bulk_burst_are_not_held() {
        let mut io = Buffered::new();
        io.write_all(&[1; 10]).await;
        io.write_all(&[1; CHUNK - 1]).await;
        assert_eq!(io.out.sizes, [10, CHUNK - 1]);

        io.write_all(&[1; CHUNK + 1]).await;
        io.flush().await;
        io.write_all(&[1; 7]).await;
        assert_eq!(io.out.sizes, [10, CHUNK - 1, CHUNK, 1, 7]);
    }

    #[tokio::test]
    async fn a_zero_chunk_passes_every_write_through() {
        let mut io = Buffered::new();
        io.tail = Tail::new(0);
        io.write_all(&[1; 2 * CHUNK + 8]).await;
        io.flush().await;
        assert_eq!(io.out.sizes, [CHUNK, CHUNK, 8]);
    }

    #[tokio::test]
    async fn a_full_chunk_waits_for_a_writer_that_is_not_ready() {
        struct Gate {
            open: bool,
            sizes: Vec<usize>,
        }

        impl AsyncWrite for Gate {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                if !self.open && !self.sizes.is_empty() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.sizes.push(data.len());
                Poll::Ready(Ok(data.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let mut tail = Tail::new(CHUNK);
        let mut out = Gate {
            open: false,
            sizes: Vec::new(),
        };
        let cx = &mut Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            tail.poll_write(cx, &mut out, &[1; CHUNK]),
            Poll::Ready(Ok(CHUNK))
        ));
        assert!(matches!(
            tail.poll_write(cx, &mut out, &[1; 5]),
            Poll::Ready(Ok(5))
        ));
        assert!(matches!(
            tail.poll_write(cx, &mut out, &[1; CHUNK]),
            Poll::Ready(Ok(n)) if n == CHUNK - 5
        ));
        assert!(tail.poll_write(cx, &mut out, &[1; 9]).is_pending());
        out.open = true;
        assert!(matches!(
            tail.poll_write(cx, &mut out, &[1; 9]),
            Poll::Ready(Ok(9))
        ));
        assert_eq!(out.sizes, [CHUNK, CHUNK]);
    }
}
