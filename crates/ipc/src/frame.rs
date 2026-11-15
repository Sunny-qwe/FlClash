use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use concord_proto::MAX_MESSAGE;
use concord_rpc::{Incoming, MessageChannel, MessageReader, MessageWriter, SendError};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf, copy, sink,
};
use tokio::time::Instant;

const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Connection for T {}

/// The concrete connection types, not a `Box<dyn Connection>`: rustc cannot prove
/// a spawned `Server::serve` future is `Send` over a trait object.
pub enum Socket {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    #[cfg(windows)]
    Pipe(tokio::net::windows::named_pipe::NamedPipeClient),
}

macro_rules! delegate {
    ($self:ident, $inner:ident => $call:expr) => {
        match $self.get_mut() {
            Socket::Tcp($inner) => $call,
            #[cfg(unix)]
            Socket::Unix($inner) => $call,
            #[cfg(windows)]
            Socket::Pipe($inner) => $call,
        }
    };
}

impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        delegate!(self, inner => Pin::new(inner).poll_read(cx, buf))
    }
}

impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        delegate!(self, inner => Pin::new(inner).poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, inner => Pin::new(inner).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, inner => Pin::new(inner).poll_shutdown(cx))
    }
}

/// Connects to the address the host listens on: digits are a loopback TCP port,
/// anything else a Unix socket path or a named pipe name.
pub fn dial(address: &str) -> impl Future<Output = io::Result<Socket>> + Send + 'static {
    let address = address.to_string();
    async move {
        if !address.is_empty() && address.bytes().all(|byte| byte.is_ascii_digit()) {
            #[allow(
                clippy::disallowed_methods,
                reason = "the loopback host connection is not an outbound dial"
            )]
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", port(&address)?)).await?;
            return Ok(Socket::Tcp(stream));
        }
        dial_local(address).await
    }
}

fn port(address: &str) -> io::Result<u16> {
    address.parse().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("port {address}: {err}"),
        )
    })
}

#[cfg(unix)]
async fn dial_local(address: String) -> io::Result<Socket> {
    Ok(Socket::Unix(
        tokio::net::UnixStream::connect(address).await?,
    ))
}

#[cfg(windows)]
async fn dial_local(address: String) -> io::Result<Socket> {
    use tokio::net::windows::named_pipe::ClientOptions;
    Ok(Socket::Pipe(ClientOptions::new().open(address)?))
}

/// Messages are `u32` little-endian length, then that many bytes of JSON.
pub struct FramedChannel<T> {
    io: T,
    max: u64,
}

impl<T: Connection> FramedChannel<T> {
    pub fn new(io: T) -> Self {
        Self::with_limit(io, MAX_MESSAGE)
    }

    pub fn with_limit(io: T, max: u64) -> Self {
        FramedChannel { io, max }
    }
}

pub struct FramedReader<T> {
    read: ReadHalf<T>,
    max: u64,
}

pub struct FramedWriter<T> {
    write: WriteHalf<T>,
    max: u64,
}

impl<T: Connection> MessageChannel for FramedChannel<T> {
    type Reader = FramedReader<T>;
    type Writer = FramedWriter<T>;

    fn split(self) -> (FramedReader<T>, FramedWriter<T>) {
        let (read, write) = tokio::io::split(self.io);
        (
            FramedReader {
                read,
                max: self.max,
            },
            FramedWriter {
                write,
                max: self.max,
            },
        )
    }
}

impl<T: Connection> MessageReader for FramedReader<T> {
    async fn recv(&mut self) -> io::Result<Option<Incoming>> {
        let mut header = [0u8; 4];
        match self.read.read_exact(&mut header).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err),
        }
        let length = u64::from(u32::from_le_bytes(header));
        if length > self.max {
            let skipped = copy(&mut (&mut self.read).take(length), &mut sink()).await?;
            if skipped < length {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            return Ok(Some(Incoming::Oversized { len: length }));
        }
        let mut data = vec![0u8; usize::try_from(length).unwrap_or(usize::MAX)];
        self.read.read_exact(&mut data).await?;
        Ok(Some(Incoming::Message(data)))
    }
}

impl<T: Connection> MessageWriter for FramedWriter<T> {
    async fn send(&mut self, message: Vec<u8>) -> Result<(), SendError> {
        write_frame(&mut self.write, &message, self.max).await
    }
}

/// A half-written frame is only in step while this side keeps writing it, and a
/// host the OS has suspended (Windows Modern Standby freezes the app but not a
/// service's child) drains again whenever it wakes, so such a stall is waited out
/// for as long as it lasts. A stall before the first byte only drops the frame.
async fn write_frame<W: AsyncWrite + Unpin>(
    write: &mut W,
    data: &[u8],
    max: u64,
) -> Result<(), SendError> {
    let Ok(length) = u32::try_from(data.len()) else {
        return Err(SendError::Dropped(io::Error::new(
            io::ErrorKind::InvalidData,
            "message does not fit a frame",
        )));
    };
    if data.len() as u64 > max {
        return Err(SendError::Dropped(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message exceeds {max} bytes"),
        )));
    }
    let header = length.to_le_bytes();
    let mut written = 0usize;
    for part in [&header[..], data] {
        let mut offset = 0;
        while let Some(rest) = part.get(offset..).filter(|rest| !rest.is_empty()) {
            let attempt =
                tokio::time::timeout_at(Instant::now() + WRITE_TIMEOUT, write.write(rest)).await;
            match attempt {
                Ok(Ok(0)) => return Err(failure(written, io::ErrorKind::WriteZero.into())),
                Ok(Ok(count)) => {
                    offset += count;
                    written += count;
                }
                Ok(Err(err)) => return Err(failure(written, err)),
                Err(_) if written == 0 => {
                    return Err(SendError::Dropped(io::ErrorKind::TimedOut.into()));
                }
                Err(_) => {}
            }
        }
    }
    write.flush().await.map_err(SendError::Broken)
}

fn failure(written: usize, err: io::Error) -> SendError {
    if written == 0 {
        SendError::Dropped(err)
    } else {
        SendError::Broken(err)
    }
}

#[cfg(test)]
mod tests;
