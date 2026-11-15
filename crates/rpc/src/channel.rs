use std::future::Future;
use std::io;

use tokio::sync::mpsc;

/// One message arriving from the peer.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    Message(Vec<u8>),
    /// A message above the limit. The transport has already skipped its body, so
    /// the connection stays in step and the server can answer `payload_too_large`.
    Oversized {
        len: u64,
    },
}

#[derive(Debug)]
pub enum SendError {
    /// Nothing of the message reached the peer; the connection is still usable.
    Dropped(io::Error),
    /// Part of a message was written and the rest could not be, so the stream is
    /// no longer in step.
    Broken(io::Error),
}

pub trait MessageReader: Send + 'static {
    /// `None` is a clean close by the peer.
    fn recv(&mut self) -> impl Future<Output = io::Result<Option<Incoming>>> + Send;
}

pub trait MessageWriter: Send + 'static {
    fn send(&mut self, message: Vec<u8>) -> impl Future<Output = Result<(), SendError>> + Send;
}

/// All the RPC layer knows of a transport: a message in, a message out, and the end.
pub trait MessageChannel: Send + 'static {
    type Reader: MessageReader;
    type Writer: MessageWriter;

    fn split(self) -> (Self::Reader, Self::Writer);
}

/// A channel in memory, for tests and for in-process embedding.
pub struct MemoryChannel {
    incoming: mpsc::Receiver<Incoming>,
    outgoing: mpsc::Sender<Incoming>,
}

impl MemoryChannel {
    pub fn pair(depth: usize) -> (MemoryChannel, MemoryChannel) {
        let (a_tx, a_rx) = mpsc::channel(depth);
        let (b_tx, b_rx) = mpsc::channel(depth);
        (
            MemoryChannel {
                incoming: b_rx,
                outgoing: a_tx,
            },
            MemoryChannel {
                incoming: a_rx,
                outgoing: b_tx,
            },
        )
    }

    pub async fn send(&self, message: Vec<u8>) -> bool {
        self.outgoing.send(Incoming::Message(message)).await.is_ok()
    }

    /// Stands for a transport that skipped a message above its limit.
    pub async fn send_oversized(&self, len: u64) -> bool {
        self.outgoing
            .send(Incoming::Oversized { len })
            .await
            .is_ok()
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        match self.incoming.recv().await? {
            Incoming::Message(message) => Some(message),
            Incoming::Oversized { .. } => None,
        }
    }
}

pub struct MemoryReader(mpsc::Receiver<Incoming>);
pub struct MemoryWriter(mpsc::Sender<Incoming>);

impl MessageReader for MemoryReader {
    async fn recv(&mut self) -> io::Result<Option<Incoming>> {
        Ok(self.0.recv().await)
    }
}

impl MessageWriter for MemoryWriter {
    async fn send(&mut self, message: Vec<u8>) -> Result<(), SendError> {
        self.0
            .send(Incoming::Message(message))
            .await
            .map_err(|_| SendError::Broken(io::ErrorKind::BrokenPipe.into()))
    }
}

impl MessageChannel for MemoryChannel {
    type Reader = MemoryReader;
    type Writer = MemoryWriter;

    fn split(self) -> (MemoryReader, MemoryWriter) {
        (MemoryReader(self.incoming), MemoryWriter(self.outgoing))
    }
}
