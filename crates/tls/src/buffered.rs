use std::io::{self, BufRead};
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::{BoxRead, BoxStream, BoxWrite, split_with_lock};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::boring_backend::{self, BoringStream, LogSlot};
use crate::record::{Keys, RecordStream};
use crate::record_io::RecordIo;
use crate::rustls_backend::RustlsStream;

enum Backend {
    Rustls(Box<RustlsStream>),
    Boring {
        stream: Box<BoringStream>,
        slot: LogSlot,
    },
}

pub struct BufferedTls {
    backend: Backend,
    read_started: bool,
    write_pending: bool,
    closing: bool,
}

pub(crate) fn split_event(backend: &str, outcome: &str, reason: &str) {
    tracing::debug!(target: "concord_tls::split", backend, outcome, reason, "TLS split handoff");
}

impl BufferedTls {
    pub(crate) fn rustls(stream: RustlsStream) -> Self {
        Self::new(Backend::Rustls(Box::new(stream)))
    }

    pub(crate) fn boring(stream: BoringStream, slot: LogSlot) -> Self {
        Self::new(Backend::Boring {
            stream: Box::new(stream),
            slot,
        })
    }

    fn new(backend: Backend) -> Self {
        Self {
            backend,
            read_started: false,
            write_pending: false,
            closing: false,
        }
    }

    fn name(&self) -> &'static str {
        match self.backend {
            Backend::Rustls(_) => "rustls",
            Backend::Boring { .. } => "boring",
        }
    }

    pub(crate) fn io(&self) -> &RecordIo<BoxStream> {
        match &self.backend {
            Backend::Rustls(stream) => stream.get_ref().0,
            Backend::Boring { stream, .. } => stream.get_ref(),
        }
    }

    pub(crate) fn io_mut(&mut self) -> &mut RecordIo<BoxStream> {
        match &mut self.backend {
            Backend::Rustls(stream) => stream.get_mut().0,
            Backend::Boring { stream, .. } => stream.get_mut(),
        }
    }

    pub(crate) fn alpn(&self) -> Option<&[u8]> {
        match &self.backend {
            Backend::Rustls(stream) => stream.get_ref().1.alpn_protocol(),
            Backend::Boring { stream, .. } => stream.ssl().selected_alpn_protocol(),
        }
    }

    pub(crate) fn is_tls13(&self) -> bool {
        match &self.backend {
            Backend::Rustls(stream) => {
                stream.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
            }
            Backend::Boring { stream, .. } => {
                stream.ssl().version2() == Some(boring::ssl::SslVersion::TLS1_3)
            }
        }
    }

    pub(crate) fn has_plaintext(&mut self) -> bool {
        match &mut self.backend {
            Backend::Rustls(stream) => {
                matches!(stream.get_mut().1.reader().fill_buf(), Ok(data) if !data.is_empty())
            }
            Backend::Boring { stream, .. } => boring_backend::pending_plaintext(stream) > 0,
        }
    }

    pub(crate) fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        self.read_started = true;
        match &mut self.backend {
            Backend::Rustls(stream) => {
                let mut reader = stream.get_mut().1.reader();
                while let Ok(data) = reader.fill_buf() {
                    if data.is_empty() {
                        break;
                    }
                    let n = data.len();
                    out.extend_from_slice(data);
                    reader.consume(n);
                }
            }
            Backend::Boring { stream, .. } => boring_backend::drain_plaintext(stream, out),
        }
    }

    fn fallback_reason(&self) -> Option<&'static str> {
        if self.read_started {
            return Some("after-read");
        }
        if self.closing {
            return Some("closing");
        }
        if self.write_pending {
            return Some("pending-write");
        }
        match &self.backend {
            Backend::Rustls(stream) if !stream.get_ref().1.can_handoff_to_kernel() => {
                Some("buffered-or-control")
            }
            Backend::Boring { stream, .. } if !stream.get_ref().at_record_boundary() => {
                Some("partial-record")
            }
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_kernel_ready(&self) -> bool {
        match &self.backend {
            Backend::Rustls(stream) => stream.get_ref().1.can_handoff_to_kernel(),
            Backend::Boring { .. } => false,
        }
    }

    /// Refusal keeps the original TLS object, including errors and partially processed I/O.
    pub(crate) fn try_into_record(self) -> Result<io::Result<RecordStream>, Self> {
        if let Some(reason) = self.fallback_reason() {
            split_event(self.name(), "fallback", reason);
            return Err(self);
        }
        let Self {
            backend,
            read_started,
            write_pending,
            closing,
        } = self;
        match backend {
            Backend::Rustls(stream) => {
                let (io, conn) = (*stream).into_inner();
                let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
                let result = conn
                    .dangerous_into_kernel_connection()
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
                    .and_then(|(secrets, kernel)| Keys::from_rustls(secrets, kernel))
                    .map(|keys| RecordStream::new(io, keys, alpn, Vec::new(), Vec::new()));
                split_event(
                    "rustls",
                    if result.is_ok() { "native" } else { "error" },
                    "quiescent",
                );
                Ok(result)
            }
            Backend::Boring { mut stream, slot } => {
                match boring_backend::handoff(stream.ssl(), &slot) {
                    Ok(Some((keys, alpn))) => {
                        let placeholder: BoxStream = Box::new(tokio::io::duplex(1).0);
                        let io = std::mem::replace(stream.get_mut(), RecordIo::new(placeholder));
                        split_event("boring", "native", "quiescent");
                        Ok(Ok(RecordStream::new(
                            io,
                            keys,
                            alpn,
                            Vec::new(),
                            Vec::new(),
                        )))
                    }
                    Ok(None) => {
                        split_event("boring", "fallback", "buffered-or-ineligible");
                        Err(Self {
                            backend: Backend::Boring { stream, slot },
                            read_started,
                            write_pending,
                            closing,
                        })
                    }
                    Err(err) => {
                        split_event("boring", "error", "export");
                        Ok(Err(err))
                    }
                }
            }
        }
    }
}

impl AsyncRead for BufferedTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.read_started = true;
        match &mut this.backend {
            Backend::Rustls(stream) => Pin::new(&mut **stream).poll_read(cx, out),
            Backend::Boring { stream, .. } => Pin::new(&mut **stream).poll_read(cx, out),
        }
    }
}

impl AsyncWrite for BufferedTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = match &mut this.backend {
            Backend::Rustls(stream) => Pin::new(&mut **stream).poll_write(cx, data),
            Backend::Boring { stream, .. } => Pin::new(&mut **stream).poll_write(cx, data),
        };
        this.write_pending = !matches!(result, Poll::Ready(Ok(_)));
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.backend {
            Backend::Rustls(stream) => Pin::new(&mut **stream).poll_flush(cx),
            Backend::Boring { stream, .. } => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.closing = true;
        match &mut this.backend {
            Backend::Rustls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
            Backend::Boring { stream, .. } => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

struct FailedIo {
    kind: io::ErrorKind,
    message: String,
}

impl FailedIo {
    fn error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

impl AsyncRead for FailedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.error()))
    }
}

impl AsyncWrite for FailedIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(self.error()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.error()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(self.error()))
    }
}

impl concord_common::Stream for FailedIo {
    concord_common::stream_policy!(default: all);
}

pub(crate) fn failed_split(err: io::Error) -> (BoxRead, BoxWrite) {
    split_with_lock(FailedIo {
        kind: err.kind(),
        message: err.to_string(),
    })
}
