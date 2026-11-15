#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SniffError {
    #[error("not enough information for making a decision")]
    NoClue,
    #[error("need at least {0} bytes")]
    NeedAtLeast(usize),
    #[error("not TLS header")]
    NotTls,
    #[error("not client hello")]
    NotClientHello,
    #[error("not an HTTP")]
    NotHttp,
    #[error("host is ip")]
    HostIsIp,
    #[error("not QUIC")]
    NotQuic,
    #[error("not QUIC initial packet")]
    NotQuicInitial,
    #[error("QUIC decryption failed")]
    DecryptionFailed,
    #[error("unexpected EOF")]
    UnexpectedEof,
    #[error("crypto data exceeds the sniffing budget")]
    ShortBuffer,
    #[error("sniffing buffer is full")]
    BufferFull,
    #[error("reading ahead failed")]
    Read,
    #[error("all sniffer failed")]
    AllFailed,
}
