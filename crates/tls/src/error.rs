use std::io;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Certificate(String),
    #[error("{0}")]
    Handshake(String),
}

impl From<TlsError> for io::Error {
    fn from(err: TlsError) -> Self {
        let kind = match err {
            TlsError::Config(_) => io::ErrorKind::InvalidInput,
            TlsError::Certificate(_) => io::ErrorKind::InvalidData,
            TlsError::Handshake(_) => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, err)
    }
}

pub(crate) fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
