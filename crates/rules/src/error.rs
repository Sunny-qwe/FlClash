use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatError(String);

impl FormatError {
    pub fn new(message: impl Into<String>) -> Self {
        FormatError(message.into())
    }
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FormatError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidDomain {
    pub domain: String,
    pub reason: String,
}

impl InvalidDomain {
    pub(crate) fn new(domain: &str, reason: impl Into<String>) -> Self {
        InvalidDomain {
            domain: domain.to_string(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for InvalidDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid domain {:?}: {}", self.domain, self.reason)
    }
}

impl std::error::Error for InvalidDomain {}
