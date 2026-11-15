use std::error::Error;
use std::io;

use concord_common::CoreError;

/// Whether `err`, or an error it carries at any depth, says this process ran out of descriptors,
/// socket buffers or memory, which says nothing about the peer being dialed.
pub fn is_local_exhaustion(err: &io::Error) -> bool {
    let mut next: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(current) = next {
        if let Some(io) = current.downcast_ref::<io::Error>() {
            if io.kind() == io::ErrorKind::OutOfMemory
                || io.raw_os_error().is_some_and(out_of_descriptors_or_buffers)
            {
                return true;
            }
            // `io::Error::source` skips the error it wraps and goes to that error's source.
            next = io.get_ref().map(|inner| inner as &(dyn Error + 'static));
            continue;
        }
        if matches!(current.downcast_ref(), Some(CoreError::FdPressure)) {
            return true;
        }
        next = current.source();
    }
    false
}

#[cfg(unix)]
fn out_of_descriptors_or_buffers(code: i32) -> bool {
    matches!(code, libc::EMFILE | libc::ENFILE | libc::ENOBUFS)
}

#[cfg(windows)]
fn out_of_descriptors_or_buffers(code: i32) -> bool {
    use windows_sys::Win32::Networking::WinSock::{WSAEMFILE, WSAENOBUFS};
    matches!(code, WSAEMFILE | WSAENOBUFS)
}

#[cfg(not(any(unix, windows)))]
fn out_of_descriptors_or_buffers(_: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::sync::Arc;

    use super::*;

    #[derive(Debug)]
    struct Wrapped(Arc<io::Error>);

    impl fmt::Display for Wrapped {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "wrapped: {}", self.0)
        }
    }

    impl Error for Wrapped {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    fn wrap(err: io::Error) -> io::Error {
        io::Error::new(err.kind(), Wrapped(Arc::new(err)))
    }

    #[test]
    fn exhaustion_is_found_at_any_depth() {
        let pressure = || io::Error::from(CoreError::FdPressure);
        assert!(is_local_exhaustion(&pressure()));
        assert!(is_local_exhaustion(&wrap(wrap(pressure()))));
        assert!(is_local_exhaustion(&io::Error::other(wrap(pressure()))));
        assert!(is_local_exhaustion(&wrap(io::Error::from(
            io::ErrorKind::OutOfMemory
        ))));
        #[cfg(unix)]
        assert!(is_local_exhaustion(&wrap(io::Error::from_raw_os_error(
            libc::EMFILE
        ))));
    }

    #[test]
    fn a_failure_of_the_peer_or_the_path_is_not_exhaustion() {
        for err in [
            io::Error::from(io::ErrorKind::TimedOut),
            io::Error::from(io::ErrorKind::ConnectionRefused),
            io::Error::from(io::ErrorKind::WouldBlock),
            io::Error::other("all DNS requests failed"),
            io::Error::from(CoreError::DialerLoop("node".into())),
        ] {
            assert!(!is_local_exhaustion(&wrap(err)));
        }
    }
}
