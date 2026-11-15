use concord_common::RawSocket;

/// How a socket is told from a later one that takes its descriptor number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketIdentity {
    /// `SO_COOKIE`: unique for the kernel's uptime. Linux 4.12 and later.
    Cookie,
    /// The socket's inode number, which Linux reuses only after its 32-bit counter wraps. macOS
    /// reports 0 for every socket, which counts as no identity.
    Inode,
}

impl SocketIdentity {
    /// The cookie where the kernel has it for `socket`, the inode otherwise.
    pub fn probe(socket: RawSocket) -> SocketIdentity {
        if SocketIdentity::Cookie.of(socket).is_some() {
            SocketIdentity::Cookie
        } else {
            SocketIdentity::Inode
        }
    }

    /// `None` when the descriptor is no socket, or no longer open.
    pub fn of(self, socket: RawSocket) -> Option<u64> {
        imp::identity(self, socket)
    }
}

/// Runs `f` with a duplicate of `socket` when it still names the socket `identity` was read
/// from, so the socket cannot close and give its number away while `f` runs. `None` when it is
/// closed, or its number now belongs to another socket.
pub fn with_same_socket<R>(
    socket: RawSocket,
    kind: SocketIdentity,
    identity: u64,
    f: impl FnOnce(RawSocket) -> R,
) -> Option<R> {
    imp::with_same_socket(socket, kind, identity, f)
}

#[cfg(unix)]
mod imp {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use concord_common::RawSocket;

    use super::SocketIdentity;

    /// The asm-generic value, used by every architecture Concord builds for; libc does not export
    /// it for Android.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const SO_COOKIE: libc::c_int = 57;

    pub(super) fn identity(kind: SocketIdentity, socket: RawSocket) -> Option<u64> {
        let fd = RawFd::try_from(socket.0).ok()?;
        match kind {
            SocketIdentity::Cookie => cookie(fd),
            SocketIdentity::Inode => inode(fd),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn cookie(fd: RawFd) -> Option<u64> {
        let mut value: u64 = 0;
        let mut len = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: `value` and `len` are valid out-pointers that match the size passed; a closed or
        // foreign descriptor only makes the call fail.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_COOKIE,
                std::ptr::from_mut(&mut value).cast(),
                &mut len,
            )
        };
        (rc == 0 && len as usize == std::mem::size_of::<u64>()).then_some(value)
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn cookie(_fd: RawFd) -> Option<u64> {
        None
    }

    fn inode(fd: RawFd) -> Option<u64> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` is a valid out-pointer for one `struct stat`; a closed descriptor only
        // makes the call fail.
        let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        // SAFETY: `fstat` succeeded, so it filled the whole struct.
        let stat = unsafe { stat.assume_init() };
        // 32-bit Android has a `u32` st_mode but a `u16` mode_t.
        let file_type = u64::from(stat.st_mode) & u64::from(libc::S_IFMT);
        (file_type == u64::from(libc::S_IFSOCK) && stat.st_ino != 0).then_some(stat.st_ino)
    }

    pub(super) fn with_same_socket<R>(
        socket: RawSocket,
        kind: SocketIdentity,
        identity: u64,
        f: impl FnOnce(RawSocket) -> R,
    ) -> Option<R> {
        let fd = RawFd::try_from(socket.0).ok()?;
        // SAFETY: duplicating a number this process may no longer own is harmless: it fails, or
        // yields a descriptor the identity check below rejects unless it is the same socket.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return None;
        }
        // SAFETY: `fcntl` just returned this descriptor and nothing else owns it.
        let dup = unsafe { OwnedFd::from_raw_fd(dup) };
        let raw = RawSocket(i64::from(dup.as_raw_fd()));
        (self::identity(kind, raw) == Some(identity)).then(|| f(raw))
    }
}

#[cfg(not(unix))]
mod imp {
    use concord_common::RawSocket;

    use super::SocketIdentity;

    pub(super) fn identity(_kind: SocketIdentity, _socket: RawSocket) -> Option<u64> {
        None
    }

    pub(super) fn with_same_socket<R>(
        _socket: RawSocket,
        _kind: SocketIdentity,
        _identity: u64,
        _f: impl FnOnce(RawSocket) -> R,
    ) -> Option<R> {
        None
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    #[allow(
        clippy::disallowed_methods,
        reason = "the test needs bare loopback sockets"
    )]
    fn udp() -> std::net::UdpSocket {
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    fn raw(socket: &impl AsRawFd) -> RawSocket {
        RawSocket(i64::from(socket.as_raw_fd()))
    }

    fn kinds() -> [SocketIdentity; 2] {
        [SocketIdentity::Inode, SocketIdentity::Cookie]
    }

    #[test]
    fn the_cookie_is_probed_where_the_kernel_has_it() {
        assert_eq!(SocketIdentity::probe(raw(&udp())), SocketIdentity::Cookie);
    }

    #[test]
    fn two_live_sockets_differ_and_a_file_is_no_socket() {
        let (one, two) = (udp(), udp());
        for kind in kinds() {
            let a = kind.of(raw(&one)).unwrap();
            assert_eq!(kind.of(raw(&one)), Some(a), "{kind:?}");
            assert_ne!(kind.of(raw(&two)), Some(a), "{kind:?}");
        }
        let file = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(SocketIdentity::Inode.of(raw(&file)), None);
    }

    #[test]
    fn a_number_taken_by_another_socket_is_refused() {
        for kind in kinds() {
            let first = udp();
            let number = raw(&first);
            let identity = kind.of(number).unwrap();
            assert_eq!(
                with_same_socket(number, kind, identity, |dup| dup != number),
                Some(true),
                "{kind:?}: the duplicate is a new descriptor of the same socket"
            );
            drop(first);
            assert_eq!(with_same_socket(number, kind, identity, |_| ()), None);
            let _second = udp();
            assert_eq!(
                with_same_socket(number, kind, identity, |_| ()),
                None,
                "{kind:?}"
            );
        }
    }
}
