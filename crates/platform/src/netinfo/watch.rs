//! The network epoch: it moves on every link, address or route change the kernel reports.

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use netlink::epoch;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn epoch() -> u64 {
    0
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod netlink {
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::sync::Once;
    use std::sync::atomic::{AtomicU64, Ordering};

    use socket2::{Domain, Protocol, Socket, Type};

    // rtnetlink.h's group bits; Android's libc leaves them out.
    const RTMGRP_LINK: u32 = 0x1;
    const RTMGRP_IPV4_IFADDR: u32 = 0x10;
    const RTMGRP_IPV4_ROUTE: u32 = 0x40;
    const RTMGRP_IPV6_IFADDR: u32 = 0x100;
    const RTMGRP_IPV6_ROUTE: u32 = 0x400;
    const GROUPS: u32 = RTMGRP_LINK
        | RTMGRP_IPV4_IFADDR
        | RTMGRP_IPV4_ROUTE
        | RTMGRP_IPV6_IFADDR
        | RTMGRP_IPV6_ROUTE;

    static EPOCH: AtomicU64 = AtomicU64::new(0);
    static START: Once = Once::new();

    pub fn epoch() -> u64 {
        START.call_once(start);
        EPOCH.load(Ordering::Acquire)
    }

    /// Android refuses `bind` on a route socket to apps, so there the tables only age out or
    /// are dropped when the host reports a network change.
    fn start() {
        let watching = subscribe().and_then(|socket| {
            std::thread::Builder::new()
                .name("concord-netwatch".into())
                .spawn(move || watch(&socket))
        });
        if let Err(err) = watching {
            tracing::debug!("network changes are not watched: {err}");
        }
    }

    fn subscribe() -> io::Result<Socket> {
        let socket = Socket::new(
            Domain::from(libc::AF_NETLINK),
            Type::RAW,
            Some(Protocol::from(libc::NETLINK_ROUTE)),
        )?;
        // SAFETY: all-zero bytes are a valid `sockaddr_nl`.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = GROUPS;
        // SAFETY: `addr` is a `sockaddr_nl` passed with its own size, and the socket is open.
        let rc = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    fn watch(socket: &Socket) {
        let mut buf = [MaybeUninit::<u8>::uninit(); 16 * 1024];
        loop {
            match socket.recv(&mut buf) {
                Ok(_) => {
                    EPOCH.fetch_add(1, Ordering::Release);
                }
                // An overflowed queue dropped changes: the tables are stale all the same.
                Err(err) if err.raw_os_error() == Some(libc::ENOBUFS) => {
                    EPOCH.fetch_add(1, Ordering::Release);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => {
                    tracing::debug!("network change watch ended: {err}");
                    return;
                }
            }
        }
    }
}
