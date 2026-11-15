use std::io::{self, IoSliceMut};
use std::os::fd::RawFd;
use std::ptr;

const PREFIX: usize = 4;
pub const UTUN_BATCH: usize = 64;
/// `sendmsg_x` builds every packet of a batch before sending any, and a packet above 4096
/// bytes with its prefix takes a 16 KB mbuf cluster from a pool of a few hundred; a batch of
/// them fails with ENOBUFS, so only frames up to this size are batched.
pub const UTUN_BATCH_FRAME: usize = 4096 - PREFIX;

#[repr(C)]
#[derive(Clone, Copy)]
struct MsgHdrX {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut libc::iovec,
    msg_iovlen: libc::c_int,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: libc::c_int,
    msg_datalen: usize,
}

const EMPTY_HEADER: MsgHdrX = MsgHdrX {
    msg_name: ptr::null_mut(),
    msg_namelen: 0,
    msg_iov: ptr::null_mut(),
    msg_iovlen: 0,
    msg_control: ptr::null_mut(),
    msg_controllen: 0,
    msg_flags: 0,
    msg_datalen: 0,
};

const EMPTY_IOVEC: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};

unsafe extern "C" {
    fn recvmsg_x(
        s: libc::c_int,
        msgp: *const MsgHdrX,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> isize;
    fn sendmsg_x(
        s: libc::c_int,
        msgp: *const MsgHdrX,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> isize;
}

/// Strips utun's family prefix; `lens` gets 0 for a packet that did not fit its buffer.
pub fn utun_recv_batch(
    fd: RawFd,
    bufs: &mut [IoSliceMut<'_>],
    lens: &mut [usize],
) -> io::Result<usize> {
    let count = bufs.len().min(lens.len()).min(UTUN_BATCH);
    let mut prefixes = [[0u8; PREFIX]; UTUN_BATCH];
    let mut iovecs = [[EMPTY_IOVEC; 2]; UTUN_BATCH];
    let mut headers = [EMPTY_HEADER; UTUN_BATCH];
    for (((buf, prefix), iovec), header) in bufs
        .iter_mut()
        .zip(prefixes.iter_mut())
        .zip(iovecs.iter_mut())
        .zip(headers.iter_mut())
        .take(count)
    {
        *iovec = [
            libc::iovec {
                iov_base: prefix.as_mut_ptr().cast(),
                iov_len: PREFIX,
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
        ];
        header.msg_iov = iovec.as_mut_ptr();
        header.msg_iovlen = 2;
    }
    let received = loop {
        // SAFETY: the first `count` headers point at iovecs over buffers borrowed for this call.
        let n = unsafe { recvmsg_x(fd, headers.as_ptr(), count as libc::c_uint, 0) };
        if n >= 0 {
            break n.unsigned_abs();
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    };
    for (header, len) in headers.iter().zip(lens.iter_mut()).take(received) {
        let truncated = header.msg_flags & libc::MSG_TRUNC != 0;
        *len = if truncated || header.msg_datalen <= PREFIX {
            0
        } else {
            header.msg_datalen - PREFIX
        };
    }
    Ok(received)
}

/// ENOBUFS comes back as `WouldBlock` with nothing sent; any other error consumed the whole batch.
pub fn utun_send_batch(fd: RawFd, packets: &[&[u8]]) -> io::Result<usize> {
    let count = packets.len().min(UTUN_BATCH);
    let mut prefixes = [[0u8; PREFIX]; UTUN_BATCH];
    let mut iovecs = [[EMPTY_IOVEC; 2]; UTUN_BATCH];
    let mut headers = [EMPTY_HEADER; UTUN_BATCH];
    for (((packet, prefix), iovec), header) in packets
        .iter()
        .zip(prefixes.iter_mut())
        .zip(iovecs.iter_mut())
        .zip(headers.iter_mut())
        .take(count)
    {
        let family = match packet.first().map(|b| b >> 4) {
            Some(6) => libc::AF_INET6,
            _ => libc::AF_INET,
        };
        *prefix = (family as u32).to_be_bytes();
        *iovec = [
            libc::iovec {
                iov_base: prefix.as_mut_ptr().cast(),
                iov_len: PREFIX,
            },
            libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast(),
                iov_len: packet.len(),
            },
        ];
        header.msg_iov = iovec.as_mut_ptr();
        header.msg_iovlen = 2;
    }
    loop {
        // SAFETY: the first `count` headers point at iovecs the kernel only reads during the call.
        let n = unsafe { sendmsg_x(fd, headers.as_ptr(), count as libc::c_uint, 0) };
        if n >= 0 {
            return Ok(n.unsigned_abs());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ENOBUFS) => return Err(io::ErrorKind::WouldBlock.into()),
            _ => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    use super::*;

    #[test]
    #[allow(clippy::disallowed_methods, reason = "a loopback test pair")]
    fn a_batch_round_trips_with_the_family_prefix() {
        let near = UdpSocket::bind("127.0.0.1:0").unwrap();
        let far = UdpSocket::bind("127.0.0.1:0").unwrap();
        near.connect(far.local_addr().unwrap()).unwrap();
        far.connect(near.local_addr().unwrap()).unwrap();
        let v4 = [0x45u8, 1, 2, 3, 4];
        let v6 = [0x60u8, 9, 8];
        let sent = utun_send_batch(near.as_raw_fd(), &[&v4, &v6]).unwrap();
        assert_eq!(sent, 2);

        let mut raw = [0u8; 16];
        let n = far.peek(&mut raw).unwrap();
        assert_eq!(&raw[..n], &[0, 0, 0, libc::AF_INET as u8, 0x45, 1, 2, 3, 4]);

        far.set_nonblocking(true).unwrap();
        let mut bufs = [[0u8; 8]; 3];
        let mut lens = [9; 3];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got = 0;
        // The second datagram may still be in flight on loopback when the first is peeked.
        while got < 2 {
            let mut slices: Vec<_> = bufs[got..].iter_mut().map(|b| IoSliceMut::new(b)).collect();
            match utun_recv_batch(far.as_raw_fd(), &mut slices, &mut lens[got..]) {
                Ok(n) => got += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "only {got} arrived");
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(err) => panic!("{err}"),
            }
        }
        assert_eq!(got, 2);
        assert_eq!(&lens[..2], &[5, 3]);
        assert_eq!(&bufs[0][..5], &v4);
        assert_eq!(&bufs[1][..3], &v6);
        let empty = utun_recv_batch(
            far.as_raw_fd(),
            &mut [IoSliceMut::new(&mut bufs[0])],
            &mut lens,
        )
        .unwrap_err();
        assert_eq!(empty.kind(), io::ErrorKind::WouldBlock);
    }
}
