#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(
    unsafe_code,
    reason = "puts SIGPIPE back to the default an embedding host leaves it at"
)]

use std::io::{ErrorKind, Write};
use std::thread::sleep;
use std::time::Duration;

use concord_platform::{SplicePipe, ignore_sigpipe};
use concord_test_support::std_tcp_pair as pair;

#[test]
fn a_splice_into_a_closed_peer_fails_instead_of_ending_the_process() {
    // SAFETY: SIG_DFL is a valid disposition, and this test binary runs nothing else.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    assert_eq!(
        SplicePipe::new().err().map(|e| e.kind()),
        Some(ErrorKind::Unsupported)
    );

    ignore_sigpipe();
    let mut pipe = SplicePipe::new().unwrap();
    let (mut src_far, src) = pair();
    let (dst, dst_far) = pair();
    src.set_nonblocking(true).unwrap();
    dst.set_nonblocking(true).unwrap();
    drop(dst_far);

    let failure = (0..50).find_map(|_| {
        src_far.write_all(&[7; 16 * 1024]).unwrap();
        sleep(Duration::from_millis(20));
        let _ = pipe.fill(&src);
        pipe.drain(&dst).err()
    });
    let kind = failure
        .expect("writes into the closed peer kept succeeding")
        .kind();
    assert!(
        matches!(kind, ErrorKind::BrokenPipe | ErrorKind::ConnectionReset),
        "{kind:?}"
    );
}
