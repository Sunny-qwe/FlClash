/// Only a Rust binary ignores SIGPIPE before `main`: a library takes its host's disposition, and in the Android app
/// that stays fatal until Dart starts. A handler the host installed stays in place.
pub fn ignore_sigpipe() {
    if sigpipe_kills() {
        // SAFETY: SIG_IGN is a valid disposition for SIGPIPE.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    }
}

pub(crate) fn sigpipe_kills() -> bool {
    // SAFETY: a null new action only reads the current one, and an all-zero sigaction is a valid value to fill.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut current) != 0
            || current.sa_sigaction == libc::SIG_DFL
    }
}
