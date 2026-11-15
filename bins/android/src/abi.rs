use std::ffi::{CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, OnceLock};

use concord_api::LogBridge;
use tracing_subscriber::layer::SubscriberExt;

use crate::core::{Core, ThreadHook};
use crate::logcat;
use crate::platform::PlatformHost;

const PACKAGE_CAPACITY: usize = 223;

/// The `VpnService` side as C callbacks, each called with `context` from any core thread. A string
/// argument is a NUL-terminated `host:port`.
#[repr(C)]
pub struct ConcordPlatformHost {
    pub context: *mut c_void,
    /// Keeps `fd` out of the VPN, as `VpnService.protect`, and returns its answer: `false` while
    /// no VPN is established. The core protects a refused socket again on the next TUN start.
    pub protect: unsafe extern "C" fn(context: *mut c_void, fd: i32) -> bool,
    /// The uid that owns the connection, or -1.
    pub resolve_uid: unsafe extern "C" fn(
        context: *mut c_void,
        protocol: i32,
        source: *const c_char,
        target: *const c_char,
    ) -> i32,
    /// Writes the package of `uid` as UTF-8 into `buffer` and returns its length, 0 when unknown. A
    /// length above `capacity` asks for one more call with a buffer that holds it.
    pub resolve_package: unsafe extern "C" fn(
        context: *mut c_void,
        uid: i32,
        buffer: *mut u8,
        capacity: usize,
    ) -> usize,
    /// Runs with `context` once the core no longer holds this host.
    pub release: Option<unsafe extern "C" fn(context: *mut c_void)>,
}

struct CHost(ConcordPlatformHost);

// SAFETY: `concord_set_platform_host` requires callbacks that may run on any thread.
unsafe impl Send for CHost {}
// SAFETY: as above; the struct is only read.
unsafe impl Sync for CHost {}

impl Drop for CHost {
    fn drop(&mut self) {
        if let Some(release) = self.0.release {
            // SAFETY: the host handed `context` over with the callbacks; this is its last use.
            unsafe { release(self.0.context) }
        }
    }
}

impl PlatformHost for CHost {
    fn protect(&self, fd: i32) -> bool {
        // SAFETY: a callback of the registered host, called with its own context.
        unsafe { (self.0.protect)(self.0.context, fd) }
    }

    fn resolve_uid(&self, protocol: i32, source: &str, target: &str) -> i32 {
        let (Ok(source), Ok(target)) = (CString::new(source), CString::new(target)) else {
            return -1;
        };
        // SAFETY: as in `protect`; both strings outlive the call.
        unsafe { (self.0.resolve_uid)(self.0.context, protocol, source.as_ptr(), target.as_ptr()) }
    }

    fn resolve_package(&self, uid: i32) -> String {
        let mut buffer = vec![0u8; PACKAGE_CAPACITY];
        for _ in 0..2 {
            // SAFETY: as in `protect`; `buffer` holds `capacity` writable bytes.
            let length = unsafe {
                (self.0.resolve_package)(self.0.context, uid, buffer.as_mut_ptr(), buffer.len())
            };
            if length <= buffer.len() {
                buffer.truncate(length);
                return String::from_utf8(buffer).unwrap_or_default();
            }
            buffer.resize(length, 0);
        }
        String::new()
    }
}

struct Context(*mut c_void);

// SAFETY: `concord_start` requires a hook that may run on any thread with its context.
unsafe impl Send for Context {}
// SAFETY: as above; the pointer is only passed back.
unsafe impl Sync for Context {}

impl Context {
    fn get(&self) -> *mut c_void {
        self.0
    }
}

static CORE: OnceLock<Option<Core<CHost>>> = OnceLock::new();

/// Starts the core, once per process; later calls only report whether it runs. `on_thread_start`,
/// when set, runs with `context` on every runtime thread before that thread does any work, which is
/// where a JVM host attaches it. Returns 0 when the core runs, -1 when it could not start.
///
/// # Safety
/// `on_thread_start` must be safe to call from any thread with `context` for the life of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn concord_start(
    on_thread_start: Option<unsafe extern "C" fn(context: *mut c_void)>,
    context: *mut c_void,
) -> i32 {
    let hook = on_thread_start.map(|hook| {
        let context = Context(context);
        // SAFETY: forwarded from this function's contract.
        Arc::new(move || unsafe { hook(context.get()) }) as ThreadHook
    });
    let started = catch_unwind(AssertUnwindSafe(|| {
        CORE.get_or_init(move || start(hook)).is_some()
    }));
    if started.unwrap_or(false) { 0 } else { -1 }
}

fn start(hook: Option<ThreadHook>) -> Option<Core<CHost>> {
    std::panic::set_hook(Box::new(|info| logcat::error(&format!("panic: {info}"))));
    #[cfg(unix)]
    concord_platform::ignore_sigpipe();
    concord_platform::raise_fd_limit();
    match Core::new(hook) {
        Ok(core) => {
            let bus = core.control().bus();
            let bridge = LogBridge::new(bus.gate().clone(), bus.clone(), false);
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(bridge),
            );
            concord_ffi::set_notice(logcat::info);
            concord_ffi::install(core.hub().clone());
            Some(core)
        }
        Err(err) => {
            logcat::error(&format!("runtime: {err}"));
            None
        }
    }
}

/// Makes `host` the one the core asks for `protect` and connection owners, releasing the one before.
/// The struct is copied; null clears the host. Returns 0, or -1 when the core is not running, in
/// which case `host` is released right away.
///
/// # Safety
/// `host` is null or points to a valid `ConcordPlatformHost` whose callbacks are safe to call from any
/// thread with its context until `release` has run.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn concord_set_platform_host(host: *const ConcordPlatformHost) -> i32 {
    // SAFETY: forwarded from this function's contract.
    let host = unsafe { host.as_ref() }.map(|host| {
        Arc::new(CHost(ConcordPlatformHost {
            context: host.context,
            protect: host.protect,
            resolve_uid: host.resolve_uid,
            resolve_package: host.resolve_package,
            release: host.release,
        }))
    });
    let set = catch_unwind(AssertUnwindSafe(move || match CORE.get() {
        Some(Some(core)) => {
            core.set_platform_host(host);
            true
        }
        _ => false,
    }));
    if set.unwrap_or(false) { 0 } else { -1 }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    use concord_common::sync::lock;

    struct Answers {
        package: &'static str,
        protected: Mutex<Vec<i32>>,
        calls: Mutex<usize>,
        released: Mutex<bool>,
    }

    unsafe extern "C" fn protect(context: *mut c_void, fd: i32) -> bool {
        // SAFETY: `context` is the `Answers` the test hands to `host`, which outlives every call.
        let answers = unsafe { &*context.cast::<Answers>() };
        lock(&answers.protected).push(fd);
        fd != 8
    }

    unsafe extern "C" fn resolve_uid(
        _context: *mut c_void,
        protocol: i32,
        source: *const c_char,
        target: *const c_char,
    ) -> i32 {
        // SAFETY: the core passes NUL-terminated addresses that live for the call.
        let source = unsafe { std::ffi::CStr::from_ptr(source) }
            .to_str()
            .unwrap();
        // SAFETY: as above.
        let target = unsafe { std::ffi::CStr::from_ptr(target) }
            .to_str()
            .unwrap();
        if (protocol, source, target) == (6, "10.0.0.2:5000", "1.1.1.1:443") {
            10_123
        } else {
            -1
        }
    }

    unsafe extern "C" fn resolve_package(
        context: *mut c_void,
        _uid: i32,
        buffer: *mut u8,
        capacity: usize,
    ) -> usize {
        // SAFETY: `context` is the `Answers` the test hands to `host`, which outlives every call.
        let answers = unsafe { &*context.cast::<Answers>() };
        *lock(&answers.calls) += 1;
        let bytes = answers.package.as_bytes();
        if bytes.len() <= capacity {
            // SAFETY: the core's buffer holds `capacity` bytes, checked just above, and does
            // not overlap the test's string.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) };
        }
        bytes.len()
    }

    unsafe extern "C" fn release(context: *mut c_void) {
        // SAFETY: `context` is the `Answers` the test hands to `host`, which outlives every call.
        let answers = unsafe { &*context.cast::<Answers>() };
        *lock(&answers.released) = true;
    }

    fn host(answers: &Answers) -> CHost {
        CHost(ConcordPlatformHost {
            context: std::ptr::from_ref(answers).cast_mut().cast(),
            protect,
            resolve_uid,
            resolve_package,
            release: Some(release),
        })
    }

    fn answers(package: &'static str) -> Answers {
        Answers {
            package,
            protected: Mutex::new(Vec::new()),
            calls: Mutex::new(0),
            released: Mutex::new(false),
        }
    }

    #[test]
    fn the_callbacks_answer_for_the_platform_and_are_released_with_it() {
        let answers = answers("com.example.app");
        let host = host(&answers);

        assert!(host.protect(7));
        assert!(!host.protect(8));
        assert_eq!(host.resolve_uid(6, "10.0.0.2:5000", "1.1.1.1:443"), 10_123);
        assert_eq!(host.resolve_uid(6, "a\0b", "1.1.1.1:443"), -1);
        assert_eq!(host.resolve_package(10_123), "com.example.app");
        drop(host);

        assert_eq!(*lock(&answers.protected), [7, 8]);
        assert!(*lock(&answers.released));
    }

    #[test]
    fn a_package_longer_than_the_buffer_is_asked_for_again_once() {
        let long: &'static str = "p".repeat(PACKAGE_CAPACITY + 40).leak();
        let answers = answers(long);

        assert_eq!(host(&answers).resolve_package(1), long);
        assert_eq!(*lock(&answers.calls), 2);
    }
}
