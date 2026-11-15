use std::ffi::c_void;

use crate::hub::Receiver;

pub type Deliver = unsafe extern "C" fn(context: *mut c_void, data: *const u8, len: usize) -> bool;
pub type Release = unsafe extern "C" fn(context: *mut c_void);

/// A session receiver made of a host's C callbacks. `release` runs once, when the session is dropped.
pub(crate) struct Callback {
    deliver: Deliver,
    release: Option<Release>,
    context: *mut c_void,
}

// SAFETY: `concord_open_callback` requires callbacks that may run on any thread.
unsafe impl Send for Callback {}

impl Callback {
    pub(crate) fn new(deliver: Deliver, context: *mut c_void, release: Option<Release>) -> Self {
        Callback {
            deliver,
            release,
            context,
        }
    }
}

impl Receiver for Callback {
    fn deliver(&mut self, message: Vec<u8>) -> bool {
        // SAFETY: the bytes stay valid for the call, which is all the contract promises.
        unsafe { (self.deliver)(self.context, message.as_ptr(), message.len()) }
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            // SAFETY: the host handed `context` over with the callbacks; this is its last use.
            unsafe { release(self.context) }
        }
    }
}
