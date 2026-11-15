use std::ffi::{CStr, c_char, c_int, c_void};
use std::sync::OnceLock;

use crate::hub::Receiver;

const API_MAJOR: c_int = 2;
const TYPED_DATA: c_int = 7;
const EXTERNAL_TYPED_DATA: c_int = 8;
const UINT8: c_int = 2;
/// Below this a message is copied into the Dart heap; above it the buffer is handed over instead.
const EXTERNAL_FROM: usize = 16 * 1024;

#[repr(C)]
struct ApiTable {
    major: c_int,
    minor: c_int,
    entries: *const Entry,
}

#[repr(C)]
struct Entry {
    name: *const c_char,
    function: *const c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Typed {
    kind: c_int,
    length: isize,
    values: *const u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct External {
    kind: c_int,
    length: isize,
    data: *mut u8,
    peer: *mut c_void,
    finalizer: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
}

#[repr(C)]
union Payload {
    typed: Typed,
    external: External,
}

#[repr(C)]
struct CObject {
    kind: c_int,
    payload: Payload,
}

type PostCObject = unsafe extern "C" fn(i64, *mut CObject) -> bool;

static POST: OnceLock<PostCObject> = OnceLock::new();

/// `Dart_InitializeApiDL` for the one function used. `data` is `NativeApi.initializeApiDLData`.
///
/// # Safety
/// `data` must point to the table the Dart VM provides, or be null.
pub(crate) unsafe fn initialize(data: *const c_void) -> bool {
    if data.is_null() {
        return false;
    }
    // SAFETY: the table and its entries outlive the process, per the Dart embedder API.
    let table = unsafe { &*data.cast::<ApiTable>() };
    if table.major != API_MAJOR {
        return false;
    }
    let mut entry = table.entries;
    loop {
        // SAFETY: the entry list ends with an entry whose name is null.
        let current = unsafe { &*entry };
        if current.name.is_null() {
            return false;
        }
        // SAFETY: a non-null name is a NUL-terminated string.
        if unsafe { CStr::from_ptr(current.name) } == c"Dart_PostCObject" {
            // SAFETY: the VM registers this name with the signature of `PostCObject`.
            let post =
                unsafe { std::mem::transmute::<*const c_void, PostCObject>(current.function) };
            let _ = POST.set(post);
            return true;
        }
        // SAFETY: the entry just read was not the terminator.
        entry = unsafe { entry.add(1) };
    }
}

/// Posts each message to a `ReceivePort`; a port that no longer exists ends the session.
pub(crate) struct DartPort(pub i64);

unsafe extern "C" fn release_buffer(_callback_data: *mut c_void, peer: *mut c_void) {
    // SAFETY: `peer` is the box `post_external` leaked, and the VM runs this once.
    drop(unsafe { Box::from_raw(peer.cast::<Vec<u8>>()) });
}

impl DartPort {
    fn post_copy(&self, post: PostCObject, message: &[u8]) -> bool {
        let mut object = CObject {
            kind: TYPED_DATA,
            payload: Payload {
                typed: Typed {
                    kind: UINT8,
                    length: message.len() as isize,
                    values: message.as_ptr(),
                },
            },
        };
        // SAFETY: the object describes `message`, which outlives the call; the VM copies it.
        unsafe { post(self.0, &mut object) }
    }

    fn post_external(&self, post: PostCObject, message: Vec<u8>) -> bool {
        let owner = Box::into_raw(Box::new(message));
        // SAFETY: `owner` was just made from a live box.
        let (data, length) = unsafe { ((*owner).as_mut_ptr(), (*owner).len()) };
        let mut object = CObject {
            kind: EXTERNAL_TYPED_DATA,
            payload: Payload {
                external: External {
                    kind: UINT8,
                    length: length as isize,
                    data,
                    peer: owner.cast(),
                    finalizer: Some(release_buffer),
                },
            },
        };
        // SAFETY: the VM owns the buffer once it accepts the message and calls `release_buffer`;
        // when it refuses, the buffer is still ours.
        let posted = unsafe { post(self.0, &mut object) };
        if !posted {
            // SAFETY: the VM refused the message, so nothing else holds `owner`.
            drop(unsafe { Box::from_raw(owner) });
        }
        posted
    }
}

impl Receiver for DartPort {
    fn deliver(&mut self, message: Vec<u8>) -> bool {
        let Some(&post) = POST.get() else {
            return false;
        };
        if message.len() < EXTERNAL_FROM {
            self.post_copy(post, &message)
        } else {
            self.post_external(post, message)
        }
    }
}

pub(crate) fn is_initialized() -> bool {
    POST.get().is_some()
}
