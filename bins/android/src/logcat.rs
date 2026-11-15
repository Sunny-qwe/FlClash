use std::ffi::c_int;

const ANDROID_LOG_INFO: c_int = 4;
const ANDROID_LOG_ERROR: c_int = 6;

pub fn info(message: &str) {
    write(ANDROID_LOG_INFO, message);
}

pub fn error(message: &str) {
    write(ANDROID_LOG_ERROR, message);
}

#[cfg(target_os = "android")]
fn write(priority: c_int, message: &str) {
    use std::ffi::{CStr, CString, c_char};

    const TAG: &CStr = c"concord";

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(priority: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    let Ok(text) = CString::new(message.replace('\0', " ")) else {
        return;
    };
    // SAFETY: the tag and the text are NUL-terminated and outlive the call.
    unsafe {
        __android_log_write(priority, TAG.as_ptr(), text.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
fn write(_priority: c_int, message: &str) {
    eprintln!("{message}");
}
