//! The signed DLL is compiled in so the Helper's hash of the core covers it, and is loaded from where
//! only administrators can write: one beside a portable core is the user's to swap under an elevated core.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_arch = "x86_64")]
const DLL: &[u8] = include_bytes!("../../../assets/wintun/amd64/wintun.dll");
#[cfg(target_arch = "aarch64")]
const DLL: &[u8] = include_bytes!("../../../assets/wintun/arm64/wintun.dll");

#[cfg(target_arch = "x86_64")]
const FILE: &str = "wintun-0.14.1-amd64.dll";
#[cfg(target_arch = "aarch64")]
const FILE: &str = "wintun-0.14.1-arm64.dll";

pub(crate) fn install() -> io::Result<PathBuf> {
    let dir = program_files()?.join("Concord");
    let path = dir.join(FILE);
    if holds_dll(&path) {
        return Ok(path);
    }
    std::fs::create_dir_all(&dir)?;
    let staged = dir.join(format!("{FILE}.{}", std::process::id()));
    std::fs::write(&staged, DLL)?;
    if let Err(err) = std::fs::rename(&staged, &path) {
        let _ = std::fs::remove_file(&staged);
        if !holds_dll(&path) {
            return Err(err);
        }
    }
    Ok(path)
}

fn holds_dll(path: &Path) -> bool {
    std::fs::read(path).is_ok_and(|held| held == DLL)
}

/// `%ProgramFiles%` comes from the environment, which the unelevated user sets.
#[allow(unsafe_code, reason = "SHGetKnownFolderPath is a C API")]
fn program_files() -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };

    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: the folder id is a static GUID, the token is null for the current user, and `raw`
    // is a valid out-pointer the call fills with a CoTaskMem string or leaves null.
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramFiles,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut raw,
        )
    };
    let path = if result >= 0 && !raw.is_null() {
        // SAFETY: on success `raw` is a NUL-terminated wide string that stays allocated until
        // `CoTaskMemFree` below, so reading up to its NUL and borrowing that span is in bounds.
        let wide = unsafe {
            let len = (0..).take_while(|&at| *raw.add(at) != 0).count();
            std::slice::from_raw_parts(raw, len)
        };
        Ok(PathBuf::from(OsString::from_wide(wide)))
    } else {
        Err(io::Error::from_raw_os_error(result))
    };
    // SAFETY: `raw` is null or the string `SHGetKnownFolderPath` allocated, freed once, after
    // `wide` was copied into an owned path.
    unsafe { CoTaskMemFree(raw.cast()) };
    path
}
