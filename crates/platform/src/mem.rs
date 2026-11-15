#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_vm_rss(status: &str) -> Option<u64> {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().next()?.parse().ok()?;
    Some(kib * 1024)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn resident_memory() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| parse_vm_rss(&status))
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
pub fn resident_memory() -> u64 {
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: all-zero is a valid `proc_taskinfo`, and the kernel fills at most `size` bytes.
    unsafe {
        let mut info: libc::proc_taskinfo = std::mem::zeroed();
        let pid = std::process::id() as libc::c_int;
        let out = std::ptr::from_mut(&mut info).cast();
        let written = libc::proc_pidinfo(pid, libc::PROC_PIDTASKINFO, 0, out, size);
        if written == size {
            info.pti_resident_size
        } else {
            0
        }
    }
}

#[cfg(windows)]
pub fn resident_memory() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{
        K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: all-zero is a valid counters struct and `cb` carries its real size.
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let ok = K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb);
        if ok != 0 {
            counters.WorkingSetSize as u64
        } else {
            0
        }
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
pub fn resident_memory() -> u64 {
    0
}

pub fn release_free_memory() {
    #[cfg(target_vendor = "apple")]
    {
        unsafe extern "C" {
            fn malloc_zone_pressure_relief(
                zone: *mut libc::c_void,
                goal: libc::size_t,
            ) -> libc::size_t;
        }
        // SAFETY: a null zone stands for all of them, and a goal of 0 for all they can return.
        unsafe {
            malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
        }
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `malloc_trim` takes no pointers.
    unsafe {
        libc::malloc_trim(0);
    }
    #[cfg(target_os = "android")]
    {
        // The libc stub of API 24 and 25 has no `mallopt`, and a direct reference would fail to load there.
        type Mallopt = unsafe extern "C" fn(libc::c_int, libc::c_int) -> libc::c_int;
        const M_PURGE: libc::c_int = -101;
        // SAFETY: `dlsym` is given a NUL-terminated name; `mallopt` takes plain integers.
        unsafe {
            let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"mallopt".as_ptr());
            if !symbol.is_null() {
                std::mem::transmute::<*mut libc::c_void, Mallopt>(symbol)(M_PURGE, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_is_read_from_the_status_file() {
        let status = "Name:\tcore\nVmPeak:\t 200 kB\nVmRSS:\t   1234 kB\nThreads:\t4\n";
        assert_eq!(parse_vm_rss(status), Some(1234 * 1024));
        assert_eq!(parse_vm_rss("Name:\tcore\n"), None);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn the_running_test_has_resident_memory() {
        assert!(resident_memory() > 1024 * 1024);
        release_free_memory();
    }
}
