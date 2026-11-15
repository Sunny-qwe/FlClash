use std::io;
use std::num::NonZeroUsize;

/// The CPUs this process may run on. `std::thread::available_parallelism` honours the affinity
/// mask on Linux but not on Windows, where a core limited by `start /affinity`, a job object or a
/// launcher that pins it would otherwise start a worker for every CPU of the machine.
pub fn available_cpus() -> io::Result<NonZeroUsize> {
    #[cfg(windows)]
    if let Some(count) = affinity_count() {
        return Ok(count);
    }
    std::thread::available_parallelism()
}

#[cfg(windows)]
fn affinity_count() -> Option<NonZeroUsize> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessAffinityMask};

    let mut process = 0usize;
    let mut system = 0usize;
    // SAFETY: the current-process pseudo handle needs no closing, and both pointers are valid.
    let ok = unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process, &mut system) };
    // A process whose threads span processor groups gets zero masks: one mask cannot describe it.
    if ok == 0 {
        return None;
    }
    NonZeroUsize::new(process.count_ones() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_at_least_one_cpu_and_no_more_than_the_machine() {
        let usable = available_cpus().unwrap().get();
        let machine = std::thread::available_parallelism().unwrap().get();
        assert!((1..=machine.max(64)).contains(&usable));
    }
}
