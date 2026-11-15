//! What another process has used, read from outside it at nanosecond resolution.
//! Fields a platform cannot give stay `None`, so a report never shows a zero it
//! did not measure.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Usage {
    pub user_ns: u64,
    pub sys_ns: u64,
    pub instructions: Option<u64>,
    pub cycles: Option<u64>,
    /// Time threads were runnable but waited for a CPU: the contention signal.
    pub wait_ns: Option<u64>,
    pub context_switches: Option<u64>,
    pub syscalls: Option<u64>,
    pub io: Option<IoCounts>,
    pub mem: Memory,
}

/// `/proc/<pid>/io` on Linux: calls and bytes of the read and write families that pass through the VFS
/// (`read`, `readv`, `write`, `writev`, `sendfile`, ...). `recv*`, `send*` and `splice` on a socket do
/// not count, so compare only cores that use the same calls.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct IoCounts {
    pub read_calls: u64,
    pub write_calls: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

impl IoCounts {
    fn since(self, before: IoCounts) -> IoCounts {
        IoCounts {
            read_calls: self.read_calls.saturating_sub(before.read_calls),
            write_calls: self.write_calls.saturating_sub(before.write_calls),
            read_bytes: self.read_bytes.saturating_sub(before.read_bytes),
            write_bytes: self.write_bytes.saturating_sub(before.write_bytes),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Memory {
    /// Memory charged to the process: phys_footprint on Apple, PSS on Linux.
    pub footprint: u64,
    pub rss: u64,
    /// Highest footprint over the process's life (RSS high-water mark on Linux).
    pub peak: u64,
    pub threads: u64,
}

impl Usage {
    pub fn cpu_ns(&self) -> u64 {
        self.user_ns + self.sys_ns
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Delta {
    pub wall_ns: u64,
    pub user_ns: u64,
    pub sys_ns: u64,
    pub instructions: Option<u64>,
    pub cycles: Option<u64>,
    pub wait_ns: Option<u64>,
    pub context_switches: Option<u64>,
    pub syscalls: Option<u64>,
    pub io: Option<IoCounts>,
    #[serde(skip)]
    pub syscall_counts: Option<crate::syscalls::Counts>,
}

impl Delta {
    pub fn cpu_ns(&self) -> u64 {
        self.user_ns + self.sys_ns
    }

    pub fn cores(&self) -> f64 {
        self.cpu_ns() as f64 / self.wall_ns.max(1) as f64
    }
}

fn sub(after: Option<u64>, before: Option<u64>) -> Option<u64> {
    Some(after?.saturating_sub(before?))
}

pub struct Window {
    pid: u32,
    started: Instant,
    before: Usage,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    counters: Option<linux::perf::Counters>,
    syscalls: Option<crate::syscalls::Counters>,
}

impl Window {
    pub fn open(pid: u32) -> Window {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let counters = linux::perf::Counters::open(pid);
        Window {
            pid,
            started: Instant::now(),
            before: usage(pid).unwrap_or_default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            counters,
            syscalls: None,
        }
    }

    /// Also counts the process's system calls, when `--count-syscalls` is on.
    pub fn open_counting_syscalls(pid: u32) -> Window {
        let syscalls = crate::syscalls::enabled()
            .then(|| crate::syscalls::Counters::open(pid))
            .flatten();
        Window {
            syscalls,
            ..Window::open(pid)
        }
    }

    pub fn close(self) -> Delta {
        let after = usage(self.pid).unwrap_or_default();
        let wall_ns = self.started.elapsed().as_nanos() as u64;
        let mut delta = Delta {
            wall_ns,
            user_ns: after.user_ns.saturating_sub(self.before.user_ns),
            sys_ns: after.sys_ns.saturating_sub(self.before.sys_ns),
            instructions: sub(after.instructions, self.before.instructions),
            cycles: sub(after.cycles, self.before.cycles),
            wait_ns: sub(after.wait_ns, self.before.wait_ns),
            context_switches: sub(after.context_switches, self.before.context_switches),
            syscalls: sub(after.syscalls, self.before.syscalls),
            io: after.io.zip(self.before.io).map(|(a, b)| a.since(b)),
            syscall_counts: None,
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some((instructions, cycles)) = self.counters.and_then(|c| c.read()) {
            delta.instructions = Some(instructions);
            delta.cycles = Some(cycles);
        }
        if let Some(counters) = self.syscalls {
            let counts = counters.read();
            delta.syscalls = Some(counts.total);
            delta.syscall_counts = Some(counts);
        }
        delta
    }
}

pub struct Sampler {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Vec<(u64, Memory)>>,
}

impl Sampler {
    pub fn start(pid: u32, every: Duration) -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            let started = Instant::now();
            let mut points = Vec::new();
            while !flag.load(Ordering::Relaxed) {
                if let Some(mem) = memory(pid, false) {
                    points.push((started.elapsed().as_millis() as u64, mem));
                }
                std::thread::sleep(every);
            }
            points
        });
        Sampler { stop, handle }
    }

    pub fn finish(self) -> Vec<(u64, Memory)> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap_or_default()
    }
}

pub fn peak(points: &[(u64, Memory)]) -> Memory {
    points.iter().fold(Memory::default(), |acc, (_, m)| Memory {
        footprint: acc.footprint.max(m.footprint),
        rss: acc.rss.max(m.rss),
        peak: acc.peak.max(m.peak),
        threads: acc.threads.max(m.threads),
    })
}

pub const FOOTPRINT_KIND: &str = if cfg!(target_os = "macos") {
    "phys_footprint"
} else if cfg!(any(target_os = "linux", target_os = "android")) {
    "pss"
} else if cfg!(windows) {
    "private_working_set"
} else {
    "rss"
};

pub fn usage(pid: u32) -> Option<Usage> {
    imp::usage(pid)
}

/// `precise` asks for PSS on Linux, which walks every mapping; the sampler skips it.
pub fn memory(pid: u32, precise: bool) -> Option<Memory> {
    imp::memory(pid, precise)
}

pub fn open_fds(pid: u32) -> Option<u64> {
    imp::open_fds(pid)
}

#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(any(target_os = "linux", target_os = "android"))]
use linux as imp;

#[cfg(windows)]
use windows as imp;

#[cfg(not(any(
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    windows
)))]
mod imp {
    use super::{Memory, Usage};

    pub fn usage(_: u32) -> Option<Usage> {
        None
    }

    pub fn memory(_: u32, _: bool) -> Option<Memory> {
        None
    }

    pub fn open_fds(_: u32) -> Option<u64> {
        None
    }
}

#[cfg(target_os = "macos")]
#[allow(
    deprecated,
    reason = "libc deprecates its mach bindings in favour of the mach2 crate"
)]
#[allow(
    unsafe_code,
    reason = "proc_pid_rusage and proc_pidinfo fill zeroed caller-owned structs of the size passed"
)]
mod macos {
    use std::sync::OnceLock;

    use super::{Memory, Usage};

    fn timebase() -> (u64, u64) {
        static BASE: OnceLock<(u64, u64)> = OnceLock::new();
        *BASE.get_or_init(|| {
            let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
            let status = unsafe { libc::mach_timebase_info(&mut info) };
            if status != 0 || info.denom == 0 {
                (1, 1)
            } else {
                (u64::from(info.numer), u64::from(info.denom))
            }
        })
    }

    fn ns(ticks: u64) -> u64 {
        let (numer, denom) = timebase();
        (u128::from(ticks) * u128::from(numer) / u128::from(denom)) as u64
    }

    fn rusage(pid: u32) -> Option<libc::rusage_info_v4> {
        let mut info: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        let status = unsafe {
            libc::proc_pid_rusage(
                pid as i32,
                libc::RUSAGE_INFO_V4,
                (&raw mut info).cast::<libc::rusage_info_t>(),
            )
        };
        (status == 0).then_some(info)
    }

    fn task(pid: u32) -> Option<libc::proc_taskinfo> {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
        let written = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTASKINFO,
                0,
                (&raw mut info).cast(),
                size,
            )
        };
        (written == size).then_some(info)
    }

    pub fn usage(pid: u32) -> Option<Usage> {
        let info = rusage(pid)?;
        let task = task(pid);
        Some(Usage {
            user_ns: ns(info.ri_user_time),
            sys_ns: ns(info.ri_system_time),
            instructions: Some(info.ri_instructions).filter(|v| *v > 0),
            cycles: Some(info.ri_cycles).filter(|v| *v > 0),
            wait_ns: Some(ns(info.ri_runnable_time)),
            context_switches: task.map(|t| t.pti_csw as u64),
            syscalls: task.map(|t| t.pti_syscalls_unix as u64 + t.pti_syscalls_mach as u64),
            io: None,
            mem: Memory {
                footprint: info.ri_phys_footprint,
                rss: info.ri_resident_size,
                peak: info.ri_lifetime_max_phys_footprint,
                threads: task.map_or(0, |t| t.pti_threadnum as u64),
            },
        })
    }

    pub fn memory(pid: u32, _precise: bool) -> Option<Memory> {
        usage(pid).map(|u| u.mem)
    }

    pub fn open_fds(pid: u32) -> Option<u64> {
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        (bytes > 0).then(|| bytes as u64 / std::mem::size_of::<libc::proc_fdinfo>() as u64)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(
    unsafe_code,
    reason = "the process CPU clock and perf_event_open have no safe wrapper; every pointer passed is a live local"
)]
mod linux {
    use super::{Memory, Usage};

    fn process_cpu_ns(pid: u32) -> Option<u64> {
        let mut clock: libc::clockid_t = 0;
        if unsafe { libc::clock_getcpuclockid(pid as libc::pid_t, &mut clock) } != 0 {
            return None;
        }
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(clock, &mut now) } != 0 {
            return None;
        }
        Some(now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64)
    }

    fn ticks_per_second() -> u64 {
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks > 0 { ticks as u64 } else { 100 }
    }

    fn stat_fields(pid: u32) -> Option<Vec<u64>> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The command name may hold spaces and parentheses; fields resume after the last `)`.
        let (_, rest) = stat.rsplit_once(')')?;
        Some(
            rest.split_whitespace()
                .map(|f| f.parse().unwrap_or(0))
                .collect(),
        )
    }

    fn tasks(pid: u32) -> Vec<String> {
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|dir| {
                dir.filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn kib(text: &str, key: &str) -> Option<u64> {
        text.lines()
            .find_map(|line| line.strip_prefix(key))?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
            .map(|v| v * 1024)
    }

    pub fn usage(pid: u32) -> Option<Usage> {
        let fields = stat_fields(pid)?;
        let (utime, stime) = (fields.get(11).copied()?, fields.get(12).copied()?);
        // utime and stime are clock ticks and only split the precise total; when the
        // CPU clock of another user's process is refused they are all there is.
        let total = process_cpu_ns(pid)
            .unwrap_or_else(|| (utime + stime) * 1_000_000_000 / ticks_per_second());
        let user_ns = if utime + stime == 0 {
            total
        } else {
            (u128::from(total) * u128::from(utime) / u128::from(utime + stime)) as u64
        };
        let mut wait = 0u64;
        let mut switches = 0u64;
        for tid in tasks(pid) {
            if let Ok(schedstat) =
                std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/schedstat"))
            {
                wait += schedstat
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
            }
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status")) {
                for key in ["voluntary_ctxt_switches:", "nonvoluntary_ctxt_switches:"] {
                    switches += status
                        .lines()
                        .find_map(|l| l.strip_prefix(key))
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .unwrap_or(0);
                }
            }
        }
        Some(Usage {
            user_ns,
            sys_ns: total - user_ns,
            instructions: None,
            cycles: None,
            wait_ns: Some(wait),
            context_switches: Some(switches),
            syscalls: None,
            io: io(pid),
            mem: memory(pid, false)?,
        })
    }

    fn io(pid: u32) -> Option<super::IoCounts> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
        let field = |key: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        Some(super::IoCounts {
            read_calls: field("syscr:")?,
            write_calls: field("syscw:")?,
            read_bytes: field("rchar:")?,
            write_bytes: field("wchar:")?,
        })
    }

    pub fn memory(pid: u32, precise: bool) -> Option<Memory> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let rss = kib(&status, "VmRSS:")?;
        let threads = status
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let footprint = if precise {
            std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
                .ok()
                .and_then(|text| kib(&text, "Pss:"))
                .unwrap_or(rss)
        } else {
            rss
        };
        Some(Memory {
            footprint,
            rss,
            peak: kib(&status, "VmHWM:").unwrap_or(rss),
            threads,
        })
    }

    pub fn open_fds(pid: u32) -> Option<u64> {
        Some(std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?.count() as u64)
    }

    pub mod perf {
        //! Counts only threads alive when a window opens; the core's workers are
        //! all up before the first window.

        use std::os::fd::{FromRawFd, OwnedFd};

        const PERF_TYPE_HARDWARE: u32 = 0;
        const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
        const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
        const EXCLUDE_KERNEL: u64 = 1 << 5;
        const EXCLUDE_HV: u64 = 1 << 6;
        const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;

        #[repr(C)]
        struct Attr {
            kind: u32,
            size: u32,
            config: u64,
            sample_period: u64,
            sample_type: u64,
            read_format: u64,
            flags: u64,
            wakeup_events: u32,
            bp_type: u32,
            bp_addr: u64,
        }

        pub struct Counters {
            fds: Vec<(OwnedFd, OwnedFd)>,
        }

        fn open(tid: i32, config: u64, flags: u64) -> Option<OwnedFd> {
            let attr = Attr {
                kind: PERF_TYPE_HARDWARE,
                size: std::mem::size_of::<Attr>() as u32,
                config,
                sample_period: 0,
                sample_type: 0,
                read_format: 0,
                flags,
                wakeup_events: 0,
                bp_type: 0,
                bp_addr: 0,
            };
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    &raw const attr,
                    tid,
                    -1i32,
                    -1i32,
                    PERF_FLAG_FD_CLOEXEC,
                )
            };
            (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
        }

        fn read(fd: OwnedFd) -> u64 {
            use std::io::Read;
            let mut bytes = [0u8; 8];
            match std::fs::File::from(fd).read_exact(&mut bytes) {
                Ok(()) => u64::from_ne_bytes(bytes),
                Err(_) => 0,
            }
        }

        impl Counters {
            /// Falls back to user time alone when `perf_event_paranoid` forbids kernel counting.
            pub fn open(pid: u32) -> Option<Counters> {
                let tids: Vec<i32> = super::tasks(pid)
                    .iter()
                    .filter_map(|t| t.parse().ok())
                    .collect();
                for flags in [EXCLUDE_HV, EXCLUDE_HV | EXCLUDE_KERNEL] {
                    let fds: Option<Vec<_>> = tids
                        .iter()
                        .map(|&tid| {
                            Some((
                                open(tid, PERF_COUNT_HW_INSTRUCTIONS, flags)?,
                                open(tid, PERF_COUNT_HW_CPU_CYCLES, flags)?,
                            ))
                        })
                        .collect();
                    if let Some(fds) = fds.filter(|f| !f.is_empty()) {
                        return Some(Counters { fds });
                    }
                }
                None
            }

            pub fn read(self) -> Option<(u64, u64)> {
                let mut totals = (0, 0);
                for (instructions, cycles) in self.fds {
                    totals.0 += read(instructions);
                    totals.1 += read(cycles);
                }
                (totals.1 > 0).then_some(totals)
            }
        }
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "the Win32 process queries fill caller-owned structs through a handle closed on drop"
)]
mod windows {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX2,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessHandleCount, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::System::WindowsProgramming::QueryProcessCycleTime;

    use super::{Memory, Usage};

    struct Process(HANDLE);

    impl Process {
        fn open(pid: u32) -> Option<Process> {
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            (!handle.is_null()).then_some(Process(handle))
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn hundred_ns(time: FILETIME) -> u64 {
        ((u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)) * 100
    }

    pub fn usage(pid: u32) -> Option<Usage> {
        let process = Process::open(pid)?;
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        if unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return None;
        }
        let mut cycles = 0u64;
        let cycles = (unsafe { QueryProcessCycleTime(process.0, &mut cycles) } != 0 && cycles > 0)
            .then_some(cycles);
        Some(Usage {
            user_ns: hundred_ns(user),
            sys_ns: hundred_ns(kernel),
            instructions: None,
            cycles,
            wait_ns: None,
            context_switches: None,
            syscalls: None,
            io: None,
            mem: counters(&process, false).unwrap_or_default(),
        })
    }

    fn counters(process: &Process, threads: bool) -> Option<Memory> {
        let mut info: PROCESS_MEMORY_COUNTERS_EX2 = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX2>() as u32;
        info.cb = size;
        if unsafe {
            GetProcessMemoryInfo(
                process.0,
                (&raw mut info).cast::<PROCESS_MEMORY_COUNTERS>(),
                size,
            )
        } == 0
        {
            return None;
        }
        Some(Memory {
            footprint: info.PrivateWorkingSetSize as u64,
            rss: info.WorkingSetSize as u64,
            peak: info.PeakWorkingSetSize as u64,
            threads: if threads {
                thread_count(process_id(process))
            } else {
                0
            },
        })
    }

    fn process_id(process: &Process) -> u32 {
        unsafe { windows_sys::Win32::System::Threading::GetProcessId(process.0) }
    }

    /// Walks every thread on the system, so only the settled readings ask for it.
    fn thread_count(pid: u32) -> u64 {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot.is_null() || snapshot as isize == -1 {
            return 0;
        }
        let snapshot = Process(snapshot);
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut count = 0;
        let mut more = unsafe { Thread32First(snapshot.0, &mut entry) } != 0;
        while more {
            if entry.th32OwnerProcessID == pid {
                count += 1;
            }
            more = unsafe { Thread32Next(snapshot.0, &mut entry) } != 0;
        }
        count
    }

    pub fn memory(pid: u32, precise: bool) -> Option<Memory> {
        counters(&Process::open(pid)?, precise)
    }

    pub fn open_fds(pid: u32) -> Option<u64> {
        let process = Process::open(pid)?;
        let mut count = 0u32;
        (unsafe { GetProcessHandleCount(process.0, &mut count) } != 0).then_some(u64::from(count))
    }
}
