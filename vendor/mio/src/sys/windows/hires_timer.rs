//! Concord: a high-resolution waitable timer that ends a timed wait on the completion port, as Go's runtime
//! does in `runtime/netpoll_windows.go`. `GetQueuedCompletionStatusEx` ends its own timeout on the system
//! tick, so a 1 ms wait otherwise lasts up to a tick.

use std::cell::Cell;
use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_ALL, HANDLE, NTSTATUS, STATUS_CANCELLED, STATUS_SUCCESS,
};
use windows_sys::Win32::System::Threading::{
    CreateWaitableTimerExW, SetWaitableTimer, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
    TIMER_ALL_ACCESS,
};
use windows_sys::Win32::System::IO::OVERLAPPED_ENTRY;

use super::iocp::{CompletionPort, CompletionStatus};
use super::{Event, Overlapped};

windows_link::link!("ntdll.dll" "system" fn NtCreateWaitCompletionPacket(
    handle: *mut HANDLE,
    access: u32,
    attributes: *const c_void,
) -> NTSTATUS);
windows_link::link!("ntdll.dll" "system" fn NtAssociateWaitCompletionPacket(
    packet: HANDLE,
    port: HANDLE,
    target: HANDLE,
    key: *const c_void,
    apc: *const c_void,
    status: NTSTATUS,
    information: usize,
    already_signaled: *mut u8,
) -> NTSTATUS);
windows_link::link!("ntdll.dll" "system" fn NtCancelWaitCompletionPacket(
    packet: HANDLE,
    remove_signaled: u8,
) -> NTSTATUS);

/// Odd, so `feed_events` hands the packet to `Overlapped::callback` instead of reading it as a socket state;
/// the callback adds no event, so the packet only ends the wait and its key never reaches the caller.
const TIMER_KEY: usize = 1;

/// tokio rounds its deadlines to whole milliseconds, so successive waits for the same timer ask for deadlines
/// less than this apart; such a wait keeps the armed timer instead of paying three calls to re-arm it.
const REUSE: Duration = Duration::from_millis(1);

#[derive(Debug)]
pub(super) struct HiResTimer {
    timer: HANDLE,
    packet: HANDLE,
    overlapped: Box<Overlapped>,
    armed: Cell<Option<Instant>>,
}

// SAFETY: the handles are kernel objects usable from any thread; `arm`, `disarm` and `observe` (and so `armed`)
// run only from `SelectorInner::select2`, which one thread at a time enters.
unsafe impl Send for HiResTimer {}
unsafe impl Sync for HiResTimer {}

impl HiResTimer {
    /// `None` before Windows 10 1803, which lacks `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION`; waits then keep the
    /// tick, and nothing falls back to raising the system timer resolution.
    pub(super) fn new() -> Option<HiResTimer> {
        let timer = unsafe {
            CreateWaitableTimerExW(
                null(),
                null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            )
        };
        if timer.is_null() {
            return None;
        }
        let mut packet = null_mut();
        if unsafe { NtCreateWaitCompletionPacket(&mut packet, GENERIC_ALL, null()) }
            != STATUS_SUCCESS
        {
            unsafe { CloseHandle(timer) };
            return None;
        }
        Some(HiResTimer {
            timer,
            packet,
            overlapped: Box::new(Overlapped::new(no_event)),
            armed: Cell::new(None),
        })
    }

    /// Queues the timer's packet on `port` after `timeout`. Returns `true` when it expired before it was
    /// associated, so the wait must not block.
    pub(super) fn arm(&self, port: &CompletionPort, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        if let Some(armed) = self.armed.get() {
            if armed <= deadline && deadline - armed < REUSE {
                return false;
            }
        }
        if !self.disarm() {
            return false;
        }
        let due = -i64::try_from(timeout.as_nanos() / 100)
            .unwrap_or(i64::MAX)
            .max(1);
        if unsafe { SetWaitableTimer(self.timer, &due, 0, None, null(), 0) } == 0 {
            return false;
        }
        let mut signaled = 0u8;
        let status = unsafe {
            NtAssociateWaitCompletionPacket(
                self.packet,
                port.as_raw_handle() as HANDLE,
                self.timer,
                TIMER_KEY as *const c_void,
                self.overlapped.as_ptr().cast(),
                STATUS_SUCCESS,
                0,
                &mut signaled,
            )
        };
        if status != STATUS_SUCCESS {
            return false;
        }
        if signaled != 0 {
            return true;
        }
        self.armed.set(Some(deadline));
        false
    }

    /// Cancels the association and drops a packet already queued for it. `false` when the packet is being
    /// delivered (`STATUS_PENDING`) and cannot be cancelled; that wait then keeps only its own timeout.
    pub(super) fn disarm(&self) -> bool {
        if self.armed.take().is_none() {
            return true;
        }
        self.cancel()
    }

    /// Forgets the armed deadline once the timer's packet has left the port.
    pub(super) fn observe(&self, statuses: &[CompletionStatus]) {
        let ours = self.overlapped.as_ptr();
        if self.armed.get().is_some()
            && statuses.iter().any(|s| s.overlapped().cast_const() == ours)
        {
            self.armed.set(None);
        }
    }

    fn cancel(&self) -> bool {
        matches!(
            unsafe { NtCancelWaitCompletionPacket(self.packet, 1) },
            STATUS_SUCCESS | STATUS_CANCELLED
        )
    }
}

impl Drop for HiResTimer {
    fn drop(&mut self) {
        self.cancel();
        unsafe {
            CloseHandle(self.packet);
            CloseHandle(self.timer);
        }
    }
}

fn no_event(_: &OVERLAPPED_ENTRY, _: Option<&mut Vec<Event>>) {}
