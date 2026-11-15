//! Locking that outlives a panic. A panic ends one connection's task, not the process
//! (`panic = "unwind"`), so a lock it poisoned still guards state the other tasks keep using.
#![allow(
    clippy::disallowed_methods,
    reason = "the one place that takes a std lock directly"
)]

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Locks `mutex`, taking the guard back if a panicking holder poisoned it.
pub fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read-locks `rwlock`, taking the guard back if a panicking writer poisoned it.
pub fn read<T: ?Sized>(rwlock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    rwlock.read().unwrap_or_else(PoisonError::into_inner)
}

/// Write-locks `rwlock`, taking the guard back if a panicking writer poisoned it.
pub fn write<T: ?Sized>(rwlock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    rwlock.write().unwrap_or_else(PoisonError::into_inner)
}
