#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(windows, test))]
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only parsed in tests off Windows")
)]
mod mib;
pub mod procnet;
#[cfg(windows)]
mod windows;

use std::net::SocketAddr;

use concord_common::{Network, ProcessInfo};

/// Blocking table scan, and `None` on Android where only the embedding app can answer.
pub fn find_owner_blocking(network: Network, src: SocketAddr) -> Option<ProcessInfo> {
    #[cfg(target_os = "macos")]
    return darwin::find(network, src);
    #[cfg(target_os = "linux")]
    return linux::find(network, src);
    #[cfg(windows)]
    return windows::find(network, src);
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = (network, src);
        None
    }
}
