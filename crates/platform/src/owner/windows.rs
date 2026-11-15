use std::net::SocketAddr;
use std::path::Path;

use concord_common::{Network, ProcessInfo};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_CONNECTIONS, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use super::mib::{Table, find_pid};

const SYSTEM_IDLE_PID: u32 = 0;
const SYSTEM_PID: u32 = 4;
const MAX_LONG_PATH: usize = 32_768;

fn read_table(network: Network, v6: bool) -> Option<Vec<u8>> {
    let family = u32::from(if v6 { AF_INET6 } else { AF_INET });
    let mut size = 8u32;
    for _ in 0..8 {
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` is writable for `size` bytes, which the call enlarges on failure.
        let rc = unsafe {
            let out = buf.as_mut_ptr().cast();
            match network {
                Network::Tcp => GetExtendedTcpTable(
                    out,
                    &mut size,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_CONNECTIONS,
                    0,
                ),
                Network::Udp => {
                    GetExtendedUdpTable(out, &mut size, 0, family, UDP_TABLE_OWNER_PID, 0)
                }
            }
        };
        match rc {
            NO_ERROR => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            _ => return None,
        }
    }
    None
}

fn image_path(pid: u32) -> Option<String> {
    match pid {
        SYSTEM_IDLE_PID => return Some(":System Idle Process".to_string()),
        SYSTEM_PID => return Some(":System".to_string()),
        _ => {}
    }
    let mut buf = vec![0u16; MAX_LONG_PATH];
    let mut size = buf.len() as u32;
    // SAFETY: the handle is closed before returning and `buf` holds `size` code units.
    let ok = unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return None;
        }
        let ok = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(process);
        ok
    };
    (ok != 0).then(|| String::from_utf16_lossy(buf.get(..size as usize).unwrap_or_default()))
}

pub fn find(network: Network, src: SocketAddr) -> Option<ProcessInfo> {
    let v6 = src.is_ipv6();
    let table = match (network, v6) {
        (Network::Tcp, false) => Table::Tcp4,
        (Network::Tcp, true) => Table::Tcp6,
        (Network::Udp, false) => Table::Udp4,
        (Network::Udp, true) => Table::Udp6,
    };
    let pid = find_pid(table, &read_table(network, v6)?, src.ip(), src.port())?;
    let path = image_path(pid)?;
    let name = Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    Some(ProcessInfo {
        uid: None,
        name,
        path,
    })
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;

    use super::*;

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the test binds a loopback socket directly"
    )]
    fn this_process_owns_its_udp_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let info = find(Network::Udp, socket.local_addr().unwrap()).unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(Path::new(&info.path).file_name(), exe.file_name());
    }
}
