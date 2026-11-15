use std::net::{IpAddr, SocketAddr};

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetIpForwardTable2, GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, SOCKET_ADDRESS};

use super::select::{Candidate, Subnet, pick};
use super::sockaddr::sockaddr_from_bytes;
use crate::InterfaceInfo;

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

pub struct Adapter {
    pub info: InterfaceInfo,
    pub prefixes: Vec<u8>,
    pub up: bool,
    pub has_gateway: bool,
    pub dns: Vec<SocketAddr>,
}

unsafe fn address_of(address: &SOCKET_ADDRESS) -> Option<SocketAddr> {
    let len = usize::try_from(address.iSockaddrLength).ok()?;
    if address.lpSockaddr.is_null() {
        return None;
    }
    // SAFETY: the OS reports `len` readable bytes at `lpSockaddr`.
    let bytes = unsafe { std::slice::from_raw_parts(address.lpSockaddr.cast::<u8>(), len) };
    sockaddr_from_bytes(bytes)
}

unsafe fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: the string is NUL-terminated, so reads stop at the terminator.
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

fn is_site_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.octets().starts_with(&[0xfe, 0xc0]))
}

pub fn adapters() -> Vec<Adapter> {
    read_adapters(false)
}

pub fn subnets(adapters: &[Adapter]) -> Vec<Subnet> {
    adapters
        .iter()
        .filter(|adapter| adapter.up)
        .flat_map(|adapter| {
            adapter
                .info
                .addrs
                .iter()
                .zip(&adapter.prefixes)
                .map(|(addr, prefix)| Subnet {
                    name: adapter.info.name.to_string(),
                    addr: *addr,
                    prefix: *prefix,
                })
        })
        .collect()
}

pub fn local_addrs() -> Vec<IpAddr> {
    read_adapters(true)
        .into_iter()
        .flat_map(|adapter| adapter.info.addrs)
        .collect()
}

fn read_adapters(with_loopback: bool) -> Vec<Adapter> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 15_000u32;
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut adapters = Vec::new();
        // SAFETY: `buf` is 8-aligned and writable for `size` bytes; the lists it receives
        // are read only while `buf` lives, and every node pointer is null-checked.
        unsafe {
            let rc = GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                head,
                &mut size,
            );
            if rc == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if rc != NO_ERROR {
                return Vec::new();
            }
            let mut current = head.as_ref();
            while let Some(adapter) = current {
                current = adapter.Next.as_ref();
                if !with_loopback && adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                    continue;
                }
                let (mut addrs, mut prefixes) = (Vec::new(), Vec::new());
                let mut unicast = adapter.FirstUnicastAddress.as_ref();
                while let Some(node) = unicast {
                    if let Some(addr) = address_of(&node.Address) {
                        addrs.push(addr.ip());
                        prefixes.push(node.OnLinkPrefixLength);
                    }
                    unicast = node.Next.as_ref();
                }
                let mut dns: Vec<SocketAddr> = Vec::new();
                let mut server = adapter.FirstDnsServerAddress.as_ref();
                while let Some(node) = server {
                    if let Some(addr) = address_of(&node.Address) {
                        let known = dns.iter().any(|seen| seen.ip() == addr.ip());
                        if !known && !is_site_local(addr.ip()) {
                            dns.push(match addr {
                                SocketAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(
                                    *v6.ip(),
                                    53,
                                    0,
                                    v6.scope_id(),
                                )),
                                SocketAddr::V4(_) => SocketAddr::new(addr.ip(), 53),
                            });
                        }
                    }
                    server = node.Next.as_ref();
                }
                adapters.push(Adapter {
                    info: InterfaceInfo {
                        name: wide_to_string(adapter.FriendlyName).into(),
                        index: adapter.Anonymous1.Anonymous.IfIndex,
                        addrs,
                    },
                    prefixes,
                    up: adapter.OperStatus == IfOperStatusUp,
                    has_gateway: !adapter.FirstGatewayAddress.is_null(),
                    dns,
                });
            }
        }
        return adapters;
    }
    Vec::new()
}

pub fn system_dns() -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    for adapter in adapters().into_iter().filter(|a| a.up && a.has_gateway) {
        for server in adapter.dns {
            if !servers.iter().any(|known| known.ip() == server.ip()) {
                servers.push(server);
            }
        }
    }
    servers
}

fn interface_metric(family: u16, index: u32) -> u32 {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceIndex: index,
        ..Default::default()
    };
    // SAFETY: `row` is zeroed with the key fields the call reads filled in.
    let rc = unsafe { GetIpInterfaceEntry(&mut row) };
    if rc == NO_ERROR { row.Metric } else { 0 }
}

pub fn default_interface(excluded: &[String]) -> Option<InterfaceInfo> {
    let adapters = adapters();
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let mut candidates = Vec::new();
    // SAFETY: `table` receives `NumEntries` valid rows that stay readable until `FreeMibTable`.
    unsafe {
        if GetIpForwardTable2(AF_UNSPEC, &mut table) != NO_ERROR || table.is_null() {
            return None;
        }
        let count = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
        for row in rows
            .iter()
            .filter(|row| row.DestinationPrefix.PrefixLength == 0)
        {
            let found = adapters
                .iter()
                .find(|a| a.up && a.info.index == row.InterfaceIndex);
            if let Some(adapter) = found {
                let family = row.DestinationPrefix.Prefix.si_family;
                candidates.push(Candidate {
                    name: adapter.info.name.to_string(),
                    metric: row
                        .Metric
                        .saturating_add(interface_metric(family, row.InterfaceIndex)),
                    scoped: false,
                });
            }
        }
        FreeMibTable(table.cast());
    }
    let chosen = pick(&candidates, excluded)?;
    adapters
        .into_iter()
        .map(|a| a.info)
        .find(|info| info.name.as_ref() == chosen.name)
}
