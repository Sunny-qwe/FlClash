use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::InterfaceInfo;

pub fn index_of(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: `name` is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

#[cfg(any(target_os = "macos", test))]
pub fn name_of(index: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` holds IF_NAMESIZE bytes, the most written, and success NUL-terminates it.
    unsafe {
        let found = libc::if_indextoname(index, buf.as_mut_ptr());
        if found.is_null() {
            return None;
        }
        CStr::from_ptr(found).to_str().ok().map(str::to_owned)
    }
}

pub fn addrs_of(name: &str) -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    walk(|found, _, addr, _| {
        if found.to_bytes() == name.as_bytes() {
            addrs.push(addr);
        }
    });
    addrs
}

unsafe fn ip_of(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: callers pass null or a socket address of the family it names.
    unsafe {
        match i32::from((*sa).sa_family) {
            libc::AF_INET => {
                let sin = &*sa.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(
                    sin.sin_addr.s_addr.to_ne_bytes(),
                )))
            }
            libc::AF_INET6 => {
                let sin6 = &*sa.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

fn prefix_of(addr: IpAddr, mask: Option<IpAddr>) -> u8 {
    let ones = match mask {
        Some(IpAddr::V4(mask)) if addr.is_ipv4() => u32::from(mask).leading_ones(),
        Some(IpAddr::V6(mask)) if addr.is_ipv6() => u128::from(mask).leading_ones(),
        _ if addr.is_ipv4() => 32,
        _ => 128,
    };
    u8::try_from(ones).unwrap_or(u8::MAX)
}

pub(super) fn walk(mut each: impl FnMut(&CStr, u32, IpAddr, u8)) {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: the list is read only until `freeifaddrs`, its addresses through `ip_of`.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return;
        }
        let mut entry = head;
        while !entry.is_null() {
            let item = &*entry;
            entry = item.ifa_next;
            if let Some(addr) = ip_of(item.ifa_addr) {
                let prefix = prefix_of(addr, ip_of(item.ifa_netmask));
                each(CStr::from_ptr(item.ifa_name), item.ifa_flags, addr, prefix);
            }
        }
        libc::freeifaddrs(head);
    }
}

pub fn by_name(name: &str) -> Option<InterfaceInfo> {
    let index = index_of(name)?;
    Some(InterfaceInfo {
        name: name.into(),
        index,
        addrs: addrs_of(name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_name() -> &'static str {
        if cfg!(any(target_os = "macos", target_os = "ios")) {
            "lo0"
        } else {
            "lo"
        }
    }

    #[test]
    fn the_loopback_interface_round_trips() {
        let info = by_name(loopback_name()).unwrap();
        assert_eq!(name_of(info.index).as_deref(), Some(loopback_name()));
        assert!(info.addrs.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn a_mask_of_the_other_family_counts_as_a_host_route() {
        let v4: IpAddr = "10.1.2.3".parse().unwrap();
        assert_eq!(prefix_of(v4, Some("255.255.240.0".parse().unwrap())), 20);
        assert_eq!(prefix_of(v4, None), 32);
        assert_eq!(prefix_of(v4, Some("ffff::".parse().unwrap())), 32);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            prefix_of(v6, Some("ffff:ffff:ffff:ffff::".parse().unwrap())),
            64
        );
    }

    #[test]
    fn an_unknown_interface_is_absent() {
        assert!(by_name("no-such-if0").is_none());
        assert!(index_of("with\0nul").is_none());
        assert!(name_of(u32::MAX).is_none());
    }
}
