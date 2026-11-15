use std::mem::offset_of;

use super::ifaces;
use super::select::{Candidate, pick};
use crate::InterfaceInfo;

const RTF_UP: i32 = 0x1;
const RTF_HOST: i32 = 0x4;
const RTF_REJECT: i32 = 0x8;
const RTF_BLACKHOLE: i32 = 0x1000;
const RTF_IFSCOPE: i32 = 0x100_0000;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;

fn read<const N: usize>(buf: &[u8], at: usize) -> Option<[u8; N]> {
    buf.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn sockaddr_slots(message: &[u8], mut offset: usize, addrs: i32) -> [Option<&[u8]>; 3] {
    let mut slots = [None; 3];
    for bit in 0..8 {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let Some(&len) = message.get(offset) else {
            break;
        };
        let len = usize::from(len);
        if let Some(slot) = slots.get_mut(bit) {
            *slot = message.get(offset..offset + len);
        }
        offset += if len == 0 { 4 } else { len.next_multiple_of(4) };
    }
    slots
}

fn is_default_destination(sockaddr: &[u8]) -> bool {
    matches!(sockaddr.get(1), Some(&(AF_INET | AF_INET6)))
        && sockaddr.iter().skip(4).all(|byte| *byte == 0)
}

pub fn parse_dump(buf: &[u8]) -> Vec<(u32, i32)> {
    let header = std::mem::size_of::<libc::rt_msghdr>();
    let mut routes = Vec::new();
    let mut at = 0;
    while let Some(length) = read::<2>(buf, at).map(u16::from_ne_bytes) {
        let length = usize::from(length);
        let Some(message) = buf.get(at..at + length).filter(|_| length >= header) else {
            break;
        };
        at += length;
        let index = read::<2>(message, offset_of!(libc::rt_msghdr, rtm_index));
        let flags = read::<4>(message, offset_of!(libc::rt_msghdr, rtm_flags));
        let addrs = read::<4>(message, offset_of!(libc::rt_msghdr, rtm_addrs));
        let (Some(index), Some(flags), Some(addrs)) = (index, flags, addrs) else {
            continue;
        };
        let (flags, addrs) = (i32::from_ne_bytes(flags), i32::from_ne_bytes(addrs));
        if flags & RTF_UP == 0 || flags & (RTF_HOST | RTF_REJECT | RTF_BLACKHOLE) != 0 {
            continue;
        }
        let [destination, _, netmask] = sockaddr_slots(message, header, addrs);
        let mask_is_zero = netmask.is_none_or(|mask| mask.iter().skip(4).all(|byte| *byte == 0));
        if destination.is_some_and(is_default_destination) && mask_is_zero {
            routes.push((u32::from(u16::from_ne_bytes(index)), flags));
        }
    }
    routes
}

fn dump_routes() -> Option<Vec<u8>> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_DUMP, 0];
    for _ in 0..4 {
        let mut len = 0usize;
        // SAFETY: a null buffer only asks for the size; `mib` has the 6 entries passed.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let mut buf = vec![0u8; len + len / 8 + 4096];
        let mut size = buf.len();
        // SAFETY: `buf` is writable for `size` bytes, which the call updates to the bytes written.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                6,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(size);
            return Some(buf);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

pub fn default_interface(excluded: &[String]) -> Option<InterfaceInfo> {
    let candidates: Vec<Candidate> = parse_dump(&dump_routes()?)
        .into_iter()
        .filter_map(|(index, flags)| {
            Some(Candidate {
                name: ifaces::name_of(index)?,
                metric: 0,
                scoped: flags & RTF_IFSCOPE != 0,
            })
        })
        .collect();
    ifaces::by_name(&pick(&candidates, excluded)?.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr(family: u8, len: usize, fill: &[(usize, u8)]) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        if len > 1 {
            bytes[0] = len as u8;
            bytes[1] = family;
        }
        for &(at, value) in fill {
            bytes[at] = value;
        }
        bytes
    }

    fn message(index: u16, flags: i32, addrs: &[Vec<u8>], bits: i32) -> Vec<u8> {
        let header = std::mem::size_of::<libc::rt_msghdr>();
        let mut bytes = vec![0u8; header];
        let put = |bytes: &mut Vec<u8>, at: usize, value: &[u8]| {
            bytes[at..at + value.len()].copy_from_slice(value)
        };
        put(
            &mut bytes,
            offset_of!(libc::rt_msghdr, rtm_index),
            &index.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(libc::rt_msghdr, rtm_flags),
            &flags.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(libc::rt_msghdr, rtm_addrs),
            &bits.to_ne_bytes(),
        );
        for addr in addrs {
            bytes.extend_from_slice(addr);
            bytes.resize(bytes.len().next_multiple_of(4), 0);
        }
        let total = (bytes.len() as u16).to_ne_bytes();
        put(&mut bytes, 0, &total);
        bytes
    }

    #[test]
    fn default_routes_are_found_among_other_entries() {
        let default = sockaddr(AF_INET, 16, &[]);
        let gateway = sockaddr(AF_INET, 16, &[(4, 192), (5, 168), (6, 1), (7, 1)]);
        let empty_mask = sockaddr(0, 0, &[]);
        let subnet = sockaddr(AF_INET, 16, &[(4, 192), (5, 168), (6, 1)]);
        let mask24 = sockaddr(AF_INET, 8, &[(4, 255), (5, 255), (6, 255)]);

        let mut dump = message(
            7,
            RTF_UP | 2,
            &[default.clone(), gateway.clone(), empty_mask],
            0b111,
        );
        dump.extend(message(
            7,
            RTF_UP | 2,
            &[subnet, gateway.clone(), mask24],
            0b111,
        ));
        dump.extend(message(
            9,
            RTF_UP | RTF_IFSCOPE | 2,
            &[default.clone(), gateway.clone()],
            0b011,
        ));
        dump.extend(message(10, RTF_UP | RTF_REJECT, &[default, gateway], 0b011));

        assert_eq!(
            parse_dump(&dump),
            vec![(7, RTF_UP | 2), (9, RTF_UP | RTF_IFSCOPE | 2)]
        );
    }

    #[test]
    fn a_truncated_dump_stops_cleanly() {
        let dump = message(7, RTF_UP, &[sockaddr(AF_INET, 16, &[])], 0b001);
        assert_eq!(parse_dump(&dump[..dump.len() - 3]), vec![]);
        assert_eq!(parse_dump(&[]), vec![]);
    }

    #[test]
    fn the_live_routing_table_parses() {
        let table = dump_routes().unwrap();
        assert!(!table.is_empty());
        if let Some(info) = default_interface(&[]) {
            assert!(info.index > 0 && !info.name.is_empty());
        }
    }
}
