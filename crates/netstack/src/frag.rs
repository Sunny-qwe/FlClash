use std::net::IpAddr;

use crate::wire::{FragmentView, IPV4_HEADER, IPV6_HEADER, finish, put16, sum_bytes};

const MAX_ENTRIES: usize = 32;
const MAX_PAYLOAD: usize = 65_535 - IPV4_HEADER;
const TIMEOUT: u64 = 15_000_000;

type Key = (IpAddr, IpAddr, u32, u8);

struct Entry {
    key: Key,
    header: Vec<u8>,
    data: Vec<u8>,
    ranges: Vec<(usize, usize)>,
    total: Option<usize>,
    started: u64,
}

impl Entry {
    fn complete(&self) -> bool {
        let Some(total) = self.total else {
            return false;
        };
        let mut covered = 0;
        for (start, end) in &self.ranges {
            if *start > covered {
                return false;
            }
            covered = covered.max(*end);
        }
        covered >= total
    }
}

/// Collects IP fragments into whole packets. Bounded in entries, size and age; fragments that
/// overlap with different lengths drop the packet, as RFC 5722 asks for IPv6.
#[derive(Default)]
pub struct Reassembler {
    entries: Vec<Entry>,
}

impl Reassembler {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds a fragment. When it completes a packet, writes the packet to `out` and returns
    /// true.
    pub fn push(&mut self, frag: &FragmentView<'_>, now: u64, out: &mut Vec<u8>) -> bool {
        self.expire(now);
        let key = (frag.src, frag.dst, frag.id, frag.proto);
        let end = frag.offset + frag.payload.len();
        if end > MAX_PAYLOAD || (frag.more && !frag.payload.len().is_multiple_of(8)) {
            return false;
        }
        let index = match self.entries.iter().position(|e| e.key == key) {
            Some(index) => index,
            None => {
                if self.entries.len() >= MAX_ENTRIES {
                    self.entries.remove(0);
                }
                self.entries.push(Entry {
                    key,
                    header: Vec::new(),
                    data: Vec::new(),
                    ranges: Vec::new(),
                    total: None,
                    started: now,
                });
                self.entries.len() - 1
            }
        };
        let Some(entry) = self.entries.get_mut(index) else {
            return false;
        };
        let overlaps = entry
            .ranges
            .iter()
            .any(|(s, e)| frag.offset < *e && *s < end && !(*s == frag.offset && *e == end));
        let conflicting_end = !frag.more && entry.total.is_some_and(|t| t != end);
        if overlaps || conflicting_end || entry.total.is_some_and(|t| end > t) {
            self.entries.remove(index);
            return false;
        }
        if frag.offset == 0 {
            entry.header = frag.header.to_vec();
        }
        if !frag.more {
            entry.total = Some(end);
        }
        if entry.data.len() < end {
            entry.data.resize(end, 0);
        }
        if let Some(dst) = entry.data.get_mut(frag.offset..end) {
            dst.copy_from_slice(frag.payload);
        }
        let at = entry.ranges.partition_point(|(s, _)| *s < frag.offset);
        entry.ranges.insert(at, (frag.offset, end));
        if !entry.complete() || entry.header.is_empty() {
            return false;
        }
        let entry = self.entries.remove(index);
        build(&entry, out)
    }

    fn expire(&mut self, now: u64) {
        self.entries
            .retain(|entry| now.saturating_sub(entry.started) < TIMEOUT);
    }
}

fn build(entry: &Entry, out: &mut Vec<u8>) -> bool {
    out.clear();
    let (_, _, _, proto) = entry.key;
    let Some(total) = entry.total else {
        return false;
    };
    let Some(payload) = entry.data.get(..total) else {
        return false;
    };
    match entry.key.0 {
        IpAddr::V4(_) => {
            let Some(header) = entry.header.get(..IPV4_HEADER) else {
                return false;
            };
            out.extend_from_slice(header);
            out.extend_from_slice(payload);
            let Ok(len) = u16::try_from(out.len()) else {
                return false;
            };
            if let Some(first) = out.first_mut() {
                *first = 0x45;
            }
            let ok = put16(out, 2, len).is_some()
                && put16(out, 6, 0).is_some()
                && put16(out, 10, 0).is_some();
            if !ok {
                return false;
            }
            let sum = finish(sum_bytes(0, out.get(..IPV4_HEADER).unwrap_or_default()));
            put16(out, 10, sum).is_some()
        }
        IpAddr::V6(_) => {
            let Some(header) = entry.header.get(..IPV6_HEADER) else {
                return false;
            };
            out.extend_from_slice(header);
            out.extend_from_slice(payload);
            let Ok(len) = u16::try_from(payload.len()) else {
                return false;
            };
            if let Some(next) = out.get_mut(6) {
                *next = proto;
            }
            put16(out, 4, len).is_some()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{L4Kind, Parsed, build_udp, emit_ip, parse_packet, parse_udp};

    fn fragments(packet: &[u8], size: usize) -> Vec<Vec<u8>> {
        let header = &packet[..IPV4_HEADER];
        let payload = &packet[IPV4_HEADER..];
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < payload.len() {
            let end = (offset + size).min(payload.len());
            let mut frag = header.to_vec();
            frag.extend_from_slice(&payload[offset..end]);
            let more = end < payload.len();
            let field = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
            let len = frag.len() as u16;
            frag[2..4].copy_from_slice(&len.to_be_bytes());
            frag[4..6].copy_from_slice(&7u16.to_be_bytes());
            frag[6..8].copy_from_slice(&field.to_be_bytes());
            frag[10..12].copy_from_slice(&[0, 0]);
            let sum = finish(sum_bytes(0, &frag[..IPV4_HEADER]));
            frag[10..12].copy_from_slice(&sum.to_be_bytes());
            out.push(frag);
            offset = end;
        }
        out
    }

    #[test]
    fn out_of_order_fragments_rebuild_the_datagram() {
        let mut packet = vec![0u8; 4000];
        let payload: Vec<u8> = (0..3000).map(|i| i as u8).collect();
        let n = build_udp(
            &mut packet,
            "10.0.0.2:5000".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
            &payload,
            crate::wire::L4Checksum::Full,
        )
        .unwrap();
        packet.truncate(n);
        let mut frags = fragments(&packet, 1200);
        frags.reverse();
        let mut reassembler = Reassembler::default();
        let mut out = Vec::new();
        let mut done = 0;
        for frag in &frags {
            let Ok(Parsed::Fragment(view)) = parse_packet(frag) else {
                panic!("expected a fragment");
            };
            if reassembler.push(&view, 0, &mut out) {
                done += 1;
            }
        }
        assert_eq!(done, 1);
        let Ok(Parsed::Packet(view)) = parse_packet(&out) else {
            panic!("expected a whole packet");
        };
        assert_eq!(view.kind, L4Kind::Udp);
        assert_eq!(parse_udp(&view).unwrap().payload, &payload[..]);
        assert!(reassembler.is_empty());
    }

    #[test]
    fn overlaps_and_age_drop_the_entry() {
        let mut packet = vec![0u8; 64];
        emit_ip(
            &mut packet,
            "10.0.0.2".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            17,
            40,
        )
        .unwrap();
        let frags = fragments(&packet[..60], 16);
        let mut reassembler = Reassembler::default();
        let mut out = Vec::new();
        let Ok(Parsed::Fragment(first)) = parse_packet(&frags[0]) else {
            panic!()
        };
        assert!(!reassembler.push(&first, 0, &mut out));
        assert_eq!(reassembler.len(), 1);
        let mut shifted = first;
        shifted.offset = 8;
        assert!(!reassembler.push(&shifted, 0, &mut out));
        assert!(reassembler.is_empty());
        assert!(!reassembler.push(&first, 0, &mut out));
        let Ok(Parsed::Fragment(second)) = parse_packet(&frags[1]) else {
            panic!()
        };
        assert!(!reassembler.push(&second, TIMEOUT + 1, &mut out));
        assert_eq!(reassembler.len(), 1);
    }
}
