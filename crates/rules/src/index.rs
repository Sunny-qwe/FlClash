//! Open-addressing multimap from a 64-bit key to ascending rule indices.

pub(crate) fn mix(mut x: u64) -> u64 {
    x ^= x >> 32;
    x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^ (x >> 29)
}

const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const FNV_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// Hashes bytes right to left, so the hash of every label-aligned suffix of a
/// host falls out of one backward scan.
#[derive(Clone, Copy)]
pub(crate) struct SuffixHash(u64);

impl SuffixHash {
    pub(crate) const fn new() -> Self {
        SuffixHash(FNV_BASIS)
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
    }

    pub(crate) fn finish(self) -> u64 {
        mix(self.0)
    }
}

pub(crate) fn hash_key(text: &str) -> u64 {
    let mut hash = SuffixHash::new();
    for byte in text.bytes().rev() {
        hash.push(byte);
    }
    hash.finish()
}

#[derive(Default)]
pub(crate) struct HashIdx {
    keys: Box<[u64]>,
    idx: Box<[u32]>,
    slots: Box<[u32]>,
}

impl HashIdx {
    pub(crate) fn build(mut entries: Vec<(u64, u32)>) -> Self {
        if entries.is_empty() {
            return HashIdx::default();
        }
        entries.sort_unstable();
        let keys: Box<[u64]> = entries.iter().map(|e| e.0).collect();
        let idx: Box<[u32]> = entries.iter().map(|e| e.1).collect();
        drop(entries);
        let groups = keys.windows(2).filter(|w| w.first() != w.get(1)).count() + 1;
        let size = (groups * 2).next_power_of_two().max(4);
        let mask = size - 1;
        let mut slots = vec![0u32; size];
        let mut pos = 0usize;
        while let Some(&key) = keys.get(pos) {
            let mut slot = (mix(key) as usize) & mask;
            loop {
                match slots.get_mut(slot) {
                    Some(cell) if *cell == 0 => {
                        *cell = (pos + 1) as u32;
                        break;
                    }
                    _ => slot = (slot + 1) & mask,
                }
            }
            while keys.get(pos) == Some(&key) {
                pos += 1;
            }
        }
        HashIdx {
            keys,
            idx,
            slots: slots.into_boxed_slice(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.keys.len() * 8 + self.idx.len() * 4 + self.slots.len() * 4
    }

    fn group(&self, key: u64) -> Option<(usize, usize)> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut slot = (mix(key) as usize) & mask;
        loop {
            let at = *self.slots.get(slot)?;
            if at == 0 {
                return None;
            }
            let start = (at - 1) as usize;
            if *self.keys.get(start)? == key {
                let mut end = start + 1;
                while self.keys.get(end) == Some(&key) {
                    end += 1;
                }
                return Some((start, end));
            }
            slot = (slot + 1) & mask;
        }
    }

    /// Smallest rule index at or after `from` stored under `key` for which
    /// `verify` holds.
    pub(crate) fn first_from(
        &self,
        key: u64,
        from: u32,
        mut verify: impl FnMut(u32) -> bool,
    ) -> Option<u32> {
        let (start, end) = self.group(key)?;
        let group = self.idx.get(start..end)?;
        let first = group.partition_point(|&i| i < from);
        group.get(first..)?.iter().copied().find(|&i| verify(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_are_ascending_and_filtered_by_from() {
        let index = HashIdx::build(vec![(7, 30), (7, 10), (9, 5), (7, 20)]);
        assert_eq!(index.first_from(7, 0, |_| true), Some(10));
        assert_eq!(index.first_from(7, 11, |_| true), Some(20));
        assert_eq!(index.first_from(7, 31, |_| true), None);
        assert_eq!(index.first_from(9, 0, |_| true), Some(5));
        assert_eq!(index.first_from(8, 0, |_| true), None);
        assert_eq!(index.first_from(7, 0, |i| i > 10), Some(20));
    }

    #[test]
    fn colliding_slots_probe_on() {
        let entries: Vec<(u64, u32)> = (0..1000u64).map(|k| (k * 4096, k as u32)).collect();
        let index = HashIdx::build(entries);
        for k in 0..1000u64 {
            assert_eq!(index.first_from(k * 4096, 0, |_| true), Some(k as u32));
        }
        assert_eq!(index.first_from(1, 0, |_| true), None);
    }

    #[test]
    fn suffix_hash_matches_whole_key_hash() {
        let key = "example.com";
        let mut hash = SuffixHash::new();
        for byte in key.bytes().rev() {
            hash.push(byte);
        }
        assert_eq!(hash.finish(), hash_key(key));
    }
}
