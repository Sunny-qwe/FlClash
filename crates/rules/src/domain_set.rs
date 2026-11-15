//! Domain pattern sets: the succinct trie behind `.mrs` domain rule sets.

use smallvec::SmallVec;

use crate::error::{FormatError, InvalidDomain};

const COMPLEX_WILDCARD: u8 = b'+';
const WILDCARD: u8 = b'*';
const STEP: u8 = b'.';

/// Splits a Clash-style domain pattern into lowercase labels, rejecting what
/// mihomo's `ValidAndSplitDomain` rejects.
pub fn valid_and_split(domain: &str) -> Result<Vec<String>, InvalidDomain> {
    if domain.is_empty() {
        return Err(InvalidDomain::new(domain, "domain is empty"));
    }
    if domain.ends_with('.') {
        return Err(InvalidDomain::new(domain, "trailing dot is not allowed"));
    }
    if domain.chars().next().is_some_and(char::is_whitespace) {
        return Err(InvalidDomain::new(
            domain,
            "leading whitespace is not allowed",
        ));
    }
    if domain.chars().next_back().is_some_and(char::is_whitespace) {
        return Err(InvalidDomain::new(
            domain,
            "trailing whitespace is not allowed",
        ));
    }
    let lower = domain.to_lowercase();
    let parts: Vec<String> = lower.split('.').map(str::to_string).collect();
    for (i, part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            return Err(InvalidDomain::new(
                domain,
                format!("label {} is empty", i + 1),
            ));
        }
    }
    for (i, part) in parts.iter().enumerate() {
        if part.contains('+') {
            if part != "+" {
                return Err(InvalidDomain::new(
                    domain,
                    format!("\"+\" wildcard must occupy the entire label {}", i + 1),
                ));
            }
            if i != 0 {
                return Err(InvalidDomain::new(
                    domain,
                    "\"+\" wildcard is only allowed in the first label",
                ));
            }
            if parts.len() == 1 {
                return Err(InvalidDomain::new(
                    domain,
                    "\"+\" wildcard must be followed by another label",
                ));
            }
        }
        if part.contains('*') && part != "*" {
            return Err(InvalidDomain::new(
                domain,
                format!("\"*\" wildcard must occupy the entire label {}", i + 1),
            ));
        }
    }
    Ok(parts)
}

fn reverse_runes(text: &str) -> Vec<u8> {
    let reversed: String = text.chars().rev().collect();
    reversed.into_bytes()
}

/// The reversed, lowercased key a query walks, without materializing it for ASCII input.
struct RevKey<'a> {
    bytes: &'a [u8],
    owned: Option<Vec<u8>>,
}

impl<'a> RevKey<'a> {
    fn new(host: &'a str) -> Self {
        if host.is_ascii() {
            RevKey {
                bytes: host.as_bytes(),
                owned: None,
            }
        } else {
            let lower: String = host.to_lowercase();
            RevKey {
                bytes: host.as_bytes(),
                owned: Some(reverse_runes(&lower)),
            }
        }
    }

    fn len(&self) -> usize {
        self.owned.as_ref().map_or(self.bytes.len(), Vec::len)
    }

    fn at(&self, i: usize) -> u8 {
        match &self.owned {
            Some(owned) => owned.get(i).copied().unwrap_or(0),
            None => self
                .bytes
                .len()
                .checked_sub(1 + i)
                .and_then(|at| self.bytes.get(at))
                .map_or(0, u8::to_ascii_lowercase),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    ranks: Vec<u32>,
    selects: Vec<u32>,
}

fn set_bit(bitmap: &mut Vec<u64>, i: usize, value: bool) {
    while (i >> 6) >= bitmap.len() {
        bitmap.push(0);
    }
    if value && let Some(word) = bitmap.get_mut(i >> 6) {
        *word |= 1 << (i & 63);
    }
}

fn get_bit(bitmap: &[u64], i: usize) -> bool {
    bitmap.get(i >> 6).is_some_and(|w| w & (1 << (i & 63)) != 0)
}

impl DomainSet {
    /// `None` when `keys` is empty, as mihomo's builder returns a nil set.
    pub(crate) fn from_keys(mut keys: Vec<Vec<u8>>) -> Option<DomainSet> {
        if keys.is_empty() {
            return None;
        }
        keys.sort_unstable();
        keys.dedup();
        let mut set = DomainSet::default();
        let mut l_idx = 0usize;
        let mut node_id = 0usize;
        let mut queue: Vec<(usize, usize)> = vec![(0, keys.len())];
        let mut next: Vec<(usize, usize)> = Vec::new();
        let mut col = 0usize;
        while !queue.is_empty() {
            for &(mut start, end) in &queue {
                if keys.get(start).is_some_and(|k| k.len() == col) {
                    set_bit(&mut set.leaves, node_id, true);
                    start += 1;
                }
                let mut j = start;
                while j < end {
                    let from = j;
                    let byte = keys.get(from).and_then(|k| k.get(col)).copied();
                    while j < end && keys.get(j).and_then(|k| k.get(col)).copied() == byte {
                        j += 1;
                    }
                    next.push((from, j));
                    set.labels.push(byte.unwrap_or(0));
                    set_bit(&mut set.label_bitmap, l_idx, false);
                    l_idx += 1;
                }
                set_bit(&mut set.label_bitmap, l_idx, true);
                l_idx += 1;
                node_id += 1;
            }
            queue.clear();
            std::mem::swap(&mut queue, &mut next);
            col += 1;
        }
        set.index();
        Some(set)
    }

    fn index(&mut self) {
        self.ranks.clear();
        self.selects.clear();
        let mut ones = 0u32;
        self.ranks.push(0);
        for (w, word) in self.label_bitmap.iter().enumerate() {
            let before = ones;
            ones += word.count_ones();
            let mut mark = before.div_ceil(64) * 64;
            while mark < ones {
                self.selects.push(w as u32);
                mark += 64;
            }
            self.ranks.push(ones);
        }
    }

    fn rank1(&self, i: usize) -> Option<usize> {
        let base = *self.ranks.get(i >> 6)? as usize;
        let word = self.label_bitmap.get(i >> 6).copied().unwrap_or(0);
        Some(base + (word & ((1u64 << (i & 63)) - 1)).count_ones() as usize)
    }

    fn count_zeros(&self, i: usize) -> Option<usize> {
        i.checked_sub(self.rank1(i)?)
    }

    fn select1(&self, k: usize) -> Option<usize> {
        let mut w = *self.selects.get(k >> 6)? as usize;
        while *self.ranks.get(w + 1)? as usize <= k {
            w += 1;
        }
        let mut word = *self.label_bitmap.get(w)?;
        for _ in 0..k.checked_sub(*self.ranks.get(w)? as usize)? {
            word &= word.wrapping_sub(1);
        }
        if word == 0 {
            return None;
        }
        Some(w * 64 + word.trailing_zeros() as usize)
    }

    pub fn has(&self, host: &str) -> bool {
        self.walk(&RevKey::new(host)).unwrap_or(false)
    }

    /// Every label is one 0 bit and leads to one node, every node one 1 bit, so a well-formed
    /// set of L labels has L + 1 nodes and 2L + 1 bits. A corrupt payload is held to the same.
    fn bits(&self) -> usize {
        2 * self.labels.len() + 1
    }

    /// A walk scans each node's run of bits once on the way down and once more after a wildcard
    /// is popped, and restarts once per key byte or pop.
    fn walk_fuel(&self, key_len: usize) -> usize {
        2 * self.bits() + self.labels.len() + 1 + key_len
    }

    fn walk(&self, key: &RevKey<'_>) -> Option<bool> {
        let n = key.len();
        let mut node_id = 0usize;
        let mut bm_idx = 0usize;
        let mut stack: SmallVec<[(usize, usize); 8]> = SmallVec::new();
        let mut fuel = self.walk_fuel(n);
        let mut i = 0usize;
        while i < n {
            'restart: loop {
                fuel = fuel.checked_sub(1)?;
                let c = key.at(i);
                loop {
                    fuel = fuel.checked_sub(1)?;
                    if get_bit(&self.label_bitmap, bm_idx) {
                        while let Some((cursor_bm, cursor_i)) = stack.pop() {
                            let next_node = self.count_zeros(cursor_bm + 1)?;
                            let mut j = cursor_i;
                            while j < n && key.at(j) != STEP {
                                j += 1;
                            }
                            if j == n {
                                if get_bit(&self.leaves, next_node) {
                                    return Some(true);
                                }
                                continue;
                            }
                            let mut next_bm = self.select1(next_node.checked_sub(1)?)? + 1;
                            while !get_bit(&self.label_bitmap, next_bm) {
                                fuel = fuel.checked_sub(1)?;
                                if *self.labels.get(next_bm.checked_sub(next_node)?)? == STEP {
                                    bm_idx = next_bm;
                                    node_id = next_node;
                                    i = j;
                                    continue 'restart;
                                }
                                next_bm += 1;
                            }
                        }
                        return Some(false);
                    }
                    let label = *self.labels.get(bm_idx.checked_sub(node_id)?)?;
                    if label == COMPLEX_WILDCARD {
                        return Some(true);
                    } else if label == WILDCARD {
                        stack.push((bm_idx, i));
                    } else if label == c {
                        break;
                    }
                    bm_idx += 1;
                }
                node_id = bm_idx.checked_sub(node_id)? + 1;
                if i + 1 == n {
                    if get_bit(&self.leaves, node_id) {
                        return Some(true);
                    }
                    if stack.is_empty() {
                        return Some(false);
                    }
                    bm_idx = self.select1(node_id)?;
                    continue 'restart;
                }
                bm_idx = self.select1(node_id.checked_sub(1)?)? + 1;
                break;
            }
            i += 1;
        }
        Some(get_bit(&self.leaves, node_id))
    }

    /// Visits the stored patterns: lowercase labels, `*` for one label, a leading
    /// `.` for sub-domains only. Exact and suffix-only entries are separate.
    pub fn foreach(&self, mut f: impl FnMut(&str) -> bool) {
        let mut key: Vec<u8> = Vec::new();
        let mut budget = self.bits();
        self.keys(0, 0, &mut key, &mut budget, &mut |raw| {
            let trimmed = raw.strip_suffix(&[COMPLEX_WILDCARD]).unwrap_or(raw);
            let text = String::from_utf8_lossy(trimmed);
            let reversed: String = text.chars().rev().collect();
            f(&reversed)
        });
    }

    fn keys(
        &self,
        node_id: usize,
        mut bm_idx: usize,
        key: &mut Vec<u8>,
        budget: &mut usize,
        f: &mut impl FnMut(&[u8]) -> bool,
    ) -> bool {
        if get_bit(&self.leaves, node_id) && !f(key) {
            return false;
        }
        loop {
            let Some(left) = budget.checked_sub(1) else {
                return false;
            };
            *budget = left;
            if get_bit(&self.label_bitmap, bm_idx) {
                return true;
            }
            let Some(label) = bm_idx
                .checked_sub(node_id)
                .and_then(|at| self.labels.get(at))
            else {
                return false;
            };
            key.push(*label);
            let next_node = bm_idx - node_id + 1;
            let next_bm = match next_node.checked_sub(1).and_then(|k| self.select1(k)) {
                Some(at) => at + 1,
                None => return false,
            };
            if !self.keys(next_node, next_bm, key, budget, f) {
                return false;
            }
            key.pop();
            bm_idx += 1;
        }
    }

    pub fn write_bin(&self, out: &mut Vec<u8>) {
        out.push(1);
        write_words(out, &self.leaves);
        write_words(out, &self.label_bitmap);
        out.extend_from_slice(&(self.labels.len() as i64).to_be_bytes());
        out.extend_from_slice(&self.labels);
    }

    /// Reads the payload that follows the `.mrs` header; returns the set and the bytes consumed.
    pub fn read_bin(buf: &[u8]) -> Result<(DomainSet, usize), FormatError> {
        let mut cur = crate::mrs::Cursor::new(buf);
        if cur.u8()? != 1 {
            return Err(FormatError::new("version is invalid"));
        }
        let mut set = DomainSet {
            leaves: read_words(&mut cur)?,
            label_bitmap: read_words(&mut cur)?,
            ..DomainSet::default()
        };
        let len = cur.i64()?;
        if len < 1 {
            return Err(FormatError::new("length is invalid"));
        }
        let len = usize::try_from(len).map_err(|_| FormatError::new("length is invalid"))?;
        set.labels = cur.bytes(len)?.to_vec();
        set.index();
        Ok((set, cur.position()))
    }
}

fn write_words(out: &mut Vec<u8>, words: &[u64]) {
    out.extend_from_slice(&(words.len() as i64).to_be_bytes());
    for word in words {
        out.extend_from_slice(&word.to_be_bytes());
    }
}

fn read_words(cur: &mut crate::mrs::Cursor<'_>) -> Result<Vec<u64>, FormatError> {
    let len = cur.i64()?;
    if len < 1 {
        return Err(FormatError::new("length is invalid"));
    }
    let len = usize::try_from(len).map_err(|_| FormatError::new("length is invalid"))?;
    if len > cur.remaining() / 8 {
        return Err(FormatError::new("unexpected end of data"));
    }
    (0..len).map(|_| cur.u64()).collect()
}

/// Collects patterns and builds a [`DomainSet`] from them.
#[derive(Default)]
pub struct DomainSetBuilder {
    keys: Vec<Vec<u8>>,
}

impl DomainSetBuilder {
    pub fn new() -> Self {
        DomainSetBuilder::default()
    }

    pub fn insert(&mut self, domain: &str) -> Result<(), InvalidDomain> {
        let mut parts = valid_and_split(domain)?;
        if parts.first().is_some_and(|p| p == "+") {
            self.push(parts.get(1..).unwrap_or_default().to_vec());
            self.push(parts);
        } else {
            self.push(std::mem::take(&mut parts));
        }
        Ok(())
    }

    fn push(&mut self, mut parts: Vec<String>) {
        if let Some(first) = parts.first_mut()
            && first.is_empty()
        {
            *first = "+".to_string();
        }
        self.keys.push(reverse_runes(&parts.join(".")));
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn build(self) -> Option<DomainSet> {
        DomainSet::from_keys(self.keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(domains: &[&str]) -> DomainSet {
        let mut builder = DomainSetBuilder::new();
        for domain in domains {
            builder.insert(domain).unwrap();
        }
        builder.build().unwrap()
    }

    fn dump(set: &DomainSet) -> Vec<String> {
        let mut keys = Vec::new();
        set.foreach(|key| {
            keys.push(key.to_string());
            true
        });
        keys.sort();
        keys
    }

    #[test]
    fn plain_and_suffix_entries() {
        let set = build(&[
            "baidu.com",
            "google.com",
            "www.google.com",
            "test.a.net",
            "test.a.oc",
            "Mijia Cloud",
            ".qq.com",
            "+.cn",
        ]);
        for hit in [
            "test.cn",
            "cn",
            "Mijia Cloud",
            "test.a.net",
            "www.qq.com",
            "google.com",
        ] {
            assert!(set.has(hit), "{hit}");
        }
        for miss in ["qq.com", "www.baidu.com"] {
            assert!(!set.has(miss), "{miss}");
        }
    }

    #[test]
    fn foreach_keeps_exact_and_suffix_apart() {
        let set = build(&[".example.com", "+.example.org", "example.net"]);
        assert_eq!(
            dump(&set),
            [".example.com", ".example.org", "example.net", "example.org"]
        );
        assert!(!set.has("example.com"));
        assert!(set.has("www.example.com"));
        assert!(set.has("example.org") && set.has("www.example.org"));
        assert!(set.has("example.net") && !set.has("www.example.net"));
    }

    #[test]
    fn complex_wildcard_cases() {
        let set = build(&[
            "+.baidu.com",
            "+.a.baidu.com",
            "www.baidu.com",
            "+.bb.baidu.com",
            "test.a.net",
            "test.a.oc",
            "www.qq.com",
        ]);
        assert!(!set.has("google.com"));
        assert!(set.has("www.baidu.com"));
        assert!(set.has("test.test.baidu.com"));
    }

    #[test]
    fn star_wildcards() {
        let set = build(&[
            "*.*.*.baidu.com",
            "www.baidu.*",
            "stun.*.*",
            "*.*.qq.com",
            "test.*.baidu.com",
            "*.apple.com",
        ]);
        for hit in [
            "www.baidu.com",
            "test.test.baidu.com",
            "test.test.qq.com",
            "stun.ab.cd",
        ] {
            assert!(set.has(hit), "{hit}");
        }
        for miss in [
            "test.baidu.com",
            "www.google.com",
            "a.www.google.com",
            "test.qq.com",
            "test.test.test.qq.com",
        ] {
            assert!(!set.has(miss), "{miss}");
        }
    }

    #[test]
    fn wildcard_shadowing() {
        let cases: [(&[&str], &str, &str); 3] = [
            (
                &["*.example.com", "dead.a.example.com"],
                "a.example.com",
                "b.a.example.com",
            ),
            (
                &[
                    "*.*.example.com",
                    "dead.*.a.example.com",
                    "dead.b.a.example.com",
                ],
                "b.a.example.com",
                "a.example.com",
            ),
            (
                &["*.*.*.example.com", "*.a.example.com"],
                "b.c.a.example.com",
                "d.b.c.a.example.com",
            ),
        ];
        for (domains, hit, miss) in cases {
            let set = build(domains);
            assert!(set.has(hit), "{hit}");
            assert!(!set.has(miss), "{miss}");
        }
    }

    #[test]
    fn case_and_unicode() {
        let set = build(&[
            "example.com",
            "EXAMPLE.COM",
            "+.mixed.example.org",
            "中文.example",
            "+.测试.cn",
        ]);
        assert!(set.has("EXAMPLE.COM") && set.has("ExAmPlE.cOm"));
        assert!(set.has("WWW.MIXED.EXAMPLE.ORG"));
        assert!(!set.has("EXAMPLE.NET"));
        assert!(set.has("中文.example") && set.has("www.测试.cn"));
        assert!(!set.has("日本語.example"));
    }

    #[test]
    fn long_hosts_do_not_overflow() {
        let set = build(&["+.example.com"]);
        let prefix = "label.".repeat(60);
        assert!(set.has(&format!("{prefix}example.com")));
        assert!(!set.has(&format!("{prefix}example.net")));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        let mut builder = DomainSetBuilder::new();
        for bad in [
            "", "a.com.", " a.com", "a.com ", "a..b", "+", "a.+.b", "*a.com", "a*.com",
        ] {
            assert!(builder.insert(bad).is_err(), "{bad:?}");
        }
        assert!(builder.is_empty());
        assert!(builder.build().is_none());
    }

    #[test]
    fn bin_round_trips_and_survives_truncation() {
        let set = build(&["+.example.com", "example.org", "*.apple.com"]);
        let mut buf = Vec::new();
        set.write_bin(&mut buf);
        let (read, used) = DomainSet::read_bin(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(read, set);
        for cut in 0..buf.len() {
            let _ = DomainSet::read_bin(buf.get(..cut).unwrap());
        }
    }

    #[test]
    fn well_formed_sets_stay_within_the_derived_budgets() {
        let patterns = [
            "+.example.com",
            "a.b.c",
            "*.apple.com",
            "x.*.y",
            "*.*.deep.*.net",
            "*.a.*.b.*.c",
            "+.*.wild.org",
        ];
        let set = build(&patterns);
        let mut seen = 0;
        let mut budget = set.bits();
        assert!(set.keys(0, 0, &mut Vec::new(), &mut budget, &mut |_| {
            seen += 1;
            true
        }));
        assert_eq!(budget, 0, "enumeration spends exactly one unit per bit");
        assert!(seen >= patterns.len());
        let labels = [
            "a", "b", "c", "x", "y", "deep", "net", "apple", "com", "wild", "org", "q",
        ];
        let mut seed = 0x9e37_79b9_u32;
        for _ in 0..2000 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let depth = 1 + (seed >> 28) as usize % 7;
            let host: Vec<&str> = (0..depth)
                .map(|at| labels[(seed as usize >> (at * 3)) % labels.len()])
                .collect();
            let host = host.join(".");
            assert!(
                set.walk(&RevKey::new(&host)).is_some(),
                "{host} ran out of fuel"
            );
        }
    }

    #[test]
    fn corrupt_tries_never_panic_or_hang() {
        let set = build(&["+.example.com", "a.b.c", "*.apple.com", "x.*.y"]);
        let mut buf = Vec::new();
        set.write_bin(&mut buf);
        let mut seed = 0x1234_5678_u32;
        for _ in 0..300 {
            let mut bytes = buf.clone();
            for _ in 0..3 {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let at = (seed as usize >> 8) % bytes.len();
                if let Some(byte) = bytes.get_mut(at) {
                    *byte = (seed >> 24) as u8;
                }
            }
            if let Ok((broken, _)) = DomainSet::read_bin(&bytes) {
                for host in ["www.example.com", "a.b.c", "x.q.y", "www.apple.com"] {
                    let _ = broken.has(host);
                }
                broken.foreach(|_| true);
            }
        }
    }
}
