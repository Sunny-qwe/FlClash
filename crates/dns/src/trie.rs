use std::collections::HashMap;

use crate::DomainMatch;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid domain {domain:?}: {reason}")]
pub struct InvalidDomain {
    pub domain: String,
    pub reason: &'static str,
}

fn invalid(domain: &str, reason: &'static str) -> InvalidDomain {
    InvalidDomain {
        domain: domain.to_string(),
        reason,
    }
}

/// Checks a pattern or a name that is already lower-cased.
fn validate(lowered: &str) -> Result<(), &'static str> {
    if lowered.is_empty() {
        return Err("domain is empty");
    }
    if lowered.ends_with('.') {
        return Err("trailing dot is not allowed");
    }
    if lowered.starts_with(char::is_whitespace) {
        return Err("leading whitespace is not allowed");
    }
    if lowered.ends_with(char::is_whitespace) {
        return Err("trailing whitespace is not allowed");
    }
    if lowered.split('.').skip(1).any(str::is_empty) {
        return Err("label is empty");
    }
    let count = lowered.split('.').count();
    for (index, part) in lowered.split('.').enumerate() {
        if part.contains('+') {
            if part != "+" {
                return Err("'+' wildcard must occupy the entire label");
            }
            if index != 0 {
                return Err("'+' wildcard is only allowed in the first label");
            }
            if count == 1 {
                return Err("'+' wildcard must be followed by another label");
            }
        }
        if part.contains('*') && part != "*" {
            return Err("'*' wildcard must occupy the entire label");
        }
    }
    Ok(())
}

/// Lower-cases and splits a domain pattern. An empty first label is the
/// `.example.com` form; `+` and `*` must fill a whole label.
pub fn split_domain(domain: &str) -> Result<Vec<String>, InvalidDomain> {
    let lowered = domain.to_lowercase();
    validate(&lowered).map_err(|reason| invalid(domain, reason))?;
    Ok(lowered.split('.').map(str::to_string).collect())
}

struct Node<T> {
    children: HashMap<String, Node<T>>,
    data: Option<T>,
}

impl<T> Node<T> {
    fn new() -> Self {
        Node {
            children: HashMap::new(),
            data: None,
        }
    }
}

/// Labels are stored from the right. Lookup order: the static label, then
/// `*`, then the `.` (empty label) catch-all.
pub struct DomainTrie<T> {
    root: Node<T>,
}

impl<T> Default for DomainTrie<T> {
    fn default() -> Self {
        DomainTrie { root: Node::new() }
    }
}

impl<T: Clone> DomainTrie<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, domain: &str, data: T) -> Result<(), InvalidDomain> {
        let mut parts = split_domain(domain)?;
        if parts.first().is_some_and(|first| first == "+") {
            self.insert_parts(parts.get(1..).unwrap_or_default(), data.clone());
            if let Some(first) = parts.first_mut() {
                first.clear();
            }
        }
        self.insert_parts(&parts, data);
        Ok(())
    }

    fn insert_parts(&mut self, parts: &[String], data: T) {
        let mut node = &mut self.root;
        for part in parts.iter().rev() {
            node = node.children.entry(part.clone()).or_insert_with(Node::new);
        }
        node.data = Some(data);
    }

    pub fn search(&self, domain: &str) -> Option<&T> {
        if self.root.children.is_empty() {
            return None;
        }
        // 253 is the longest presentation-form name (RFC 1035 section 2.3.4).
        let mut buf = [0u8; 256];
        if let Some(copy) = buf.get_mut(..domain.len()).filter(|_| domain.is_ascii()) {
            copy.copy_from_slice(domain.as_bytes());
            copy.make_ascii_lowercase();
            return self.search_lowered(std::str::from_utf8(copy).ok()?);
        }
        self.search_lowered(&domain.to_lowercase())
    }

    fn search_lowered(&self, lowered: &str) -> Option<&T> {
        validate(lowered).ok()?;
        if lowered.starts_with('.') {
            return None;
        }
        Self::search_node(&self.root, Some(lowered))
    }

    fn search_node<'a>(node: &'a Node<T>, rest: Option<&str>) -> Option<&'a T> {
        let Some(rest) = rest else {
            return node.data.as_ref();
        };
        let (label, rest) = match rest.rsplit_once('.') {
            Some((rest, label)) => (label, Some(rest)),
            None => (rest, None),
        };
        if let Some(child) = node.children.get(label)
            && let Some(found) = Self::search_node(child, rest)
        {
            return Some(found);
        }
        if let Some(child) = node.children.get("*")
            && let Some(found) = Self::search_node(child, rest)
        {
            return Some(found);
        }
        node.children.get("").and_then(|child| child.data.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.root.children.is_empty()
    }
}

/// A set of patterns in the same syntax as the trie.
#[derive(Default)]
pub struct DomainSet {
    trie: DomainTrie<()>,
}

impl DomainSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, pattern: &str) -> Result<(), InvalidDomain> {
        self.trie.insert(pattern, ())
    }

    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }

    pub fn has(&self, domain: &str) -> bool {
        self.trie.search(domain).is_some()
    }
}

impl DomainMatch for DomainSet {
    fn matches(&self, domain: &str) -> bool {
        self.has(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trie(patterns: &[&str]) -> DomainTrie<usize> {
        let mut trie = DomainTrie::new();
        for (index, pattern) in patterns.iter().enumerate() {
            trie.insert(pattern, index).unwrap();
        }
        trie
    }

    #[test]
    fn exact_wildcard_and_plus_patterns() {
        let t = trie(&[
            "www.example.com",
            "*.google.com",
            "+.baidu.com",
            ".qq.com",
            "test.*.example.org",
        ]);
        assert_eq!(t.search("www.example.com"), Some(&0));
        assert_eq!(t.search("example.com"), None);
        assert_eq!(t.search("a.google.com"), Some(&1));
        assert_eq!(t.search("a.b.google.com"), None);
        assert_eq!(t.search("google.com"), None);
        assert_eq!(t.search("baidu.com"), Some(&2));
        assert_eq!(t.search("a.b.baidu.com"), Some(&2));
        assert_eq!(t.search("qq.com"), None);
        assert_eq!(t.search("x.y.qq.com"), Some(&3));
        assert_eq!(t.search("test.zz.example.org"), Some(&4));
        assert_eq!(t.search("WWW.Example.COM"), Some(&0));
    }

    #[test]
    fn static_labels_beat_wildcards() {
        let t = trie(&["*.example.com", "a.example.com", "+.example.com"]);
        assert_eq!(t.search("a.example.com"), Some(&1));
        assert_eq!(t.search("b.example.com"), Some(&0));
        assert_eq!(t.search("x.b.example.com"), Some(&2));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        for bad in [
            "", "a.com.", " a.com", "a.com ", "a..com", "a+.com", "x.+.com", "+", "a*b.com",
        ] {
            assert!(split_domain(bad).is_err(), "{bad:?}");
        }
        let mut t = DomainTrie::<()>::new();
        assert!(t.insert("bad..com", ()).is_err());
    }

    #[test]
    fn a_search_for_a_pattern_form_finds_nothing() {
        let t = trie(&["+.example.com"]);
        assert_eq!(t.search(".example.com"), None);
        assert_eq!(t.search("a..example.com"), None);
    }

    fn long_name(len: usize, suffix: &str) -> String {
        let mut name = String::new();
        let mut remaining = len - suffix.len();
        while remaining > 0 {
            let label = match remaining {
                ..=64 => remaining - 1,
                65 => 61,
                _ => 63,
            };
            name.push_str(&"x".repeat(label));
            name.push('.');
            remaining -= label + 1;
        }
        name.push_str(suffix);
        assert_eq!(name.len(), len);
        name
    }

    #[test]
    fn boundary_names_search_as_the_split_did() {
        let t = trie(&["+.baidu.com", "+.xn--fiqs8s", "+.中国", "äö.example"]);
        assert_eq!(t.search("A.B.BAIDU.COM"), Some(&0));
        assert_eq!(t.search("baidu.com."), None);
        assert_eq!(t.search("www.baidu.com."), None);
        assert_eq!(t.search("a..baidu.com"), None);
        assert_eq!(t.search("..baidu.com"), None);
        assert_eq!(t.search(" baidu.com"), None);
        for len in [255, 256, 257, 300] {
            let name = long_name(len, "baidu.com");
            assert_eq!(t.search(&name), Some(&0), "{len} bytes");
            assert_eq!(
                t.search(&name.to_uppercase()),
                Some(&0),
                "{len} bytes upper"
            );
            assert_eq!(
                t.search(&long_name(len, "baidu.org")),
                None,
                "{len} bytes other"
            );
        }
        assert_eq!(t.search("WWW.XN--FIQS8S"), Some(&1));
        assert_eq!(t.search("xn--fiqs8s"), Some(&1));
        assert_eq!(t.search("www.中国"), Some(&2));
        assert_eq!(t.search("ÄÖ.EXAMPLE"), Some(&3));
        let long_unicode = format!("{}.中国", "ü".repeat(60));
        assert_eq!(t.search(&long_unicode.to_uppercase()), Some(&2));
    }

    #[test]
    fn domain_set_matches_like_the_trie() {
        let mut set = DomainSet::new();
        set.insert("+.lan").unwrap();
        set.insert("time.*.com").unwrap();
        assert!(set.has("router.lan"));
        assert!(set.has("lan"));
        assert!(set.has("time.apple.com"));
        assert!(!set.has("time.a.b.com"));
    }
}
