//! `xtask public-suffix`: writes the public suffix table `concord-group` looks registrable domains up
//! in, from the upstream list in `crates/group/data/public-suffix/`.
//!
//! The layout is golang.org/x/net/publicsuffix's (v0.35.0 `gen.go`) with two changes: the ICANN
//! bit, which no caller reads, goes to the children index, and an internationalised rule is kept
//! in its Unicode form beside its Punycode one, as the `psl` crate matches both.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

// The reader is `crates/group/src/public_suffix.rs`; both sides change together.
const TEXT_LENGTH_BITS: u32 = 6;
const TEXT_OFFSET_BITS: u32 = 16;
const CHILDREN_INDEX_BITS: u32 = 11;
const LO_BITS: u32 = 14;
const HI_BITS: u32 = 14;
const NODE_TYPE_BITS: u32 = 2;
const NODE_BYTES: u32 = 5;
const LEAF_KINDS: u32 = 3;

const LIST: &str = "public_suffix_list.dat";
const OUTPUTS: [&str; 3] = ["text", "nodes", "children"];

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/group/data/public-suffix")
}

pub fn run() -> Result<(), String> {
    let dir = data_dir();
    let list = fs::read_to_string(dir.join(LIST)).map_err(|err| format!("{LIST}: {err}"))?;
    for (name, bytes) in OUTPUTS.into_iter().zip(generate(&list)?) {
        let path = dir.join(name);
        fs::write(&path, bytes).map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Normal = 0,
    Exception = 1,
    ParentOnly = 2,
}

struct Node {
    children: BTreeMap<String, Node>,
    kind: Kind,
    wildcard: bool,
    children_index: u32,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            children: BTreeMap::new(),
            kind: Kind::ParentOnly,
            wildcard: false,
            children_index: 0,
        }
    }
}

/// The `text`, `nodes` and `children` files for a list in publicsuffix.org's format.
fn generate(list: &str) -> Result<[Vec<u8>; 3], String> {
    let mut root = tree(list)?;
    let mut labels = Vec::new();
    collect_labels(&root, &mut labels);
    labels.sort_unstable();
    labels.dedup();
    let text = crush(remove_substrings(
        &labels.iter().map(String::as_str).collect::<Vec<_>>(),
    ));
    let mut offsets = BTreeMap::new();
    for label in labels {
        let offset = text
            .find(&label)
            .ok_or_else(|| format!("label {label:?} missing from text"))?;
        check("text offset", offset, TEXT_OFFSET_BITS)?;
        check("text length", label.len(), TEXT_LENGTH_BITS)?;
        let encoding = ((offset as u64) << TEXT_LENGTH_BITS) | label.len() as u64;
        offsets.insert(label, encoding);
    }
    let mut children = vec![0; 1 + 2 * LEAF_KINDS as usize];
    for kind in 0..LEAF_KINDS {
        children[1 + kind as usize] = kind << (LO_BITS + HI_BITS);
        children[1 + (LEAF_KINDS + kind) as usize] =
            ((1 << NODE_TYPE_BITS) | kind) << (LO_BITS + HI_BITS);
    }
    assign(&mut root, &mut 0, &mut children, true)?;
    let mut nodes = Vec::new();
    encode_nodes(&root, &offsets, &mut nodes);
    let children = children.into_iter().flat_map(u32::to_be_bytes).collect();
    Ok([text.into_bytes(), nodes, children])
}

/// The rule tree: each rule under its labels, last first, an internationalised one twice.
fn tree(list: &str) -> Result<Node, String> {
    let mut root = Node::default();
    for rule in list
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
    {
        let (kind, wildcard, name) = if let Some(name) = rule.strip_prefix("*.") {
            (Kind::ParentOnly, true, name)
        } else if let Some(name) = rule.strip_prefix('!') {
            (Kind::Exception, false, name)
        } else {
            (Kind::Normal, false, rule)
        };
        if name.contains(['*', '!']) {
            return Err(format!(
                "{LIST}: rule {rule:?} has `*` or `!` inside a label"
            ));
        }
        let ascii = to_ascii(name)?;
        if !ascii
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.".contains(&b))
        {
            return Err(format!("{LIST}: rule {rule:?} is not in canonical form"));
        }
        if ascii != name {
            insert(&mut root, kind, wildcard, name)?;
        }
        insert(&mut root, kind, wildcard, &ascii)?;
    }
    Ok(root)
}

fn to_ascii(name: &str) -> Result<String, String> {
    if name.is_ascii() {
        return Ok(name.to_owned());
    }
    if name.to_lowercase() != name {
        return Err(format!("{LIST}: rule {name:?} is not lowercase"));
    }
    let labels: Option<Vec<String>> = name
        .split('.')
        .map(|label| match label.is_ascii() {
            true => Some(label.to_owned()),
            false => idna::punycode::encode_str(label).map(|encoded| format!("xn--{encoded}")),
        })
        .collect();
    labels
        .map(|labels| labels.join("."))
        .ok_or_else(|| format!("{LIST}: cannot encode {name:?}"))
}

fn insert(root: &mut Node, kind: Kind, wildcard: bool, name: &str) -> Result<(), String> {
    if kind == Kind::Exception && !name.contains('.') {
        return Err(format!("{LIST}: exception {name:?} has a single label"));
    }
    let mut node = root;
    for label in name.rsplit('.') {
        if label.is_empty() {
            return Err(format!("{LIST}: rule {name:?} has an empty label"));
        }
        node = node.children.entry(label.to_owned()).or_default();
    }
    if kind != Kind::ParentOnly && node.kind == Kind::ParentOnly {
        node.kind = kind;
    }
    node.wildcard |= wildcard;
    Ok(())
}

fn collect_labels(node: &Node, out: &mut Vec<String>) {
    for (label, child) in &node.children {
        out.push(label.clone());
        collect_labels(child, out);
    }
}

/// Numbers each node's children in pre-order, as x/net's `assignIndexes` does. The root's range is
/// `children[0]`; a leaf points at one of the six entries after it, by node type and wildcard bit.
fn assign(
    node: &mut Node,
    next: &mut u32,
    children: &mut Vec<u32>,
    root: bool,
) -> Result<(), String> {
    if node.children.is_empty() {
        node.children_index = 1 + node.kind as u32 + if node.wildcard { LEAF_KINDS } else { 0 };
        return Ok(());
    }
    let lo = *next;
    *next += node.children.len() as u32;
    check("children lo", lo as usize, LO_BITS)?;
    check("children hi", *next as usize, HI_BITS)?;
    let mut entry = (*next << LO_BITS) | lo;
    if root {
        children[0] = entry;
    } else {
        entry |= (node.kind as u32) << (LO_BITS + HI_BITS);
        if node.wildcard {
            entry |= 1 << (LO_BITS + HI_BITS + NODE_TYPE_BITS);
        }
        check("children index", children.len(), CHILDREN_INDEX_BITS)?;
        node.children_index = children.len() as u32;
        children.push(entry);
    }
    for child in node.children.values_mut() {
        assign(child, next, children, false)?;
    }
    Ok(())
}

fn encode_nodes(node: &Node, offsets: &BTreeMap<String, u64>, out: &mut Vec<u8>) {
    for (label, child) in &node.children {
        let encoding = offsets[label.as_str()]
            | u64::from(child.children_index) << (TEXT_OFFSET_BITS + TEXT_LENGTH_BITS);
        out.extend_from_slice(&encoding.to_be_bytes()[8 - NODE_BYTES as usize..]);
    }
    for child in node.children.values() {
        encode_nodes(child, offsets, out);
    }
}

fn check(what: &str, value: usize, bits: u32) -> Result<(), String> {
    if value >> bits == 0 {
        Ok(())
    } else {
        Err(format!(
            "{what} {value} does not fit in {bits} bits; widen the table layout"
        ))
    }
}

/// The labels that are not substrings of a longer one, in byte order (x/net `removeSubstrings`).
fn remove_substrings(labels: &[&str]) -> Vec<String> {
    let mut inner = HashSet::new();
    for label in labels.iter().map(|label| label.as_bytes()) {
        for start in 0..label.len() {
            for end in start + 1..=label.len() {
                if end - start < label.len() {
                    inner.insert(&label[start..end]);
                }
            }
        }
    }
    let mut kept: Vec<String> = labels
        .iter()
        .filter(|label| !inner.contains(label.as_bytes()))
        .map(|label| (*label).to_owned())
        .collect();
    kept.sort_unstable();
    kept
}

/// Joins the labels into one string, overlapping a label's end with another's start, longest
/// overlap first (x/net `crush`).
fn crush(mut labels: Vec<String>) -> String {
    let longest = labels.iter().map(String::len).max().unwrap_or(0);
    for overlap in (1..=longest).rev() {
        let mut starts: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        for (index, label) in labels.iter().enumerate() {
            if overlap < label.len() {
                starts
                    .entry(label.as_bytes()[..overlap].to_vec())
                    .or_default()
                    .push(index);
            }
        }
        for index in 0..labels.len() {
            if labels[index].len() > overlap {
                merge(&mut labels, index, overlap, &starts);
            }
        }
    }
    labels.concat()
}

fn merge(
    labels: &mut [String],
    index: usize,
    overlap: usize,
    starts: &BTreeMap<Vec<u8>, Vec<usize>>,
) {
    loop {
        let label = labels[index].as_bytes();
        let end = &label[label.len() - overlap..];
        let Some(&other) = starts.get(end).and_then(|candidates| {
            candidates
                .iter()
                .find(|&&other| other != index && !labels[other].is_empty())
        }) else {
            return;
        };
        let tail = labels[other].as_bytes()[overlap..].to_vec();
        labels[other].clear();
        let mut merged = std::mem::take(&mut labels[index]).into_bytes();
        merged.extend_from_slice(&tail);
        labels[index] = String::from_utf8(merged).expect("merged at a shared prefix");
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn the_committed_table_is_generated_from_the_pinned_list() {
        let dir = data_dir();
        let list = fs::read(dir.join(LIST)).expect("list");
        let version = fs::read_to_string(dir.join("VERSION")).expect("VERSION");
        let pinned = version
            .lines()
            .find_map(|line| line.strip_prefix("sha256 "))
            .expect("VERSION names the list's sha256");
        let digest: String = Sha256::digest(&list)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest, pinned,
            "{LIST} differs from the revision VERSION pins"
        );
        let generated =
            generate(std::str::from_utf8(&list).expect("UTF-8 list")).expect("generate");
        for (name, bytes) in OUTPUTS.into_iter().zip(generated) {
            let committed = fs::read(dir.join(name)).expect("committed table");
            assert!(
                committed == bytes,
                "{name} is stale: run `cargo xtask public-suffix`"
            );
        }
    }

    #[test]
    fn an_internationalised_exception_stays_an_exception_in_both_forms() {
        let root = tree("*.example\n!ü.example\n").expect("tree");
        let example = &root.children["example"];
        assert!(example.wildcard);
        for label in ["ü", "xn--tda"] {
            assert_eq!(example.children[label].kind, Kind::Exception, "{label}");
        }
    }

    #[test]
    fn a_wildcard_or_bang_inside_a_label_is_refused() {
        for rule in ["a*b.example", "ü!.example", "!a.!b.example", "*.ü*.example"] {
            assert!(tree(rule).is_err(), "{rule}");
        }
    }

    #[test]
    fn text_overlaps_labels_and_keeps_each_one() {
        let labels = ["arpa", "parliament", "par", "zz"];
        let kept = remove_substrings(&labels);
        assert_eq!(kept, ["arpa", "parliament", "zz"]);
        let text = crush(kept);
        assert_eq!(text, "arparliamentzz");
    }
}
