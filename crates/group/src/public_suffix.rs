//! The registrable domain of a host, from the public suffix list in golang.org/x/net/publicsuffix's
//! table layout and lookup (v0.35.0 `list.go`). `cargo xtask public-suffix` writes the table from
//! `data/public-suffix/public_suffix_list.dat`; see `xtask/src/public_suffix.rs` for how it differs.

use std::cmp::Ordering;

static TEXT: &[u8] = include_bytes!("../data/public-suffix/text");
static NODES: &[u8] = include_bytes!("../data/public-suffix/nodes");
static CHILDREN: &[u8] = include_bytes!("../data/public-suffix/children");
/// The top-level nodes whose label starts with each byte: `TLDS[b]..TLDS[b + 1]`.
static TLDS: [u16; 257] = tlds_by_first_byte();

// The layout `xtask/src/public_suffix.rs` writes; both sides change together.
const NODE_BYTES: usize = 5;
const TEXT_LENGTH_BITS: u32 = 6;
const TEXT_OFFSET_BITS: u32 = 16;
const CHILDREN_INDEX_BITS: u32 = 11;
const LO_BITS: u32 = 14;
const HI_BITS: u32 = 14;
const NODE_TYPE_BITS: u32 = 2;
const NORMAL: u32 = 0;
const EXCEPTION: u32 = 1;

/// Go's `publicsuffix.EffectiveTLDPlusOne`: the full public suffix list with
/// its private section, `*` for unknown TLDs, and no answer for a host that is
/// itself a suffix or that has an empty label or a trailing dot.
pub(crate) fn registrable_domain(host: &str) -> Option<String> {
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return None;
    }
    let suffix = suffix_start(host.as_bytes())?;
    let head = host.get(..suffix.checked_sub(1)?)?;
    let start = head.rfind('.').map_or(0, |dot| dot + 1);
    Some(host.get(start..)?.to_ascii_lowercase())
}

/// Where the public suffix of `host` starts, matching labels without regard to ASCII case.
fn suffix_start(host: &[u8]) -> Option<usize> {
    let first = host
        .get(label_start(host))
        .map_or(0, u8::to_ascii_lowercase) as usize;
    let (mut lo, mut hi) = (
        u32::from(*TLDS.get(first)?),
        u32::from(*TLDS.get(first + 1)?),
    );
    let (mut rest, mut suffix, mut wildcard) = (host.len(), host.len(), false);
    loop {
        let name = host.get(..rest)?;
        let start = label_start(name);
        if wildcard {
            suffix = start;
        }
        let Some(node) = find(name.get(start..)?, lo, hi) else {
            break;
        };
        let children = entry(
            (node >> (TEXT_OFFSET_BITS + TEXT_LENGTH_BITS)) as u32 & mask(CHILDREN_INDEX_BITS),
        )?;
        (lo, hi) = range(children);
        match (children >> (LO_BITS + HI_BITS)) & mask(NODE_TYPE_BITS) {
            NORMAL => suffix = start,
            EXCEPTION => return Some(rest + 1),
            _ => {}
        }
        wildcard = children >> (LO_BITS + HI_BITS + NODE_TYPE_BITS) & 1 != 0;
        if start == 0 {
            break;
        }
        rest = start - 1;
    }
    Some(if suffix == host.len() {
        label_start(host)
    } else {
        suffix
    })
}

fn label_start(name: &[u8]) -> usize {
    name.iter()
        .rposition(|&byte| byte == b'.')
        .map_or(0, |dot| dot + 1)
}

fn find(label: &[u8], mut lo: u32, mut hi: u32) -> Option<u64> {
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let node = node(mid)?;
        let length = (node & u64::from(mask(TEXT_LENGTH_BITS))) as usize;
        let offset = (node >> TEXT_LENGTH_BITS & u64::from(mask(TEXT_OFFSET_BITS))) as usize;
        let text = TEXT.get(offset..offset + length)?;
        match text
            .iter()
            .copied()
            .cmp(label.iter().map(u8::to_ascii_lowercase))
        {
            Ordering::Less => lo = mid + 1,
            Ordering::Equal => return Some(node),
            Ordering::Greater => hi = mid,
        }
    }
    None
}

fn node(index: u32) -> Option<u64> {
    let at = index as usize * NODE_BYTES;
    let bytes = NODES.get(at..at + NODE_BYTES)?;
    Some(
        bytes
            .iter()
            .fold(0, |value, &byte| value << 8 | u64::from(byte)),
    )
}

fn entry(index: u32) -> Option<u32> {
    let at = index as usize * 4;
    Some(u32::from_be_bytes(
        CHILDREN.get(at..at + 4)?.try_into().ok()?,
    ))
}

fn range(entry: u32) -> (u32, u32) {
    (entry & mask(LO_BITS), entry >> LO_BITS & mask(HI_BITS))
}

#[allow(
    clippy::indexing_slicing,
    reason = "evaluated at compile time, where an index out of range fails the build"
)]
const fn tlds_by_first_byte() -> [u16; 257] {
    let root = u32::from_be_bytes([CHILDREN[0], CHILDREN[1], CHILDREN[2], CHILDREN[3]]);
    let count = (root >> LO_BITS & mask(HI_BITS)) as usize;
    let mut tlds = [0; 257];
    let (mut byte, mut tld) = (0, 0);
    while byte < tlds.len() {
        while tld < count && (first_byte(tld) as usize) < byte {
            tld += 1;
        }
        tlds[byte] = tld as u16;
        byte += 1;
    }
    tlds
}

#[allow(
    clippy::indexing_slicing,
    reason = "evaluated at compile time, where an index out of range fails the build"
)]
const fn first_byte(node: usize) -> u8 {
    let at = node * NODE_BYTES;
    let text = u32::from_be_bytes([NODES[at + 1], NODES[at + 2], NODES[at + 3], NODES[at + 4]]);
    TEXT[(text >> TEXT_LENGTH_BITS & mask(TEXT_OFFSET_BITS)) as usize]
}

const fn mask(bits: u32) -> u32 {
    (1 << bits) - 1
}
