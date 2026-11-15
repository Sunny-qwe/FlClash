use std::borrow::Cow;
use std::collections::VecDeque;

use super::hpack_tables::{HUFFMAN_CODES, HUFFMAN_LENS, STATIC_TABLE};

const LEAF: u16 = 0x8000;

/// A binary trie over the HPACK code: `0` marks a missing child (the EOS path),
/// `LEAF | symbol` a leaf, anything else the index of an inner node.
const HUFFMAN_TREE: [[u16; 2]; 512] = build_huffman_tree();

#[allow(
    clippy::indexing_slicing,
    reason = "const evaluation: an out-of-range index is a compile error"
)]
const fn build_huffman_tree() -> [[u16; 2]; 512] {
    let mut nodes = [[0u16; 2]; 512];
    let mut count = 1usize;
    let mut symbol = 0usize;
    while symbol < 256 {
        let code = HUFFMAN_CODES[symbol];
        let len = HUFFMAN_LENS[symbol] as u32;
        let mut current = 0usize;
        let mut bit_index = 0;
        while bit_index < len {
            let bit = ((code >> (len - 1 - bit_index)) & 1) as usize;
            if bit_index == len - 1 {
                nodes[current][bit] = LEAF | symbol as u16;
            } else {
                if nodes[current][bit] == 0 {
                    nodes[current][bit] = count as u16;
                    count += 1;
                }
                current = nodes[current][bit] as usize;
            }
            bit_index += 1;
        }
        symbol += 1;
    }
    nodes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DecodeError;

enum Fail {
    NeedMore,
    Invalid,
}

impl From<DecodeError> for Fail {
    fn from(_: DecodeError) -> Self {
        Fail::Invalid
    }
}

/// Decodes a string coded with the HPACK Huffman table (RFC 7541 section 5.2).
pub(super) fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(input.len() * 3 / 2);
    let mut node = 0usize;
    let mut bits_since_symbol = 0u32;
    let mut padding_is_ones = true;
    for &byte in input {
        for shift in (0..8).rev() {
            let bit = usize::from((byte >> shift) & 1);
            let child = HUFFMAN_TREE
                .get(node)
                .and_then(|children| children.get(bit))
                .copied()
                .unwrap_or(0);
            bits_since_symbol += 1;
            padding_is_ones &= bit == 1;
            if child == 0 {
                return Err(DecodeError);
            }
            if child & LEAF != 0 {
                out.push((child & 0xff) as u8);
                node = 0;
                bits_since_symbol = 0;
                padding_is_ones = true;
            } else {
                node = usize::from(child);
            }
        }
    }
    // Trailing bits must be at most seven and a prefix of EOS (all ones).
    if bits_since_symbol > 7 || !padding_is_ones {
        return Err(DecodeError);
    }
    Ok(out)
}

/// An incremental header block decoder holding the RFC 7541 dynamic table.
/// Fields reach `emit` as soon as they are complete, so a caller can stop
/// reading a block once it has what it came for.
pub(super) struct Decoder {
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
    allowed_max_size: usize,
    saved: Vec<u8>,
    first_field: bool,
}

impl Decoder {
    pub(super) fn new(max_dynamic_table_size: usize) -> Self {
        Decoder {
            table: VecDeque::new(),
            size: 0,
            max_size: max_dynamic_table_size,
            allowed_max_size: max_dynamic_table_size,
            saved: Vec::new(),
            first_field: true,
        }
    }

    /// Feeds the next fragment of a header block. An incomplete trailing field
    /// is kept for the next call.
    pub(super) fn write(
        &mut self,
        fragment: &[u8],
        mut emit: impl FnMut(&[u8], &[u8]),
    ) -> Result<(), DecodeError> {
        if fragment.is_empty() {
            return Ok(());
        }
        let joined;
        let mut buf = if self.saved.is_empty() {
            fragment
        } else {
            let mut data = std::mem::take(&mut self.saved);
            data.extend_from_slice(fragment);
            joined = data;
            joined.as_slice()
        };

        while !buf.is_empty() {
            match self.parse_representation(buf, &mut emit) {
                Ok(rest) => {
                    self.first_field = false;
                    buf = rest;
                }
                Err(Fail::NeedMore) => {
                    self.saved = buf.to_vec();
                    return Ok(());
                }
                Err(Fail::Invalid) => {
                    self.first_field = false;
                    return Err(DecodeError);
                }
            }
        }
        Ok(())
    }

    fn field(&self, index: u64) -> Option<(&[u8], &[u8])> {
        let index = usize::try_from(index).ok()?.checked_sub(1)?;
        match STATIC_TABLE.get(index) {
            Some(&(name, value)) => Some((name.as_bytes(), value.as_bytes())),
            None => {
                let (name, value) = self.table.get(index - STATIC_TABLE.len())?;
                Some((name.as_slice(), value.as_slice()))
            }
        }
    }

    fn parse_representation<'a>(
        &mut self,
        buf: &'a [u8],
        emit: &mut impl FnMut(&[u8], &[u8]),
    ) -> Result<&'a [u8], Fail> {
        let Some(&first) = buf.first() else {
            return Err(Fail::NeedMore);
        };
        if first & 0x80 != 0 {
            let (index, rest) = read_var_int(7, buf)?;
            let (name, value) = self.field(index).ok_or(Fail::Invalid)?;
            emit(name, value);
            Ok(rest)
        } else if first & 0xc0 == 0x40 {
            self.parse_literal(buf, 6, true, emit)
        } else if first & 0xf0 == 0x00 || first & 0xf0 == 0x10 {
            self.parse_literal(buf, 4, false, emit)
        } else if first & 0xe0 == 0x20 {
            self.parse_size_update(buf)
        } else {
            Err(Fail::Invalid)
        }
    }

    fn parse_literal<'a>(
        &mut self,
        buf: &'a [u8],
        prefix_bits: u8,
        indexed: bool,
        emit: &mut impl FnMut(&[u8], &[u8]),
    ) -> Result<&'a [u8], Fail> {
        let (name_index, mut rest) = read_var_int(prefix_bits, buf)?;
        let mut name_raw = None;
        let mut name = Vec::new();
        if name_index > 0 {
            name = self.field(name_index).ok_or(Fail::Invalid)?.0.to_vec();
        } else {
            let (raw, after) = read_string(rest)?;
            name_raw = Some(raw);
            rest = after;
        }
        let (value_raw, rest) = read_string(rest)?;

        if let Some(raw) = name_raw {
            name = raw.decode()?.into_owned();
        }
        let value = value_raw.decode()?;
        emit(&name, &value);
        if indexed {
            self.add(name, value.into_owned());
        }
        Ok(rest)
    }

    fn parse_size_update<'a>(&mut self, buf: &'a [u8]) -> Result<&'a [u8], Fail> {
        // RFC 7541 section 4.2: only at the beginning of a header block.
        if !self.first_field && self.size > 0 {
            return Err(Fail::Invalid);
        }
        let (size, rest) = read_var_int(5, buf)?;
        let size = usize::try_from(size).map_err(|_| Fail::Invalid)?;
        if size > self.allowed_max_size {
            return Err(Fail::Invalid);
        }
        self.max_size = size;
        self.evict();
        Ok(rest)
    }

    fn add(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.size += name.len() + value.len() + 32;
        self.table.push_front((name, value));
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            let Some((name, value)) = self.table.pop_back() else {
                break;
            };
            self.size -= name.len() + value.len() + 32;
        }
    }

    #[cfg(test)]
    pub(super) fn dynamic_table(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.table.iter().cloned().collect()
    }

    #[cfg(test)]
    pub(super) fn dynamic_size(&self) -> usize {
        self.size
    }
}

struct RawString<'a> {
    huffman: bool,
    bytes: &'a [u8],
}

impl<'a> RawString<'a> {
    fn decode(&self) -> Result<Cow<'a, [u8]>, DecodeError> {
        if self.huffman {
            huffman_decode(self.bytes).map(Cow::Owned)
        } else {
            Ok(Cow::Borrowed(self.bytes))
        }
    }
}

fn read_string(p: &[u8]) -> Result<(RawString<'_>, &[u8]), Fail> {
    let Some(&first) = p.first() else {
        return Err(Fail::NeedMore);
    };
    let (len, rest) = read_var_int(7, p)?;
    let len = usize::try_from(len).map_err(|_| Fail::Invalid)?;
    if rest.len() < len {
        return Err(Fail::NeedMore);
    }
    let (bytes, rest) = rest.split_at(len);
    Ok((
        RawString {
            huffman: first & 0x80 != 0,
            bytes,
        },
        rest,
    ))
}

/// RFC 7541 section 5.1.
fn read_var_int(prefix_bits: u8, p: &[u8]) -> Result<(u64, &[u8]), Fail> {
    let Some((&first, mut rest)) = p.split_first() else {
        return Err(Fail::NeedMore);
    };
    let max_prefix = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & max_prefix;
    if value < max_prefix {
        return Ok((value, rest));
    }
    let mut shift = 0u32;
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        value = value.wrapping_add(u64::from(byte & 0x7f) << shift);
        if byte & 0x80 == 0 {
            return Ok((value, rest));
        }
        shift += 7;
        if shift >= 63 {
            return Err(Fail::Invalid);
        }
    }
    Err(Fail::NeedMore)
}

#[cfg(test)]
#[path = "hpack_tests.rs"]
mod tests;
