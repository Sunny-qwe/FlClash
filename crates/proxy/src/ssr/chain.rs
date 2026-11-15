use std::io;
use std::sync::{Arc, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::{Buf, BytesMut};
use concord_common::PacketBuf;

use super::cipher::kdf;
use super::protocol::{Auth, Base, encrypted_auth, first_chunk_len, hmac_md5, le32, rand_bytes};
use crate::util::invalid_data;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ChainKind {
    A,
    B,
}

#[derive(Clone)]
pub(super) struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(super) fn new(key: &[u8]) -> Self {
        let mut state = [0u8; 256];
        for (index, slot) in state.iter_mut().enumerate() {
            *slot = u8::try_from(index).unwrap_or(0);
        }
        let mut j = 0u8;
        for i in 0..256 {
            let key_byte = key.get(i % key.len().max(1)).copied().unwrap_or(0);
            j = j
                .wrapping_add(state.get(i).copied().unwrap_or(0))
                .wrapping_add(key_byte);
            state.swap(i, usize::from(j));
        }
        Rc4 { state, i: 0, j: 0 }
    }

    pub(super) fn apply(&mut self, data: &mut [u8]) {
        for byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self
                .j
                .wrapping_add(self.state.get(usize::from(self.i)).copied().unwrap_or(0));
            self.state.swap(usize::from(self.i), usize::from(self.j));
            let index = self
                .state
                .get(usize::from(self.i))
                .copied()
                .unwrap_or(0)
                .wrapping_add(self.state.get(usize::from(self.j)).copied().unwrap_or(0));
            *byte ^= self.state.get(usize::from(index)).copied().unwrap_or(0);
        }
    }
}

#[derive(Default, Clone)]
pub(super) struct XorShift {
    s0: u64,
    s1: u64,
}

impl XorShift {
    pub(super) fn next(&mut self) -> u64 {
        let mut x = self.s0;
        let y = self.s1;
        self.s0 = y;
        x ^= x << 23;
        x ^= y ^ (x >> 17) ^ (y >> 26);
        self.s1 = x;
        x.wrapping_add(y)
    }

    fn load(&mut self, bin: &[u8]) {
        let mut full = [0u8; 16];
        for (slot, byte) in full.iter_mut().zip(bin) {
            *slot = *byte;
        }
        self.load_array(full);
    }

    fn load_array(&mut self, full: [u8; 16]) {
        let (low, high) = full.split_at(8);
        self.s0 = u64::from_le_bytes(<[u8; 8]>::try_from(low).unwrap_or_default());
        self.s1 = u64::from_le_bytes(<[u8; 8]>::try_from(high).unwrap_or_default());
    }

    pub(super) fn init_from_bin(&mut self, bin: &[u8]) {
        self.load(bin);
    }

    pub(super) fn init_from_bin_and_length(&mut self, bin: &[u8], length: usize) {
        let mut full = [0u8; 16];
        for (slot, byte) in full.iter_mut().zip(bin) {
            *slot = *byte;
        }
        let len = u16::try_from(length).unwrap_or(u16::MAX).to_le_bytes();
        full[..2].copy_from_slice(&len);
        self.load_array(full);
        for _ in 0..4 {
            self.next();
        }
    }
}

fn size_list(rng: &mut XorShift, modulo: u64, add: u64) -> Vec<usize> {
    let count = rng.next() % modulo + add;
    let mut list: Vec<usize> = (0..count)
        .map(|_| usize::try_from(rng.next() % 2340 % 2040 % 1440).unwrap_or(0))
        .collect();
    list.sort_unstable();
    list
}

pub(super) fn data_sizes(key: &[u8]) -> (Vec<usize>, Vec<usize>) {
    let mut rng = XorShift::default();
    rng.init_from_bin(key);
    let first = size_list(&mut rng, 8, 4);
    let second = size_list(&mut rng, 16, 8);
    (first, second)
}

fn start_pos(len: usize, rng: &mut XorShift) -> usize {
    if len == 0 {
        return 0;
    }
    usize::try_from(rng.next() % 8_589_934_609).unwrap_or(0) % len
}

fn rand_len_a(length: usize, hash: &[u8], rng: &mut XorShift) -> usize {
    if length > 1440 {
        return 0;
    }
    rng.init_from_bin_and_length(hash, length);
    tail_len(length, rng)
}

fn tail_len(length: usize, rng: &mut XorShift) -> usize {
    let modulo = if length > 1300 {
        31
    } else if length > 900 {
        127
    } else if length > 400 {
        521
    } else {
        1021
    };
    usize::try_from(rng.next() % modulo).unwrap_or(0)
}

fn rand_len_b(
    sizes: &(Vec<usize>, Vec<usize>),
    overhead: usize,
    length: usize,
    hash: &[u8],
    rng: &mut XorShift,
) -> usize {
    if length >= 1440 {
        return 0;
    }
    rng.init_from_bin_and_length(hash, length);
    let want = length + overhead;
    for (index, list) in [&sizes.0, &sizes.1].into_iter().enumerate() {
        let pos = list.partition_point(|size| *size < want);
        let count = u64::try_from(list.len()).unwrap_or(1).max(1);
        let target = pos + usize::try_from(rng.next() % count).unwrap_or(0);
        if let Some(size) = list.get(target) {
            return size.saturating_sub(want);
        }
        if index == 1 && target < pos + list.len().saturating_sub(1) {
            return 0;
        }
    }
    tail_len(length, rng)
}

pub(super) fn udp_rand_len(hash: &[u8]) -> usize {
    let mut rng = XorShift::default();
    rng.init_from_bin(hash);
    usize::try_from(rng.next() % 127).unwrap_or(0)
}

pub(super) fn rc4_for(user_key: &[u8], hash: &[u8]) -> Rc4 {
    let secret = format!("{}{}", STANDARD.encode(user_key), STANDARD.encode(hash));
    Rc4::new(&kdf(secret.as_bytes(), 16))
}

/// One direction of a chain connection: its running hash, length generator, counter and keystream.
#[derive(Clone)]
pub(super) struct Half {
    pub(super) hash: [u8; 16],
    pub(super) rng: XorShift,
    pub(super) id: u32,
    pub(super) rc4: Rc4,
}

impl Half {
    fn new() -> Self {
        Half {
            hash: [0; 16],
            rng: XorShift::default(),
            id: 1,
            rc4: Rc4::new(&[]),
        }
    }
}

/// What the first write seeds the read direction with.
struct RxSeed {
    hash: [u8; 16],
    rc4_hash: [u8; 16],
}

#[derive(Clone)]
pub(super) struct Chain {
    pub(super) kind: ChainKind,
    pub(super) sizes: Option<(Vec<usize>, Vec<usize>)>,
    pub(super) key: Vec<u8>,
    pub(super) overhead: usize,
    pub(super) user_key: Vec<u8>,
    pub(super) user_id: [u8; 4],
    pub(super) iv: Vec<u8>,
    pub(super) auth: Auth,
    pub(super) now: u32,
    pub(super) salt: &'static str,
    pub(super) sent_header: bool,
    pub(super) raw: bool,
    pub(super) tx: Half,
    pub(super) rx: Half,
    /// The server's first frame carries two bytes in front of its payload.
    pub(super) server: bool,
    /// Set on a split stream until the read half has taken the seed the write half derives.
    seed: Option<Arc<OnceLock<RxSeed>>>,
}

impl Chain {
    #[allow(
        clippy::too_many_arguments,
        reason = "every field comes from a different source"
    )]
    pub(super) fn new(
        kind: ChainKind,
        base: &Base,
        user_key: &[u8],
        user_id: [u8; 4],
        iv: Vec<u8>,
        auth: Auth,
        now: u32,
        sizes: Option<(Vec<usize>, Vec<usize>)>,
    ) -> Self {
        Chain {
            kind,
            sizes,
            key: base.key.clone(),
            overhead: base.overhead,
            user_key: user_key.to_vec(),
            user_id,
            iv,
            auth,
            now,
            salt: if kind == ChainKind::A {
                "auth_chain_a"
            } else {
                "auth_chain_b"
            },
            sent_header: false,
            raw: false,
            tx: Half::new(),
            rx: Half::new(),
            server: false,
            seed: None,
        }
    }

    pub(super) fn split(self: Box<Self>) -> (Box<Chain>, Box<Chain>) {
        let mut decode = self.clone();
        let mut encode = self;
        if !encode.sent_header {
            let seed = Arc::new(OnceLock::new());
            decode.seed = Some(seed.clone());
            encode.seed = Some(seed);
        }
        (decode, encode)
    }

    fn rand_len(
        kind: ChainKind,
        sizes: Option<&(Vec<usize>, Vec<usize>)>,
        overhead: usize,
        length: usize,
        half: &mut Half,
    ) -> usize {
        match (kind, sizes) {
            (ChainKind::B, Some(sizes)) => {
                rand_len_b(sizes, overhead, length, &half.hash, &mut half.rng)
            }
            _ => rand_len_a(length, &half.hash, &mut half.rng),
        }
    }

    pub(super) fn encode(&mut self, out: &mut Vec<u8>, mut data: &[u8]) {
        if !self.sent_header {
            let take = first_chunk_len(data);
            let (head, rest) = data.split_at(take);
            self.pack_auth_data(out, head);
            data = rest;
            self.sent_header = true;
        }
        while data.len() > 2800 {
            let (chunk, rest) = data.split_at(2800);
            self.pack_data(out, chunk);
            data = rest;
        }
        if !data.is_empty() {
            self.pack_data(out, data);
        }
    }

    fn pack_auth_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let start = out.len();
        rand_bytes(out, 4);
        self.tx.hash = hmac_md5(&mac_key, out.get(start..).unwrap_or_default());
        self.tx.rc4 = rc4_for(&self.user_key, &self.tx.hash);
        self.rx.rc4 = rc4_for(&self.user_key, &self.tx.hash);
        out.extend_from_slice(self.tx.hash.get(..8).unwrap_or_default());
        let uid = le32(&self.user_id) ^ le32(self.tx.hash.get(8..12).unwrap_or_default());
        out.extend_from_slice(&uid.to_le_bytes());
        out.extend_from_slice(&encrypted_auth(
            &self.user_key,
            self.auth,
            self.now,
            (self.overhead, 0),
            self.salt,
        ));
        self.rx.hash = hmac_md5(&self.user_key, out.get(start + 12..).unwrap_or_default());
        out.extend_from_slice(self.rx.hash.get(..4).unwrap_or_default());
        if let Some(seed) = &self.seed {
            let _ = seed.set(RxSeed {
                hash: self.rx.hash,
                rc4_hash: self.tx.hash,
            });
        }
        self.pack_data(out, data);
    }

    fn pack_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let mut sealed = Vec::with_capacity(data.len() + 2);
        if self.server && self.tx.id == 1 {
            sealed.extend_from_slice(&[0, 0]);
        }
        sealed.extend_from_slice(data);
        self.tx.rc4.apply(&mut sealed);
        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.tx.id.to_le_bytes());
        self.tx.id = self.tx.id.wrapping_add(1);
        let masked = u16::try_from(sealed.len()).unwrap_or(u16::MAX)
            ^ u16::from_le_bytes([self.tx.hash[14], self.tx.hash[15]]);
        let start = out.len();
        out.extend_from_slice(&masked.to_le_bytes());
        let rand_len = Self::rand_len(
            self.kind,
            self.sizes.as_ref(),
            self.overhead,
            sealed.len(),
            &mut self.tx,
        );
        if sealed.is_empty() {
            rand_bytes(out, rand_len);
        } else if rand_len > 0 {
            let before = start_pos(rand_len, &mut self.tx.rng);
            rand_bytes(out, before);
            out.extend_from_slice(&sealed);
            rand_bytes(out, rand_len - before);
        } else {
            out.extend_from_slice(&sealed);
        }
        self.tx.hash = hmac_md5(&mac_key, out.get(start..).unwrap_or_default());
        out.extend_from_slice(self.tx.hash.get(..2).unwrap_or_default());
    }

    pub(super) fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
    ) -> io::Result<()> {
        if self.raw {
            decoded.extend_from_slice(input);
            input.clear();
            return Ok(());
        }
        if let Some(seed) = self.seed.as_ref().and_then(|seed| seed.get()) {
            self.rx.hash = seed.hash;
            self.rx.rc4 = rc4_for(&self.user_key, &seed.rc4_hash);
            self.seed = None;
        }
        while input.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.rx.id.to_le_bytes());
            let mask = u16::from_le_bytes([self.rx.hash[14], self.rx.hash[15]]);
            let data_len = usize::from(
                u16::from_le_bytes([
                    input.first().copied().unwrap_or(0),
                    input.get(1).copied().unwrap_or(0),
                ]) ^ mask,
            );
            let rand_len = Self::rand_len(
                self.kind,
                self.sizes.as_ref(),
                self.overhead,
                data_len,
                &mut self.rx,
            );
            let length = data_len + rand_len;
            if length >= 4096 {
                self.raw = true;
                input.clear();
                return Err(invalid_data("auth_chain decode data wrong length"));
            }
            if 4 + length > input.len() {
                break;
            }
            let hash = hmac_md5(&mac_key, input.get(..length + 2).unwrap_or_default());
            if hash.get(..2) != input.get(length + 2..length + 4) {
                self.raw = true;
                input.clear();
                return Err(invalid_data("auth_chain decode data wrong checksum"));
            }
            self.rx.hash = hash;
            let mut pos = 2;
            if data_len > 0 && rand_len > 0 {
                pos += start_pos(rand_len, &mut self.rx.rng);
            }
            let Some(wanted) = input.get_mut(pos..pos + data_len) else {
                input.clear();
                return Err(invalid_data("auth_chain decode data wrong length"));
            };
            self.rx.rc4.apply(wanted);
            let payload = if self.rx.id == 1 && !self.server {
                wanted.get(2..).unwrap_or_default()
            } else {
                &*wanted
            };
            decoded.extend_from_slice(payload);
            self.rx.id = self.rx.id.wrapping_add(1);
            input.advance(length + 4);
        }
        Ok(())
    }
}

pub(super) fn chain_seal_packet(
    key: &[u8],
    user_key: &[u8],
    user_id: [u8; 4],
    pkt: &mut PacketBuf,
) {
    let mut auth = [0u8; 3];
    rand::fill(&mut auth[..]);
    let md5 = hmac_md5(key, &auth);
    let rand_len = udp_rand_len(&md5);
    rc4_for(user_key, &md5).apply(pkt.as_mut_slice());
    let mut padding = Vec::new();
    rand_bytes(&mut padding, rand_len);
    pkt.extend_from_slice(&padding);
    pkt.extend_from_slice(&auth);
    let uid = le32(&user_id) ^ le32(md5.get(..4).unwrap_or_default());
    pkt.extend_from_slice(&uid.to_le_bytes());
    let mac = hmac_md5(user_key, pkt.as_slice());
    pkt.extend_from_slice(mac.get(..1).unwrap_or_default());
}

pub(super) fn chain_open_packet(
    key: &[u8],
    user_key: &[u8],
    pkt: &mut PacketBuf,
) -> io::Result<()> {
    let len = pkt.len();
    if len < 9 {
        return Err(invalid_data("auth_chain decode data wrong length"));
    }
    let data = pkt.as_slice();
    let mac = hmac_md5(user_key, data.get(..len - 1).unwrap_or_default());
    if mac.get(..1) != data.get(len - 1..) {
        return Err(invalid_data("auth_chain decode data wrong checksum"));
    }
    let md5 = hmac_md5(key, data.get(len - 8..len - 1).unwrap_or_default());
    let rand_len = udp_rand_len(&md5);
    let wanted = len
        .checked_sub(8 + rand_len)
        .ok_or_else(|| invalid_data("auth_chain decode data wrong length"))?;
    pkt.truncate(wanted);
    rc4_for(user_key, &md5).apply(pkt.as_mut_slice());
    Ok(())
}
