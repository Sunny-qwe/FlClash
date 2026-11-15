use std::sync::Arc;
use std::time::Duration;

use super::bitmap::Bitmap;
use super::dispatcher::{Policy, SniffTarget, replace_domain};
use super::error::SniffError;
use super::quic_crypto::{InitialKey, VERSIONS, Version, decrypt_initial};
use super::tls::{HANDSHAKE_HEADER_LEN, client_hello_size, read_client_hello};

/// How long the caller waits for all fragments before routing without a domain.
pub const QUIC_WAIT: Duration = Duration::from_secs(3);

/// A resource policy sharing the 64 KiB TCP budget, not a protocol limit.
const MAX_CRYPTO_STREAM_OFFSET: usize = 64 * 1024;

const FRAME_PADDING: u8 = 0x00;
const FRAME_PING: u8 = 0x01;
const FRAME_ACK: u8 = 0x02;
const FRAME_ACK_WITH_ECN: u8 = 0x03;
const FRAME_CRYPTO: u8 = 0x06;
const FRAME_CONNECTION_CLOSE: u8 = 0x1c;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.bytes(len - 1)? {
            value = value << 8 | u64::from(*byte);
        }
        Some(value)
    }
}

pub struct QuicSniffer {
    version: Option<&'static Version>,
    initial_keys: Vec<InitialKey>,
    crypto: Vec<u8>,
    received: Bitmap,
    contiguous_end: usize,
    result: Option<String>,
    closed: bool,
    policy: Arc<Policy>,
    override_dest: bool,
}

impl QuicSniffer {
    pub(super) fn new(policy: Arc<Policy>, override_dest: bool) -> Self {
        QuicSniffer {
            version: None,
            initial_keys: Vec::new(),
            crypto: Vec::new(),
            received: Bitmap::default(),
            contiguous_end: 0,
            result: None,
            closed: false,
            policy,
            override_dest,
        }
    }

    pub fn feed(&mut self, packet: &[u8]) {
        if self.closed {
            return;
        }
        if self.read_datagram(packet).is_err() {
            self.close();
        }
    }

    pub fn finished(&self) -> bool {
        self.closed
    }

    pub fn result(&self) -> Option<&str> {
        self.result.as_deref()
    }

    /// For the caller to end sniffing when `QUIC_WAIT` elapsed.
    pub fn close(&mut self) {
        self.closed = true;
        self.crypto = Vec::new();
        self.received = Bitmap::default();
        self.contiguous_end = 0;
    }

    pub fn apply(&self, target: &mut SniffTarget<'_>) {
        let Some(host) = self.result() else { return };
        if self.policy.domain_can_replace(host) {
            replace_domain(target, host, self.override_dest);
        } else {
            tracing::debug!(host, "[Sniffer] skip sni");
        }
    }

    fn read_datagram(&mut self, mut b: &[u8]) -> Result<(), SniffError> {
        let mut first_packet = true;
        while !b.is_empty() {
            let packet_len = self.read_packet(b, !first_packet)?;
            if packet_len == 0 {
                return Err(SniffError::NotQuic);
            }
            b = b.get(packet_len..).ok_or(SniffError::NotQuic)?;
            first_packet = false;
        }

        if let Some(domain) = self.try_assemble()? {
            self.result = Some(domain);
            self.close();
        }
        Ok(())
    }

    /// Returns the packet's length in the datagram; a short-header packet has
    /// no length field, so it consumes the rest and only follows a long one.
    fn read_packet(&mut self, b: &[u8], coalesced: bool) -> Result<usize, SniffError> {
        let mut r = Reader::new(b);
        let type_byte = r.u8().ok_or(SniffError::NotQuic)?;

        if type_byte & 0x80 == 0 {
            return if coalesced {
                Ok(b.len())
            } else {
                Err(SniffError::NotQuicInitial)
            };
        }
        if type_byte & 0x40 == 0 {
            return Err(SniffError::NotQuicInitial);
        }

        let version_bytes = r.bytes(4).ok_or(SniffError::NotQuic)?;
        let version = self.version_for(version_bytes)?;

        let conn_id_len = r.u8().ok_or(SniffError::NotQuic)?;
        if conn_id_len == 0 {
            return Err(SniffError::NotQuic);
        }
        let dest_conn_id = r
            .bytes(usize::from(conn_id_len))
            .ok_or(SniffError::NotQuic)?;
        let src_len = r.u8().ok_or(SniffError::NotQuic)?;
        r.bytes(usize::from(src_len)).ok_or(SniffError::NotQuic)?;

        let packet_type = (type_byte & 0x30) >> 4;
        if packet_type == version.type_retry {
            return Ok(b.len());
        }

        if packet_type == version.type_initial {
            let token_len = r.varint().ok_or(SniffError::NotQuic)?;
            if token_len > r.remaining() as u64 {
                return Err(SniffError::NotQuic);
            }
            r.bytes(token_len as usize).ok_or(SniffError::NotQuic)?;
        }

        let packet_len = r.varint().ok_or(SniffError::NotQuic)?;
        let hdr_len = r.pos;
        if packet_len > (b.len() - hdr_len) as u64 {
            return Err(SniffError::NotQuic);
        }
        let packet_end = hdr_len + packet_len as usize;
        if packet_type != version.type_initial {
            return Ok(packet_end);
        }

        match self.decrypt_initial_packet(b, hdr_len, packet_end, dest_conn_id, version) {
            Ok(frames) => self.read_frames(&frames)?,
            // Corruption or a delayed packet must not end sniffing.
            Err(SniffError::DecryptionFailed) => {}
            Err(err) => return Err(err),
        }
        Ok(packet_end)
    }

    /// A Retry changes the DCID the keys derive from without resetting the
    /// packet number space: the new epoch inherits the largest number and is
    /// kept only after it authenticated a packet. At most one Retry is
    /// accepted, hence two epochs.
    fn decrypt_initial_packet(
        &mut self,
        b: &[u8],
        hdr_len: usize,
        packet_end: usize,
        dest_conn_id: &[u8],
        version: &Version,
    ) -> Result<Vec<u8>, SniffError> {
        if self.initial_keys.is_empty() {
            self.initial_keys
                .push(InitialKey::new(dest_conn_id, version)?);
        }

        let mut decrypt_err = SniffError::DecryptionFailed;
        let mut has_current_dest_conn_id = false;
        let mut largest_packet_number = -1i64;
        for key in &mut self.initial_keys {
            has_current_dest_conn_id |= dest_conn_id == key.dest_conn_id.as_slice();
            largest_packet_number = largest_packet_number.max(key.largest_packet_number);
            match decrypt_initial(
                b,
                hdr_len,
                packet_end,
                &key.labels,
                key.largest_packet_number,
            ) {
                Ok((frames, packet_number)) => {
                    key.largest_packet_number = key.largest_packet_number.max(packet_number);
                    return Ok(frames);
                }
                Err(err) => decrypt_err = err,
            }
        }
        if has_current_dest_conn_id {
            return Err(decrypt_err);
        }

        let mut candidate = InitialKey::new(dest_conn_id, version)?;
        candidate.largest_packet_number = largest_packet_number;
        let (frames, packet_number) = decrypt_initial(
            b,
            hdr_len,
            packet_end,
            &candidate.labels,
            candidate.largest_packet_number,
        )?;
        candidate.largest_packet_number = packet_number;
        match self.initial_keys.get_mut(1) {
            Some(slot) => *slot = candidate,
            None => self.initial_keys.push(candidate),
        }
        Ok(frames)
    }

    fn read_frames(&mut self, data: &[u8]) -> Result<(), SniffError> {
        let eof = SniffError::UnexpectedEof;
        let mut r = Reader::new(data);
        while !r.is_empty() {
            let mut frame_type = FRAME_PADDING;
            while frame_type == FRAME_PADDING && !r.is_empty() {
                frame_type = r.u8().unwrap_or(FRAME_PADDING);
            }
            match frame_type {
                FRAME_PADDING | FRAME_PING => {}
                FRAME_ACK | FRAME_ACK_WITH_ECN => {
                    r.varint().ok_or(eof)?;
                    r.varint().ok_or(eof)?;
                    let range_count = r.varint().ok_or(eof)?;
                    r.varint().ok_or(eof)?;
                    for _ in 0..range_count {
                        r.varint().ok_or(eof)?;
                        r.varint().ok_or(eof)?;
                    }
                    if frame_type == FRAME_ACK_WITH_ECN {
                        for _ in 0..3 {
                            r.varint().ok_or(eof)?;
                        }
                    }
                }
                FRAME_CRYPTO => {
                    let offset = r.varint().ok_or(eof)?;
                    let length = r.varint().ok_or(eof)?;
                    if length > r.remaining() as u64 {
                        return Err(eof);
                    }
                    let crypto = r.bytes(length as usize).ok_or(eof)?;
                    self.add_crypto_data(offset, crypto)?;
                }
                FRAME_CONNECTION_CLOSE => {
                    r.varint().ok_or(eof)?;
                    r.varint().ok_or(eof)?;
                    let length = r.varint().ok_or(eof)?;
                    if length > r.remaining() as u64 {
                        return Err(eof);
                    }
                    r.bytes(length as usize).ok_or(eof)?;
                }
                _ => return Err(SniffError::NotQuicInitial),
            }
        }
        Ok(())
    }

    fn add_crypto_data(&mut self, offset: u64, data: &[u8]) -> Result<(), SniffError> {
        if data.is_empty() {
            return Ok(());
        }
        let limit = MAX_CRYPTO_STREAM_OFFSET as u64;
        let length = data.len() as u64;
        if offset > limit || length > limit - offset {
            return Err(SniffError::ShortBuffer);
        }
        if self.closed {
            return Ok(());
        }
        let (offset, end) = (offset as usize, offset as usize + data.len());

        if end > self.crypto.len() {
            self.crypto.resize(end, 0);
        }
        if let Some(slot) = self.crypto.get_mut(offset..end) {
            slot.copy_from_slice(data);
        }
        self.received.set_range(offset, end);

        if offset <= self.contiguous_end && end > self.contiguous_end {
            self.contiguous_end = self
                .received
                .first_unset(self.contiguous_end, self.crypto.len());
        }
        Ok(())
    }

    fn try_assemble(&self) -> Result<Option<String>, SniffError> {
        if self.closed || self.contiguous_end == 0 {
            return Ok(None);
        }

        if self.contiguous_end >= HANDSHAKE_HEADER_LEN {
            let header = self.crypto.get(..HANDSHAKE_HEADER_LEN).unwrap_or_default();
            if client_hello_size(header)? > MAX_CRYPTO_STREAM_OFFSET {
                return Err(SniffError::ShortBuffer);
            }
        }

        let prefix = self.crypto.get(..self.contiguous_end).unwrap_or_default();
        match read_client_hello(prefix) {
            Ok(domain) if domain.is_empty() => Ok(None),
            Ok(domain) => Ok(Some(domain)),
            Err(SniffError::NeedAtLeast(length)) if length > MAX_CRYPTO_STREAM_OFFSET => {
                Err(SniffError::ShortBuffer)
            }
            Err(SniffError::NeedAtLeast(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn version_for(&mut self, bytes: &[u8]) -> Result<&'static Version, SniffError> {
        if let Some(version) = self.version {
            return Ok(version);
        }
        let id = u32::from_be_bytes(bytes.try_into().map_err(|_| SniffError::NotQuic)?);
        let version = VERSIONS
            .iter()
            .copied()
            .find(|v| v.id == id)
            .ok_or(SniffError::NotQuic)?;
        self.version = Some(version);
        Ok(version)
    }
}

#[cfg(test)]
#[path = "quic_tests.rs"]
mod tests;
