use std::sync::Arc;

use arc_swap::ArcSwap;

use super::padding::{Padding, Size};

pub(super) const CMD_WASTE: u8 = 0;
pub(super) const CMD_SYN: u8 = 1;
pub(super) const CMD_PSH: u8 = 2;
pub(super) const CMD_FIN: u8 = 3;
pub(super) const CMD_SETTINGS: u8 = 4;
pub(super) const CMD_ALERT: u8 = 5;
pub(super) const CMD_UPDATE_PADDING: u8 = 6;
pub(super) const CMD_SYNACK: u8 = 7;
pub(super) const CMD_HEART_REQUEST: u8 = 8;
pub(super) const CMD_HEART_RESPONSE: u8 = 9;
pub(super) const CMD_SERVER_SETTINGS: u8 = 10;

pub(super) const HEADER: usize = 7;
pub(super) const MAX_FRAME: usize = u16::MAX as usize;

pub(super) fn header(cmd: u8, sid: u32, len: usize) -> [u8; HEADER] {
    let [a, b, c, d] = sid.to_be_bytes();
    let [hi, lo] = (len as u16).to_be_bytes();
    [cmd, a, b, c, d, hi, lo]
}

pub(super) fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + data.len());
    out.extend_from_slice(&header(cmd, sid, data.len()));
    out.extend_from_slice(data);
    out
}

pub(super) fn data_frames(sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + HEADER * data.len().div_ceil(MAX_FRAME));
    for chunk in data.chunks(MAX_FRAME) {
        out.extend_from_slice(&header(CMD_PSH, sid, chunk.len()));
        out.extend_from_slice(chunk);
    }
    out
}

pub(super) struct Framer {
    pub(super) buffering: bool,
    pub(super) buffer: Vec<u8>,
    pub(super) padding_on: bool,
    pub(super) counter: u32,
    pub(super) padding: Arc<ArcSwap<Padding>>,
}

type Writes = std::iter::Chain<std::option::IntoIter<Vec<u8>>, std::vec::IntoIter<Vec<u8>>>;

impl Framer {
    fn waste(len: usize) -> Vec<u8> {
        let mut out = frame(CMD_WASTE, 0, &[]);
        out.resize(HEADER + len, 0);
        if let Some(length) = out.get_mut(5..7) {
            length.copy_from_slice(&(len as u16).to_be_bytes());
        }
        out
    }

    pub(super) fn passes_through(&self) -> bool {
        !self.buffering && self.buffer.is_empty() && !self.padding_on
    }

    /// The writes that carry `bytes`, split and padded by the scheme's record plan.
    pub(super) fn push(&mut self, bytes: Vec<u8>) -> Writes {
        let mut bytes = bytes;
        if self.buffering {
            self.buffer.extend_from_slice(&bytes);
            return None.into_iter().chain(Vec::new());
        }
        if !self.buffer.is_empty() {
            let mut joined = std::mem::take(&mut self.buffer);
            joined.extend_from_slice(&bytes);
            bytes = joined;
        }
        if !self.padding_on {
            return Some(bytes).into_iter().chain(Vec::new());
        }
        self.counter += 1;
        let scheme = self.padding.load_full();
        if self.counter >= scheme.stop {
            self.padding_on = false;
            return Some(bytes).into_iter().chain(Vec::new());
        }
        let mut out = Vec::new();
        let mut rest = bytes;
        for size in scheme.sizes(self.counter) {
            let remaining = rest.len();
            match size {
                Size::Check if remaining == 0 => break,
                Size::Check => {}
                Size::Bytes(len) if remaining > len => {
                    let tail = rest.split_off(len);
                    out.push(std::mem::replace(&mut rest, tail));
                }
                Size::Bytes(len) if remaining > 0 => {
                    let pad = len.saturating_sub(remaining + HEADER);
                    if pad > 0 {
                        rest.extend_from_slice(&Framer::waste(pad));
                    }
                    out.push(std::mem::take(&mut rest));
                }
                Size::Bytes(len) => out.push(Framer::waste(len)),
            }
        }
        if !rest.is_empty() {
            out.push(rest);
        }
        None.into_iter().chain(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framer(scheme: &str) -> Framer {
        Framer {
            buffering: false,
            buffer: Vec::new(),
            padding_on: true,
            counter: 0,
            padding: Arc::new(ArcSwap::from_pointee(
                Padding::parse(scheme.as_bytes()).unwrap(),
            )),
        }
    }

    #[test]
    fn frames_have_a_seven_byte_header() {
        assert_eq!(
            frame(CMD_PSH, 0x0102_0304, b"ab"),
            [2, 1, 2, 3, 4, 0, 2, b'a', b'b']
        );
    }

    #[test]
    fn buffered_frames_leave_with_the_next_write() {
        let mut framer = framer("stop=0");
        framer.buffering = true;
        assert!(framer.push(vec![1, 2]).next().is_none());
        framer.buffering = false;
        assert_eq!(
            framer.push(vec![3]).collect::<Vec<_>>(),
            vec![vec![1, 2, 3]]
        );
    }

    #[test]
    fn a_short_payload_is_padded_up_to_the_planned_record() {
        let mut framer = framer("stop=5\n1=40-40");
        framer.counter = 0;
        let writes = framer.push(vec![9; 10]).collect::<Vec<_>>();
        assert_eq!(writes.len(), 1);
        let write = writes.first().unwrap();
        assert_eq!(write.len(), 10 + HEADER + (40 - 10 - HEADER));
        assert_eq!(write.get(..10), Some(&[9u8; 10][..]));
        assert_eq!(write.get(10), Some(&CMD_WASTE));
    }

    #[test]
    fn a_long_payload_is_cut_at_the_record_size() {
        let mut framer = framer("stop=5\n1=30-30");
        let writes = framer.push(vec![7; 100]).collect::<Vec<_>>();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes.first().map(Vec::len), Some(30));
        assert_eq!(writes.get(1).map(Vec::len), Some(70));
    }

    #[test]
    fn padding_stops_after_the_scheme_says_so() {
        let mut framer = framer("stop=2\n1=30-30");
        assert_eq!(framer.push(vec![0; 5]).count(), 1);
        let writes = framer.push(vec![1; 100]).collect::<Vec<_>>();
        assert_eq!(writes, vec![vec![1; 100]]);
        assert!(!framer.padding_on);
    }

    #[test]
    fn a_check_mark_ends_the_plan_once_the_payload_is_spent() {
        let mut framer = framer("stop=5\n1=10-10,c,50-50");
        assert_eq!(framer.push(vec![1; 4]).count(), 1);
    }
}
