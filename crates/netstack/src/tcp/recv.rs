use std::io;

use crate::attach::Gather;
use crate::buffer::ChunkPool;
use crate::seq::Seq;
use crate::stream::SharedState;
use crate::wire::{FLAG_FIN, TcpSegment};

use super::{Event, State, TIME_WAIT, Tcb, Wakes};

/// Long enough for a relayed reply to carry the ACK, short enough not to stall a Nagle sender.
const DELAYED_ACK: u64 = 10_000;

impl Tcb {
    #[allow(
        clippy::too_many_arguments,
        reason = "input's arguments plus its event"
    )]
    pub(super) fn process_data<'a>(
        &mut self,
        seg: &TcpSegment<'a>,
        now: u64,
        state: &mut SharedState,
        pool: &ChunkPool,
        wakes: &mut Wakes,
        event: &mut Event,
        gather: &mut Gather<'a>,
    ) {
        let receiving = matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        );
        let mut seq = Seq(seg.seq);
        let mut data = seg.payload;
        if seg.has(FLAG_FIN) && receiving {
            let fin = Seq(seg.seq) + seg.payload.len() as u32;
            if fin.ge(self.rcv_nxt) {
                self.peer_fin = Some(fin);
            }
        }
        if !data.is_empty() && receiving {
            if state.dropped {
                self.abort(state, wakes, io::ErrorKind::ConnectionAborted);
                event.closed = true;
                return;
            }
            if seq.lt(self.rcv_nxt) {
                let skip = self.rcv_nxt.since(seq) as usize;
                self.dsack = Some((seq, self.rcv_nxt.min(seq + data.len() as u32)));
                data = data.get(skip..).unwrap_or_default();
                seq = self.rcv_nxt;
                self.ack_now = true;
            }
            let room = self.rcv_adv.max(self.rcv_nxt + self.mss).since(seq) as usize;
            if data.len() > room {
                data = data.get(..room).unwrap_or_default();
            }
            if !data.is_empty() {
                if seq == self.rcv_nxt {
                    self.deliver(data, state, pool, wakes, gather);
                    if !self.ooo.is_empty() {
                        self.ack_now = true;
                        gather.write(state, pool);
                        while let Some(ready) = self.ooo.take_ready(self.rcv_nxt) {
                            let mut owned = Gather::default();
                            self.deliver(&ready, state, pool, wakes, &mut owned);
                            owned.write(state, pool);
                        }
                    }
                    if self.rcv_nxt.since(self.ack_sent) >= 2 * self.mss {
                        self.ack_now = true;
                    } else {
                        self.ack_pending = true;
                        self.ack_at.get_or_insert(now + DELAYED_ACK);
                    }
                    self.measure_receive(now, state);
                } else {
                    if !self.ooo.insert(seq, data) {
                        self.dsack = Some((seq, seq + data.len() as u32));
                    }
                    self.ack_now = true;
                }
            }
        }
        if let Some(fin) = self.peer_fin
            && fin == self.rcv_nxt
        {
            self.peer_fin = None;
            self.rcv_nxt = self.rcv_nxt + 1;
            self.ack_now = true;
            state.recv_eof = true;
            wakes.add(state.wake_reader());
            match self.state {
                State::Established => self.state = State::CloseWait,
                State::FinWait1 => self.state = State::Closing,
                State::FinWait2 => {
                    self.state = State::TimeWait;
                    self.close_at = Some(now + TIME_WAIT);
                }
                _ => {}
            }
        } else if seg.has(FLAG_FIN) && self.state == State::TimeWait {
            self.ack_now = true;
        }
    }

    /// Hands in-order `data` to the attached socket through `gather`, or queues it for the
    /// application.
    fn deliver<'a>(
        &mut self,
        data: &'a [u8],
        state: &mut SharedState,
        pool: &ChunkPool,
        wakes: &mut Wakes,
        gather: &mut Gather<'a>,
    ) {
        let gathered = state.recv.is_empty()
            && state
                .passthrough
                .as_deref()
                .is_some_and(|socket| gather.push(data, socket));
        if !gathered {
            gather.write(state, pool);
            let socket = if state.recv.is_empty() {
                state.passthrough.clone()
            } else {
                None
            };
            match socket {
                Some(socket) => {
                    let mut alone = Gather::default();
                    alone.push(data, &socket);
                    alone.write(state, pool);
                }
                None => state.recv.push(pool, data),
            }
        }
        self.rcv_nxt = self.rcv_nxt + data.len() as u32;
        self.delivered_total += data.len() as u64;
        wakes.add(state.wake_reader());
    }

    /// Dynamic right-sizing: once per receive round trip, lets the buffer grow to twice what
    /// the application read in that round trip.
    fn measure_receive(&mut self, now: u64, state: &SharedState) {
        match self.rcv_rtt_mark {
            Some((mark, since)) if self.rcv_nxt.ge(mark) => {
                let sample = now.saturating_sub(since).max(100);
                self.rcv_rtt = if self.rcv_rtt == 0 {
                    sample
                } else {
                    (7 * self.rcv_rtt + sample) / 8
                };
                self.rcv_rtt_mark = None;
            }
            None => {
                let window = self.rcv_adv.since(self.rcv_nxt).max(self.mss);
                self.rcv_rtt_mark = Some((self.rcv_nxt + window, now));
            }
            _ => {}
        }
        let base = if self.rcv_rtt > 0 {
            self.rcv_rtt
        } else {
            self.rtt.smoothed()
        };
        let interval = base.max(1_000);
        if now.saturating_sub(self.drs_time) < interval {
            return;
        }
        let copied_total = self.delivered_total - state.recv.len() as u64;
        let copied = copied_total - self.drs_copied;
        self.drs_copied = copied_total;
        self.drs_time = now;
        if copied > self.drs_space {
            self.drs_space = copied;
            let want = (2 * copied).min(u64::from(self.rcv_cap_max())) as u32;
            if want > self.rcv_cap {
                self.rcv_cap = want;
            }
        }
    }

    /// The window field to advertise, moving the right edge forward but never back, and only
    /// in steps worth a segment.
    pub(super) fn window_field(&mut self, state: &SharedState) -> u16 {
        let used = (state.recv.len() + self.ooo.bytes()) as u32;
        let free = self.rcv_cap.saturating_sub(used);
        let edge = self.rcv_nxt + free;
        let step = self.mss.min(self.rcv_cap / 2);
        if edge.gt(self.rcv_adv)
            && (edge.since(self.rcv_adv) >= step || self.rcv_adv.le(self.rcv_nxt))
            && (free >= step || self.rcv_adv.gt(self.rcv_nxt))
        {
            self.rcv_adv = edge;
        }
        if self.rcv_adv.lt(self.rcv_nxt) {
            self.rcv_adv = self.rcv_nxt;
        }
        let window = self.rcv_adv.since(self.rcv_nxt) >> self.rcv_shift;
        window.min(65_535) as u16
    }

    /// True when the application read enough that the peer should hear about the window now.
    pub fn window_update_due(&self, state: &SharedState) -> bool {
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            return false;
        }
        let used = (state.recv.len() + self.ooo.bytes()) as u32;
        let free = self.rcv_cap.saturating_sub(used);
        let advertised = self.rcv_adv.since(self.rcv_nxt);
        free >= advertised + 2 * self.mss || (advertised < self.mss && free >= self.mss)
    }

    pub fn request_ack(&mut self) {
        self.ack_now = true;
    }
}
