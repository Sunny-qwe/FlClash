#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Congestion {
    #[default]
    Cubic,
    Reno,
}

impl Congestion {
    pub const NAMES: &'static [&'static str] = &["cubic", "reno"];

    /// `bbr` and `bbr3` are not implemented; they run as CUBIC and report `false`.
    pub fn parse(name: &str) -> (Self, bool) {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "cubic" => (Congestion::Cubic, true),
            "reno" => (Congestion::Reno, true),
            _ => (Congestion::Cubic, false),
        }
    }
}

const CUBIC_C: f64 = 0.4;
const CUBIC_BETA: f64 = 0.7;
const MAX_CWND: u32 = 64 << 20;

/// RFC 6928's initial window.
pub(crate) fn initial_window(mss: u32) -> u32 {
    (10 * mss).min((2 * mss).max(14_600))
}

#[derive(Default)]
struct Cubic {
    w_max: f64,
    k: f64,
    epoch_start: Option<u64>,
    origin: f64,
    w_est: f64,
}

/// Window growth and reduction. Loss detection and the window during recovery live in the
/// connection; this only answers how much to grow on delivery and where to cut on loss.
pub(crate) struct Controller {
    kind: Congestion,
    pub cwnd: u32,
    pub ssthresh: u32,
    mss: u32,
    carry: u64,
    cubic: Cubic,
}

impl Controller {
    pub fn new(kind: Congestion, mss: u32) -> Self {
        Controller {
            kind,
            cwnd: initial_window(mss),
            ssthresh: u32::MAX,
            mss,
            carry: 0,
            cubic: Cubic::default(),
        }
    }

    pub fn set_mss(&mut self, mss: u32) {
        if self.cwnd == initial_window(self.mss) {
            self.cwnd = initial_window(mss);
        }
        self.mss = mss;
    }

    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Grows the window for `acked` newly delivered bytes. Only called while the window, not
    /// the application or the receiver, was what limited sending.
    pub fn on_ack(&mut self, acked: u32, now: u64, srtt: u64) {
        let mut acked = acked;
        if self.in_slow_start() {
            let room = self.ssthresh.saturating_sub(self.cwnd);
            let grow = acked.min(room);
            self.cwnd = self.cwnd.saturating_add(grow);
            acked -= grow;
            if acked == 0 {
                self.cwnd = self.cwnd.min(MAX_CWND);
                return;
            }
        }
        match self.kind {
            Congestion::Reno => self.reno(acked),
            Congestion::Cubic => self.cubic(acked, now, srtt),
        }
        self.cwnd = self.cwnd.min(MAX_CWND);
    }

    fn reno(&mut self, acked: u32) {
        self.carry += u64::from(acked);
        let cwnd = u64::from(self.cwnd.max(self.mss));
        if self.carry >= cwnd {
            let steps = self.carry / cwnd;
            self.carry %= cwnd;
            self.cwnd = self
                .cwnd
                .saturating_add((steps * u64::from(self.mss)) as u32);
        }
    }

    fn cubic(&mut self, acked: u32, now: u64, srtt: u64) {
        let mss = f64::from(self.mss);
        let cwnd = f64::from(self.cwnd) / mss;
        let state = &mut self.cubic;
        let start = *state.epoch_start.get_or_insert_with(|| {
            if cwnd < state.w_max {
                state.k = ((state.w_max - cwnd) / CUBIC_C).cbrt();
                state.origin = state.w_max;
            } else {
                state.k = 0.0;
                state.origin = cwnd;
            }
            state.w_est = cwnd;
            now
        });
        let t = (now.saturating_sub(start) + srtt) as f64 / 1e6;
        let w_cubic = CUBIC_C * (t - state.k).powi(3) + state.origin;
        let alpha = 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA);
        state.w_est += alpha * (f64::from(acked) / mss) / cwnd;
        let target = if w_cubic < state.w_est {
            state.w_est
        } else {
            w_cubic.clamp(cwnd, 1.5 * cwnd)
        };
        if target <= cwnd {
            return;
        }
        let grow = (target - cwnd) / cwnd * f64::from(acked);
        self.carry += (grow * 1024.0) as u64;
        let whole = self.carry / 1024;
        self.carry %= 1024;
        self.cwnd = self
            .cwnd
            .saturating_add(whole.min(u64::from(u32::MAX)) as u32);
    }

    /// Sets `ssthresh` for a loss in the current window and returns it.
    pub fn on_loss(&mut self) -> u32 {
        let floor = 2 * self.mss;
        self.carry = 0;
        let ssthresh = match self.kind {
            Congestion::Reno => self.cwnd / 2,
            Congestion::Cubic => {
                let cwnd = f64::from(self.cwnd) / f64::from(self.mss);
                let state = &mut self.cubic;
                state.w_max = if cwnd < state.w_max {
                    cwnd * (1.0 + CUBIC_BETA) / 2.0
                } else {
                    cwnd
                };
                state.epoch_start = None;
                (f64::from(self.cwnd) * CUBIC_BETA) as u32
            }
        };
        self.ssthresh = ssthresh.max(floor);
        self.ssthresh
    }

    pub fn on_rto(&mut self) {
        self.on_loss();
        self.cwnd = self.mss;
    }

    /// Restarts the cubic epoch after the sender was idle, so time spent idle is not
    /// counted as time spent probing.
    pub fn on_idle(&mut self) {
        self.cubic.epoch_start = None;
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Rtt {
    pub srtt: u64,
    pub rttvar: u64,
    pub rto: u64,
    pub min_rtt: u64,
    min_stamp: u64,
    pub sampled: bool,
}

pub(crate) const INITIAL_RTO: u64 = 1_000_000;
/// Above the delayed-ACK timer of every kernel that can be the peer: Linux holds a lone
/// segment's ACK for 40 ms, Darwin for 100 ms and Windows for 200 ms.
pub(crate) const MIN_RTO: u64 = 300_000;
pub(crate) const MAX_RTO: u64 = 60_000_000;
const MIN_RTT_WINDOW: u64 = 10_000_000;

impl Default for Rtt {
    fn default() -> Self {
        Rtt {
            srtt: 0,
            rttvar: 0,
            rto: INITIAL_RTO,
            min_rtt: u64::MAX,
            min_stamp: 0,
            sampled: false,
        }
    }
}

impl Rtt {
    pub fn sample(&mut self, rtt: u64, now: u64) {
        let rtt = rtt.max(1);
        if self.sampled {
            let diff = self.srtt.abs_diff(rtt);
            self.rttvar = (3 * self.rttvar + diff) / 4;
            self.srtt = (7 * self.srtt + rtt) / 8;
        } else {
            self.srtt = rtt;
            self.rttvar = rtt / 2;
            self.sampled = true;
        }
        self.rto = (self.srtt + (4 * self.rttvar).max(1_000)).clamp(MIN_RTO, MAX_RTO);
        if rtt <= self.min_rtt || now.saturating_sub(self.min_stamp) > MIN_RTT_WINDOW {
            self.min_rtt = rtt;
            self.min_stamp = now;
        }
    }

    /// The smoothed RTT, or a conservative stand-in before the first sample.
    pub fn smoothed(&self) -> u64 {
        if self.sampled { self.srtt } else { 100_000 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_start_doubles_then_loss_cuts_by_beta() {
        let mut cc = Controller::new(Congestion::Cubic, 1000);
        assert_eq!(cc.cwnd, 10_000);
        cc.on_ack(10_000, 0, 1000);
        assert_eq!(cc.cwnd, 20_000);
        let ssthresh = cc.on_loss();
        assert_eq!(ssthresh, 14_000);
        cc.cwnd = ssthresh;
        let mut now = 0;
        for _ in 0..2000 {
            now += 10_000;
            cc.on_ack(1000, now, 10_000);
        }
        assert!(cc.cwnd > 20_000, "cubic regrows past w_max: {}", cc.cwnd);
    }

    #[test]
    fn reno_adds_one_segment_per_window() {
        let mut cc = Controller::new(Congestion::Reno, 1000);
        cc.ssthresh = 10_000;
        for _ in 0..10 {
            cc.on_ack(1000, 0, 1000);
        }
        assert_eq!(cc.cwnd, 11_000);
    }

    #[test]
    fn rto_follows_rfc6298_with_a_floor() {
        let mut rtt = Rtt::default();
        assert_eq!(rtt.rto, INITIAL_RTO);
        rtt.sample(1_000, 0);
        assert_eq!(rtt.rto, MIN_RTO);
        rtt.sample(1_000_000, 1);
        assert!(rtt.rto > 1_000_000);
        assert_eq!(rtt.min_rtt, 1_000);
    }
}
