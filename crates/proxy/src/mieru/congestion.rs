use std::time::Duration;

use tokio::time::Instant;

const RTT_ALPHA: f64 = 0.125;
const RTT_BETA: f64 = 0.25;
const INITIAL_RTO: Duration = Duration::from_secs(2);
const MIN_DEVIATION: Duration = Duration::from_millis(10);
const CUBIC_BETA: f64 = 0.7;
const CUBIC_C: f64 = 0.4;

pub(super) struct Rtt {
    smoothed: Option<Duration>,
    deviation: Duration,
    max_ack_delay: Duration,
    multiplier: f64,
}

impl Rtt {
    pub(super) fn new(max_ack_delay: Duration, multiplier: f64) -> Rtt {
        Rtt {
            smoothed: None,
            deviation: Duration::ZERO,
            max_ack_delay,
            multiplier,
        }
    }

    pub(super) fn rto(&self) -> Duration {
        let Some(smoothed) = self.smoothed else {
            return INITIAL_RTO;
        };
        let rto = smoothed + (self.deviation * 4).max(MIN_DEVIATION) + self.max_ack_delay;
        rto.mul_f64(self.multiplier)
    }

    pub(super) fn update(&mut self, sample: Duration) {
        if sample.is_zero() {
            return;
        }
        let Some(smoothed) = self.smoothed else {
            self.smoothed = Some(sample);
            self.deviation = sample / 2;
            return;
        };
        let micros = |d: Duration| d.as_micros() as f64;
        let gap = micros(smoothed.abs_diff(sample));
        self.deviation = Duration::from_micros(
            ((1.0 - RTT_BETA) * micros(self.deviation) + RTT_BETA * gap) as u64,
        );
        self.smoothed = Some(Duration::from_micros(
            ((1.0 - RTT_ALPHA) * micros(smoothed) + RTT_ALPHA * micros(sample)) as u64,
        ));
    }
}

pub(super) struct Cubic {
    min: u32,
    max: u32,
    slow_start: bool,
    window: u32,
    before_reduction: u32,
    reduced_at: Option<Instant>,
    acks: u32,
}

impl Cubic {
    pub(super) fn new(min: u32, max: u32) -> Cubic {
        Cubic {
            min,
            max,
            slow_start: true,
            window: min,
            before_reduction: 0,
            reduced_at: None,
            acks: 0,
        }
    }

    pub(super) fn window(&self) -> u32 {
        self.window
    }

    pub(super) fn on_ack(&mut self) {
        if self.slow_start {
            self.window += 1;
        } else {
            self.acks += 1;
            let before = f64::from(self.before_reduction);
            let k = (before * (1.0 - CUBIC_BETA) / CUBIC_C).cbrt();
            let t = self.reduced_at.map_or(0.0, |at| at.elapsed().as_secs_f64());
            self.window = (CUBIC_C * (t - k).powi(3) + before) as u32 + self.acks / 16;
        }
        self.clamp();
    }

    pub(super) fn on_loss(&mut self) {
        self.slow_start = false;
        self.reduced_at = Some(Instant::now());
        self.before_reduction = self.window;
        self.acks = 0;
        self.window = (f64::from(self.window) * CUBIC_BETA) as u32;
        self.clamp();
    }

    pub(super) fn on_timeout(&mut self) {
        self.slow_start = true;
        self.window = self.min;
        self.before_reduction = 0;
        self.reduced_at = None;
        self.acks = 0;
    }

    fn clamp(&mut self) {
        self.window = self.window.clamp(self.min, self.max);
    }
}
