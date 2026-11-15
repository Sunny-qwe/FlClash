//! Pacing of packet transmissions.

use crate::congestion::ControllerMetrics;
use crate::{Duration, Instant}; // Concord: controller-selected rate and send quantum, as in noq#611.

use std::num::NonZeroU64; // Concord: a cached explicit rate; None keeps native pacing.
use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    prev: Instant,
    // Concord: the legacy bucket is unchanged until both explicit pacing inputs are supplied.
    explicit_rate: Option<NonZeroU64>,
    has_sent: bool,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
            explicit_rate: None,
            has_sent: false,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    // Concord: the reference rate budget includes ACK-only bytes; the native pacer charges congestion bytes.
    pub(super) fn on_transmit_at(&mut self, congestion_bytes: u16, wire_bytes: u16, now: Instant) {
        if self.explicit_rate.is_some() {
            self.tokens = self.budget(now).saturating_sub(wire_bytes.into());
            self.prev = now;
            self.has_sent = true;
        } else {
            self.on_transmit(congestion_bytes);
        }
    }

    // Concord: configure before ACK-only packets too, which bypass the congestion/pacing admission check.
    pub(super) fn configure_with_metrics(
        &mut self,
        smoothed_rtt: Duration,
        mtu: u16,
        metrics: &ControllerMetrics,
        now: Instant,
    ) {
        let (Some(bits_per_second), Some(quantum)) = (metrics.pacing_rate, metrics.send_quantum)
        else {
            if self.explicit_rate.is_some() {
                let budget = self.budget(now);
                self.explicit_rate = None;
                self.capacity = optimal_capacity(smoothed_rtt, metrics.congestion_window, mtu);
                self.tokens = budget.min(self.capacity);
                self.last_window = metrics.congestion_window;
                self.last_mtu = mtu;
                self.prev = now;
            }
            return;
        };
        let capacity = quantum.max(u64::from(mtu));
        if self.explicit_rate.is_none() {
            self.tokens = capacity;
            self.prev = now;
            self.has_sent = false;
        }
        self.explicit_rate = NonZeroU64::new(bits_per_second.max(1));
        self.capacity = capacity;
    }

    // Concord: like the reference Budget query, only an actual transmission commits elapsed credit.
    fn budget(&self, now: Instant) -> u64 {
        let Some(rate) = self.explicit_rate else {
            return self.tokens;
        };
        if !self.has_sent {
            return self.capacity;
        }
        let elapsed = now.saturating_duration_since(self.prev).as_nanos();
        if elapsed == 0 {
            return self.tokens.min(self.capacity);
        }
        let earned = u128::from(rate.get()).saturating_mul(elapsed) / 8_000_000_000;
        u128::from(self.tokens)
            .saturating_add(earned)
            .min(u128::from(self.capacity)) as u64
    }

    // Concord: noq#611's metrics API, with an opt-in quantum so existing diagnostic rates do not change BBR.
    pub(super) fn delay_with_metrics(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        untracked_bytes: u64,
        mtu: u16,
        metrics: &ControllerMetrics,
        now: Instant,
    ) -> Option<Instant> {
        self.configure_with_metrics(smoothed_rtt, mtu, metrics, now);
        if self.explicit_rate.is_none() {
            return self.delay(
                smoothed_rtt,
                bytes_to_send,
                mtu,
                metrics.congestion_window,
                now,
            );
        }
        let rate = u128::from(metrics.pacing_rate.unwrap().max(1));
        // Concord: the buffered packet is charged after this check; only unreserved credit can admit the next one.
        let available = self.budget(now).saturating_sub(untracked_bytes);
        let target = bytes_to_send
            .saturating_sub(untracked_bytes)
            .min(self.capacity);
        if available >= target {
            return None;
        }
        // Concord: reuse Quinn's userspace burst interval, leaving room for a timer-granularity late wake.
        let headroom = (rate
            .saturating_mul(metrics.min_pacing_delay.unwrap_or_default().as_nanos())
            / 8_000_000_000)
            .min(u128::from(self.capacity)) as u64;
        let batch_credit = (rate.saturating_mul(BURST_INTERVAL_NANOS) / 8_000_000_000)
            .min(u128::from(self.capacity - headroom)) as u64;
        let refill_goal = target.max(batch_credit);
        let nanos = (u128::from(refill_goal - available) * 8_000_000_000).div_ceil(rate);
        let delay = Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64);
        let until = now + delay;
        // Concord: the buffered packet is finalized at now before this batch returns.
        let last_sent = if untracked_bytes != 0 {
            Some(now)
        } else {
            self.has_sent.then_some(self.prev)
        };
        Some(match (last_sent, metrics.min_pacing_delay) {
            (Some(sent), Some(minimum)) => until.max(sent + minimum),
            _ => until,
        })
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        if window != self.last_window || mtu != self.last_mtu {
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu);

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = window as f64 * 1.25 * elapsed_rtts;
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as _)
            .min(self.capacity);

        self.prev = now;

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
                .is_none()
        );
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    // Concord: exercise the same pacing source from the workspace gate.
    fn rate_metrics(window: u64, rate: u64, burst: u64) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = window;
        metrics.pacing_rate = Some(rate * 8);
        metrics.send_quantum = Some(burst);
        metrics.min_pacing_delay = Some(Duration::from_millis(1));
        metrics
    }

    #[test]
    fn diagnostic_rate_does_not_change_legacy_pacing() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        let mut legacy = Pacer::new(rtt, 100_000, 1200, start);
        let mut extended = Pacer::new(rtt, 100_000, 1200, start);
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = 100_000;
        metrics.pacing_rate = Some(900_000_000);
        for step in 0..200 {
            let now = start + Duration::from_micros(step * 50);
            let expected = legacy.delay(rtt, 2400, 1200, 100_000, now);
            let actual = extended.delay_with_metrics(rtt, 2400, 0, 1200, &metrics, now);
            assert_eq!(actual, expected);
            if actual.is_none() {
                legacy.on_transmit(1200);
                extended.on_transmit_at(1200, 1200, now);
            }
            assert_eq!(legacy.tokens, extended.tokens);
            assert_eq!(legacy.capacity, extended.capacity);
        }
    }

    #[test]
    fn ack_only_bytes_are_charged_and_refilled_only_for_explicit_pacing() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        let metrics = rate_metrics(100_000, 1000, 1252);
        let mut explicit = Pacer::new(rtt, 100_000, 1252, start);
        explicit.configure_with_metrics(rtt, 1252, &metrics, start);
        explicit.on_transmit_at(0, 1000, start);
        assert_eq!(explicit.tokens, 252);
        let now = start + Duration::from_millis(500);
        explicit.configure_with_metrics(rtt, 1252, &metrics, now);
        assert_eq!(explicit.budget(now), 752);
        explicit.on_transmit_at(0, 500, now);
        assert_eq!(explicit.tokens, 252);
        assert_eq!(explicit.prev, now);
        assert_eq!(
            explicit.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now),
            Some(now + Duration::from_secs(1))
        );

        let mut native = Pacer::new(rtt, 100_000, 1252, start);
        let initial_tokens = native.tokens;
        let mut diagnostic = ControllerMetrics::default();
        diagnostic.congestion_window = 100_000;
        diagnostic.pacing_rate = Some(8000);
        native.configure_with_metrics(rtt, 1252, &diagnostic, start);
        native.on_transmit_at(0, 1000, start);
        assert_eq!(native.tokens, initial_tokens);
        assert!(!native.has_sent);
    }

    #[test]
    fn explicit_rate_is_independent_of_window_and_rtt() {
        let start = Instant::now();
        let rate = 12_500_000;
        let burst = 50_000;
        for rtt in [Duration::from_millis(1), Duration::from_millis(200)] {
            for window in [100_000, 10_000_000] {
                let metrics = rate_metrics(window, rate, burst);
                let mut pacer = Pacer::new(rtt, window, 1252, start);
                let mut now = start;
                let end = start + Duration::from_secs(1);
                let mut bytes = 0;
                let mut polls = 0;
                while now < end {
                    polls += 1;
                    assert!(polls < 100_000, "pacer did not make progress");
                    match pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now) {
                        None => {
                            pacer.on_transmit_at(1252, 1252, now);
                            bytes += 1252;
                        }
                        Some(until) => {
                            assert!(until > now);
                            now = until;
                        }
                    }
                }
                assert!(bytes >= rate - burst);
                assert!(bytes <= rate + burst);
            }
        }
    }

    #[test]
    fn h2_sq_native_burst_deadlines_preserve_rate_with_timer_overshoot() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        let rate = 12_500_000;
        // Concord: H2/SQ leave 1ms of rate headroom above the native 2ms refill goal.
        let burst = 50_000;
        for overshoot in [Duration::ZERO, Duration::from_millis(1)] {
            let metrics = rate_metrics(1_000_000, rate, burst);
            let mut pacer = Pacer::new(rtt, 1_000_000, 1252, start);
            let mut now = start;
            let end = start + Duration::from_secs(1);
            let mut bytes = 0;
            let mut polls = 0;
            while now < end {
                polls += 1;
                assert!(polls < 100_000, "pacer did not make progress");
                match pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now) {
                    None => {
                        pacer.on_transmit_at(1252, 1252, now);
                        bytes += 1252;
                    }
                    Some(until) => {
                        assert!(until > now);
                        now = until + overshoot;
                    }
                }
            }
            assert!(
                bytes >= rate - burst,
                "burst={burst}, overshoot={overshoot:?}: {bytes}"
            );
            assert!(bytes <= rate + burst);
        }
    }

    #[test]
    fn h1_burst_deadlines_match_reference_minimum_wait_with_late_wakes() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        let metrics = rate_metrics(1_000_000, 12_500_000, 25_000);
        // Concord: a 2ms bucket can clip a packet remainder on a 1ms-minimum wait plus a 1ms-late wake.
        // Check the reference deadline, rather than asserting an unattainable full rate in that case.
        for overshoot in [Duration::ZERO, Duration::from_millis(1)] {
            let mut pacer = Pacer::new(rtt, 1_000_000, 1252, start);
            let mut reference_tokens = 25_000u64;
            let mut reference_sent: Option<Instant> = None;
            let mut now = start;
            let end = start + Duration::from_secs(1);
            let mut polls = 0;
            while now < end {
                polls += 1;
                assert!(polls < 100_000, "pacer did not make progress");
                pacer.configure_with_metrics(rtt, 1252, &metrics, now);
                // Concord: Budget reads from the last SentPacket; reference queries commit no state.
                let budget = reference_sent.map_or(25_000, |sent| {
                    (u128::from(reference_tokens)
                        + now.duration_since(sent).as_nanos() * 12_500_000 / 1_000_000_000)
                        .min(25_000) as u64
                });
                let reference = if budget >= 1252 {
                    None
                } else {
                    let deficit = 1252 - reference_tokens;
                    let refill = Duration::from_nanos(deficit * 80);
                    Some(reference_sent.unwrap() + refill.max(Duration::from_millis(1)))
                };
                let actual = pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now);
                assert_eq!(actual, reference);
                match actual {
                    None => {
                        reference_tokens = budget - 1252;
                        reference_sent = Some(now);
                        pacer.on_transmit_at(1252, 1252, now);
                    }
                    Some(until) => now = until + overshoot,
                }
            }
        }
    }

    #[test]
    fn early_ack_poll_can_use_returned_credit_before_burst_deadline() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        let metrics = rate_metrics(1_000_000, 12_500_000, 50_000);
        let mut pacer = Pacer::new(rtt, 1_000_000, 1252, start);
        pacer.configure_with_metrics(rtt, 1252, &metrics, start);
        pacer.on_transmit_at(50_000, 50_000, start);
        let until = pacer
            .delay_with_metrics(rtt, 1252, 0, 1252, &metrics, start)
            .unwrap();
        assert_eq!(until - start, Duration::from_millis(2));
        assert_eq!(
            pacer.delay_with_metrics(
                rtt,
                1252,
                0,
                1252,
                &metrics,
                start + Duration::from_micros(500)
            ),
            None
        );
    }

    #[test]
    fn buffered_packet_does_not_reuse_one_mtu_quantum() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        let rate = 1_000_000;
        let mtu = 1252;
        let metrics = rate_metrics(100_000, rate, u64::from(mtu));
        let mut pacer = Pacer::new(rtt, 100_000, mtu, start);
        let mut now = start;
        let mut sent = 0;
        while now < start + Duration::from_secs(1) {
            assert_eq!(
                pacer.delay_with_metrics(rtt, mtu.into(), 0, mtu, &metrics, now),
                None
            );
            let until = pacer
                .delay_with_metrics(rtt, 2 * u64::from(mtu), mtu.into(), mtu, &metrics, now)
                .expect("the buffered packet already consumes the one-MTU quantum");
            assert!(until > now);
            pacer.on_transmit_at(mtu, mtu, now);
            sent += u64::from(mtu);
            now = until;
        }
        assert!(sent <= rate + u64::from(mtu));
    }

    #[test]
    fn buffered_packet_anchors_minimum_wait_at_its_send_time() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        for burst in [1252, 25_000] {
            let metrics = rate_metrics(1_000_000, 12_500_000, burst);
            let mut pacer = Pacer::new(rtt, 1_000_000, 1252, start);
            pacer.configure_with_metrics(rtt, 1252, &metrics, start);
            let now = if burst == 1252 {
                start
            } else {
                pacer.on_transmit_at(25_000, 25_000, start);
                start + Duration::from_micros(120)
            };
            assert_eq!(
                pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now),
                None
            );
            // Concord: the buffered packet is sent at now; reference TimeUntilSend then waits at least 1ms.
            assert_eq!(
                pacer.delay_with_metrics(rtt, 2504, 1252, 1252, &metrics, now),
                Some(now + Duration::from_millis(1))
            );
        }
    }

    #[test]
    fn packets_in_a_gso_batch_are_each_charged() {
        let now = Instant::now();
        let rtt = Duration::from_millis(40);
        let metrics = rate_metrics(100_000, 1_000_000, 12_520);
        let mut pacer = Pacer::new(rtt, 100_000, 1252, now);
        assert_eq!(
            pacer.delay_with_metrics(rtt, 2504, 0, 1252, &metrics, now),
            None
        );
        for _ in 0..9 {
            pacer.on_transmit_at(1252, 1252, now);
        }
        assert_eq!(pacer.tokens, 1252);
        // A buffered packet and the next packet require credit for both, before the buffered one is finalized.
        let until = pacer
            .delay_with_metrics(rtt, 2504, 1252, 1252, &metrics, now)
            .unwrap();
        assert_eq!(until - now, Duration::from_millis(2));
        pacer.on_transmit_at(1252, 1252, now);
        assert_eq!(pacer.tokens, 0);
        assert_eq!(
            pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, until),
            None
        );
        assert_eq!(pacer.budget(until), 2000);
    }

    #[test]
    fn depleted_bucket_respects_minimum_wait_and_then_resumes() {
        let now = Instant::now();
        let rtt = Duration::from_millis(40);
        let metrics = rate_metrics(100_000, 12_500_000, 25_000);
        let mut pacer = Pacer::new(rtt, 100_000, 1252, now);
        pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now);
        pacer.on_transmit_at(25_000, 25_000, now);
        let until = pacer
            .delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now)
            .unwrap();
        assert_eq!(until - now, Duration::from_millis(1));
        assert_eq!(
            pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, until),
            None
        );
    }

    #[test]
    fn budget_queries_preserve_fractional_credit_without_a_send() {
        let start = Instant::now();
        let rtt = Duration::from_millis(40);
        let metrics = rate_metrics(100_000, 1000, 12_520);
        let mut pacer = Pacer::new(rtt, 100_000, 1252, start);
        pacer.configure_with_metrics(rtt, 1252, &metrics, start);
        pacer.on_transmit_at(12_520, 12_520, start);
        for step in 1..=1000 {
            let now = start + Duration::from_micros(step * 1500);
            pacer.configure_with_metrics(rtt, 1252, &metrics, now);
        }
        let now = start + Duration::from_millis(1500);
        // Concord: the reference Budget query leaves 1500 bytes earned since the last actual send.
        assert_eq!(
            pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now),
            None
        );
        pacer.on_transmit_at(1252, 1252, now);
        assert_eq!(
            pacer.delay_with_metrics(rtt, 1252, 0, 1252, &metrics, now),
            Some(start + Duration::from_millis(2504))
        );
    }

    #[test]
    fn low_rates_keep_fractional_time_and_mtu_updates_bound_bursts() {
        let start = Instant::now();
        let rtt = Duration::from_millis(1);
        let metrics = rate_metrics(100_000, 1, 1200);
        let mut pacer = Pacer::new(rtt, 100_000, 1200, start);
        pacer.delay_with_metrics(rtt, 1200, 0, 1200, &metrics, start);
        pacer.on_transmit_at(1200, 1200, start);
        for step in 1..10 {
            let now = start + Duration::from_millis(step * 100);
            assert!(
                pacer
                    .delay_with_metrics(rtt, 1200, 0, 1200, &metrics, now)
                    .is_some()
            );
        }
        let now = start + Duration::from_secs(1);
        pacer.delay_with_metrics(rtt, 1200, 0, 1200, &metrics, now);
        assert_eq!(pacer.budget(now), 1);
        pacer.delay_with_metrics(rtt, 9000, 0, 9000, &metrics, now);
        assert_eq!(pacer.capacity, 9000);
    }

    #[test]
    fn removing_opt_in_returns_to_legacy_window_pacing() {
        let now = Instant::now();
        let rtt = Duration::from_millis(40);
        let mut pacer = Pacer::new(rtt, 100_000, 1200, now);
        pacer.delay_with_metrics(
            rtt,
            1200,
            0,
            1200,
            &rate_metrics(100_000, 1_000_000, 50_000),
            now,
        );
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = 100_000;
        pacer.delay_with_metrics(rtt, 1200, 0, 1200, &metrics, now);
        assert!(pacer.explicit_rate.is_none());
        assert_eq!(pacer.capacity, optimal_capacity(rtt, 100_000, 1200));
    }
}
