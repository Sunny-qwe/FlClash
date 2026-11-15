use std::time::Duration;

const MIN_BACKOFF: Duration = Duration::from_secs(10);
/// A GEO file the rules wait for retries up to mihomo's default `geo-update-interval`.
pub const GEO_RETRY_CAP: Duration = Duration::from_secs(24 * 3600);

/// The wait before the next fetch of a provider that has failed `failures` times, as mihomo's
/// resource fetcher backs off: from `min(10 s, interval)`, doubling, up to the interval. A
/// provider with `interval: 0` is not retried at all, as in mihomo, so callers skip it.
pub fn provider_backoff(failures: u32, interval: Duration) -> Duration {
    let min = MIN_BACKOFF.min(interval);
    min.saturating_mul(2u32.saturating_pow(failures))
        .min(interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_from_ten_seconds_up_to_the_interval() {
        let interval = Duration::from_secs(3600);
        let steps: Vec<u64> = (0..4)
            .map(|n| provider_backoff(n, interval).as_secs())
            .collect();
        assert_eq!(steps, [10, 20, 40, 80]);
        assert_eq!(provider_backoff(20, interval), interval);
        assert_eq!(
            provider_backoff(3, Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn a_day_long_interval_lets_a_dead_url_back_off_to_a_day() {
        let day = Duration::from_secs(86_400);
        assert_eq!(provider_backoff(40, day), day);
    }
}
