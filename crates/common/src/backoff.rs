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

/// Retries an initial load after each backoff. `None` means its owner is gone;
/// cancellation interrupts the wait, while an in-flight load keeps its caller's policy.
#[cfg(feature = "io")]
pub async fn retry_until_loaded<F>(
    interval: Duration,
    stop: &tokio_util::sync::CancellationToken,
    mut load: impl FnMut() -> F,
) -> bool
where
    F: Future<Output = Option<bool>> + Send,
{
    if interval.is_zero() {
        return false;
    }
    let mut failures = 0;
    loop {
        tokio::select! {
            () = stop.cancelled() => return false,
            () = tokio::time::sleep(provider_backoff(failures, interval)) => {}
        }
        match load().await {
            Some(true) => return true,
            None => return false,
            Some(false) => failures = failures.saturating_add(1),
        }
    }
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

#[cfg(all(test, feature = "io"))]
mod retry_tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[tokio::test(start_paused = true)]
    async fn initial_load_retries_follow_the_backoff_until_success() {
        let stop = CancellationToken::new();
        let start = tokio::time::Instant::now();
        let mut waits = Vec::new();
        assert!(
            retry_until_loaded(Duration::from_secs(40), &stop, || {
                waits.push(start.elapsed().as_secs());
                std::future::ready(Some(waits.len() == 4))
            })
            .await
        );
        assert_eq!(waits, [10, 30, 70, 110]);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_interval_cancellation_and_owner_loss_end_initial_retries() {
        let stop = CancellationToken::new();
        let mut calls = 0;
        assert!(
            !retry_until_loaded(Duration::ZERO, &stop, || {
                calls += 1;
                std::future::ready(Some(false))
            })
            .await
        );
        assert_eq!(calls, 0);
        stop.cancel();
        assert!(
            !retry_until_loaded(Duration::from_secs(30), &stop, || {
                calls += 1;
                std::future::ready(Some(false))
            })
            .await
        );
        assert_eq!(calls, 0);
        let stop = CancellationToken::new();
        assert!(
            !retry_until_loaded(Duration::from_secs(30), &stop, || {
                calls += 1;
                std::future::ready(None)
            })
            .await
        );
        assert_eq!(calls, 1);
    }
}
