use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use tokio::time::sleep;

const POLL: Duration = Duration::from_secs(2);
const SETTLE: Duration = Duration::from_millis(100);

type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &std::path::Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Notices a file being written or replaced by looking at its modification time and
/// size, which needs no per-platform watcher and no standing thread.
pub struct FileWatch {
    path: PathBuf,
    seen: Stamp,
    poll: Duration,
    settle: Duration,
}

impl FileWatch {
    pub fn new(path: PathBuf) -> Self {
        Self::with_timing(path, POLL, SETTLE)
    }

    pub fn with_timing(path: PathBuf, poll: Duration, settle: Duration) -> Self {
        let seen = stamp(&path);
        FileWatch {
            path,
            seen,
            poll,
            settle,
        }
    }

    /// Completes once the file differs from how it was last seen and has stopped changing
    /// for the settling time. A file that disappears is not a change; its return is.
    /// Safe to drop and call again.
    pub async fn changed(&mut self) {
        loop {
            sleep(self.poll).await;
            let now = stamp(&self.path);
            if now == self.seen || now.is_none() {
                continue;
            }
            let mut last = now;
            loop {
                sleep(self.settle).await;
                let again = stamp(&self.path);
                if again == last {
                    break;
                }
                last = again;
            }
            self.seen = last;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn watch(path: PathBuf) -> FileWatch {
        FileWatch::with_timing(path, Duration::from_millis(10), Duration::from_millis(20))
    }

    #[tokio::test]
    async fn a_rewrite_is_noticed_and_an_untouched_file_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        std::fs::write(&path, "a").unwrap();
        let mut watch = watch(path.clone());

        assert!(
            tokio::time::timeout(Duration::from_millis(150), watch.changed())
                .await
                .is_err()
        );
        std::fs::write(&path, "bb").unwrap();
        tokio::time::timeout(Duration::from_secs(5), watch.changed())
            .await
            .expect("the rewrite was not noticed");
        assert!(
            tokio::time::timeout(Duration::from_millis(150), watch.changed())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_file_that_goes_away_and_comes_back_counts_when_it_returns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.yaml");
        std::fs::write(&path, "a").unwrap();
        let mut watch = watch(path.clone());
        std::fs::remove_file(&path).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), watch.changed())
                .await
                .is_err()
        );
        std::fs::write(&path, "other").unwrap();
        tokio::time::timeout(Duration::from_secs(5), watch.changed())
            .await
            .expect("the file's return was not noticed");
    }
}
