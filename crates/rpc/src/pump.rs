use std::time::Duration;

use futures_util::stream::BoxStream;
use futures_util::{FutureExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::dispatch::Encoded;
use crate::envelope::{event_params, notification, resync_params};

pub struct Pump {
    pub sub: u64,
    pub events: BoxStream<'static, Encoded>,
    pub credit: Arc<Semaphore>,
    pub batch_window: Duration,
    pub batch_bytes: usize,
    pub max_message: usize,
    pub token: CancellationToken,
    pub outbox: mpsc::Sender<Vec<u8>>,
}

enum Step {
    Event(Vec<u8>, u64),
    Resync,
    End,
}

async fn send(token: &CancellationToken, outbox: &mpsc::Sender<Vec<u8>>, message: Vec<u8>) -> bool {
    tokio::select! {
        biased;
        () = token.cancelled() => false,
        sent = outbox.send(message) => sent.is_ok(),
    }
}

impl Pump {
    /// Moves events to the peer one batch per credit. The stream is not polled
    /// without credit, so a consumer that stops refilling stops all production
    /// and encoding behind this point; what the producer does meanwhile is its
    /// stream's policy.
    pub async fn run(mut self) {
        let mut seq = 0u64;
        // The envelope at its widest, so a batch held under `room` always fits one message.
        let envelope = notification("$/event", &event_params(self.sub, u64::MAX, &[], u64::MAX));
        let room = self.max_message.saturating_sub(envelope.len());
        let mut held: Option<Step> = None;
        loop {
            let permit = tokio::select! {
                biased;
                () = self.token.cancelled() => return,
                permit = self.credit.acquire() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return,
                },
            };
            let mut step = match held.take() {
                Some(step) => step,
                None => tokio::select! {
                    biased;
                    () = self.token.cancelled() => return,
                    next = self.events.next() => Self::step(next),
                },
            };
            let mut batch: Vec<Vec<u8>> = Vec::new();
            let mut bytes = 0usize;
            let mut dropped = 0u64;
            let mut finished = false;
            let mut resync = false;
            loop {
                match step {
                    Step::Event(data, lost) if bytes + data.len() + 1 > room => {
                        if batch.is_empty() {
                            dropped += lost + 1;
                        } else {
                            held = Some(Step::Event(data, lost));
                            break;
                        }
                    }
                    Step::Event(data, lost) => {
                        bytes += data.len() + 1;
                        dropped += lost;
                        batch.push(data);
                    }
                    Step::Resync => {
                        resync = true;
                        break;
                    }
                    Step::End => {
                        finished = true;
                        break;
                    }
                }
                if batch.len() == 1 && !self.batch_window.is_zero() {
                    tokio::select! {
                        biased;
                        () = self.token.cancelled() => return,
                        () = sleep(self.batch_window) => {}
                    }
                }
                if bytes >= self.batch_bytes {
                    break;
                }
                match self.events.next().now_or_never() {
                    Some(next) => step = Self::step(next),
                    None => break,
                }
            }
            if !batch.is_empty() || dropped > 0 {
                seq += 1;
                let params = event_params(self.sub, seq, &batch, dropped);
                if !send(&self.token, &self.outbox, notification("$/event", &params)).await {
                    return;
                }
                permit.forget();
            }
            if resync {
                seq += 1;
                let message = notification("$/event", &resync_params(self.sub, seq));
                send(&self.token, &self.outbox, message).await;
                return;
            }
            if finished {
                return;
            }
        }
    }

    fn step(next: Option<Encoded>) -> Step {
        match next {
            Some(Encoded::Event { data, dropped }) => Step::Event(data, dropped),
            Some(Encoded::Resync) => Step::Resync,
            None => Step::End,
        }
    }
}
