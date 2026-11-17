use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};

use concord_common::sync::lock;
use tokio::sync::watch;

type Outcome = Option<Result<(), Arc<io::Error>>>;
type Flight = watch::Sender<Outcome>;

pub(crate) struct SessionSlot<T> {
    state: Mutex<State<T>>,
}

struct State<T> {
    cached: Option<T>,
    connecting: Option<Arc<Flight>>,
}

impl<T> SessionSlot<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                cached: None,
                connecting: None,
            }),
        }
    }

    pub(crate) fn take(&self) -> Option<T> {
        lock(&self.state).cached.take()
    }

    pub(crate) async fn get<R>(
        &self,
        cached: impl Fn(&mut Option<T>) -> Option<R>,
        dial: impl Future<Output = io::Result<(R, Option<T>)>>,
    ) -> io::Result<(R, bool)> {
        let mut reused = true;
        loop {
            let (mut outcome, turn) = {
                let mut state = lock(&self.state);
                if let Some(value) = cached(&mut state.cached) {
                    return Ok((value, reused));
                }
                reused = false;
                match &state.connecting {
                    Some(flight) => (flight.subscribe(), None),
                    None => {
                        let (flight, outcome) = watch::channel(None);
                        let flight = Arc::new(flight);
                        state.connecting = Some(Arc::clone(&flight));
                        (outcome, Some(Connecting { slot: self, flight }))
                    }
                }
            };
            if let Some(turn) = turn {
                return match dial.await {
                    Ok((value, session)) => {
                        turn.finish(session, Ok(()));
                        Ok((value, false))
                    }
                    Err(err) => {
                        let err = Arc::new(err);
                        turn.finish(None, Err(Arc::clone(&err)));
                        Err(io::Error::new(err.kind(), err))
                    }
                };
            }
            let result = outcome
                .wait_for(Option::is_some)
                .await
                .map_err(io::Error::other)?
                .clone();
            if let Some(Err(err)) = result {
                return Err(io::Error::new(err.kind(), err));
            }
        }
    }
}

struct Connecting<'a, T> {
    slot: &'a SessionSlot<T>,
    flight: Arc<Flight>,
}

impl<T> Connecting<'_, T> {
    fn finish(self, session: Option<T>, result: Result<(), Arc<io::Error>>) {
        let mut state = lock(&self.slot.state);
        if let Some(session) = session {
            state.cached = Some(session);
        }
        state.connecting = None;
        self.flight.send_replace(Some(result));
    }
}

impl<T> Drop for Connecting<'_, T> {
    fn drop(&mut self) {
        let mut state = lock(&self.slot.state);
        if state
            .connecting
            .as_ref()
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            state.connecting = None;
            self.flight.send_replace(Some(Err(Arc::new(io::Error::new(
                io::ErrorKind::Interrupted,
                "DNS session dial cancelled",
            )))));
        }
    }
}

#[cfg(test)]
mod tests;
