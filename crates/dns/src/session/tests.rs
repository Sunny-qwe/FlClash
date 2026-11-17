use super::*;
use futures_util::{FutureExt, poll};

fn cached(slot: &mut Option<usize>) -> Option<usize> {
    *slot
}

#[tokio::test]
async fn concurrent_callers_share_a_successful_dial() {
    let slot = SessionSlot::new();
    let (send, recv) = tokio::sync::oneshot::channel();
    let first = slot.get(cached, async {
        recv.await.unwrap();
        Ok((7, Some(7)))
    });
    tokio::pin!(first);
    assert!(poll!(&mut first).is_pending());
    let mut waiters: Vec<_> = (0..16)
        .map(|_| slot.get(cached, async { panic!("duplicate dial") }).boxed())
        .collect();
    for waiter in &mut waiters {
        assert!(poll!(waiter).is_pending());
    }
    send.send(()).unwrap();
    assert_eq!(first.await.unwrap(), (7, false));
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap(), (7, false));
    }
    assert_eq!(
        slot.get(cached, async { panic!("cached") }).await.unwrap(),
        (7, true)
    );
}

#[tokio::test]
async fn only_the_waiting_batch_shares_a_dial_error() {
    let slot = SessionSlot::new();
    let (send, recv) = tokio::sync::oneshot::channel();
    let first = slot.get(cached, async {
        recv.await.unwrap();
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "dial failed",
        ))
    });
    tokio::pin!(first);
    assert!(poll!(&mut first).is_pending());
    let mut waiters: Vec<_> = (0..16)
        .map(|_| {
            slot.get(cached, async { panic!("duplicate failed dial") })
                .boxed()
        })
        .collect();
    for waiter in &mut waiters {
        assert!(poll!(waiter).is_pending());
    }
    send.send(()).unwrap();
    let first = first.await.unwrap_err();
    // A new caller can succeed before the old waiters consume their error.
    assert_eq!(
        slot.get(cached, async { Ok((9, Some(9))) }).await.unwrap(),
        (9, false)
    );
    for waiter in waiters {
        let err = waiter.await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(err.to_string(), "dial failed");
        let shared = |err: &io::Error| {
            Arc::as_ptr(
                err.get_ref()
                    .unwrap()
                    .downcast_ref::<Arc<io::Error>>()
                    .unwrap(),
            )
        };
        assert_eq!(shared(&first), shared(&err));
    }
}

#[tokio::test]
async fn cancelling_the_dial_releases_waiters_and_allows_another_dial() {
    let slot = SessionSlot::new();
    let mut first = slot.get(cached, std::future::pending()).boxed();
    assert!(poll!(&mut first).is_pending());
    let mut waiter = slot.get(cached, async { panic!("duplicate dial") }).boxed();
    assert!(poll!(&mut waiter).is_pending());
    drop(first);
    assert_eq!(waiter.await.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert_eq!(
        slot.get(cached, async { Ok((1, Some(1))) }).await.unwrap(),
        (1, false)
    );
    assert_eq!(slot.take(), Some(1));
    assert_eq!(
        slot.get(cached, async { Ok((2, Some(2))) }).await.unwrap(),
        (2, false)
    );
}

#[tokio::test]
async fn an_uncached_sender_keeps_its_own_connection() {
    let slot = SessionSlot::<usize>::new();
    assert_eq!(
        slot.get(cached, async { Ok((1, None)) }).await.unwrap(),
        (1, false)
    );
    assert_eq!(
        slot.get(cached, async { Ok((2, None)) }).await.unwrap(),
        (2, false)
    );
}
