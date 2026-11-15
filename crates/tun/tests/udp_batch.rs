#![allow(clippy::unwrap_used, reason = "test setup and assertions")]

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{BoxStream, FlowKey, UdpReply};
use concord_tun::testing::fake_device;
use concord_tun::{FlowSink, IpStack, NetStack, StackOptions};
use support::udp_packet;
use tokio_util::sync::CancellationToken;

#[derive(Debug, PartialEq)]
enum Event {
    Begin,
    Udp(u8),
    End,
}

#[derive(Default)]
struct Recording(Mutex<Vec<Event>>);

impl Recording {
    fn push(&self, event: Event) {
        lock(&self.0).push(event);
    }
}

impl FlowSink for Recording {
    fn tcp(&self, _flow: FlowKey, _stream: BoxStream) {}

    fn udp(&self, _flow: FlowKey, payload: &[u8], _reply: &Arc<dyn UdpReply>) {
        self.push(Event::Udp(payload[0]));
    }

    fn udp_round(&self, round: &mut dyn FnMut()) {
        self.push(Event::Begin);
        round();
        self.push(Event::End);
    }
}

#[tokio::test]
async fn every_datagram_of_a_receive_round_is_handed_over_inside_one_batch() {
    let (device, net) = fake_device(64, 2048);
    for index in 0..5u8 {
        let datagram = udp_packet(
            "10.0.0.2:5000".parse().unwrap(),
            "8.8.4.4:9999".parse().unwrap(),
            &[index; 32],
        );
        assert!(net.inject(&datagram));
    }
    let sink = Arc::new(Recording::default());
    let stop = CancellationToken::new();
    let task = tokio::spawn(NetStack::new(StackOptions::default()).run(
        device,
        Arc::clone(&sink) as Arc<dyn FlowSink>,
        stop.clone(),
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let done = {
                let events = lock(&sink.0);
                let handed = events.iter().filter(|e| matches!(e, Event::Udp(_))).count();
                handed == 5 && events.last() == Some(&Event::End)
            };
            if done {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.cancel();
    task.await.unwrap().unwrap();

    let events = lock(&sink.0);
    let mut open = false;
    let mut batches_with_udp = Vec::new();
    for event in events.iter() {
        match event {
            Event::Begin => {
                assert!(!open, "a batch began inside another");
                open = true;
                batches_with_udp.push(Vec::new());
            }
            Event::End => {
                assert!(open, "a batch ended that never began");
                open = false;
            }
            Event::Udp(index) => {
                assert!(open, "datagram {index} was handed over outside a batch");
                batches_with_udp.last_mut().unwrap().push(*index);
            }
        }
    }
    assert!(!open);
    batches_with_udp.retain(|batch| !batch.is_empty());
    assert_eq!(batches_with_udp, vec![vec![0, 1, 2, 3, 4]]);
}
