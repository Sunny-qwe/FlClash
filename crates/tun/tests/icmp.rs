mod support;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{BoxStream, FlowKey, IcmpAnswer, UdpReply};
use concord_tun::testing::fake_device;
use concord_tun::{FlowSink, IpStack, NetStack, StackOptions};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, IpProtocol};
use support::{split_ip, wrap_ip};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Forwarder {
    held: Mutex<Vec<(IpAddr, Vec<u8>, IcmpAnswer)>>,
}

impl FlowSink for Forwarder {
    fn tcp(&self, _flow: FlowKey, _stream: BoxStream) {}

    fn udp(&self, _flow: FlowKey, _payload: &[u8], _reply: &Arc<dyn UdpReply>) {}

    fn icmp(&self, dst: IpAddr, message: &[u8], answer: IcmpAnswer) -> bool {
        lock(&self.held).push((dst, message.to_vec(), answer));
        true
    }
}

fn echo_request(src: IpAddr, dst: IpAddr) -> Vec<u8> {
    let repr = Icmpv4Repr::EchoRequest {
        ident: 7,
        seq_no: 3,
        data: b"abcd",
    };
    let mut l4 = vec![0u8; repr.buffer_len()];
    repr.emit(
        &mut Icmpv4Packet::new_unchecked(&mut l4[..]),
        &ChecksumCapabilities::default(),
    );
    wrap_ip(src, dst, IpProtocol::Icmp, &l4)
}

#[tokio::test]
async fn a_forwarded_echo_is_answered_when_the_sink_says_so() {
    let (device, net) = fake_device(256, 2048);
    let sink = Arc::new(Forwarder::default());
    let stop = CancellationToken::new();
    let options = StackOptions {
        mtu: 1500,
        ..StackOptions::default()
    };
    let task = tokio::spawn(NetStack::new(options).run(device, sink.clone(), stop.clone()));
    let (src, dst): (IpAddr, IpAddr) = ("10.0.0.2".parse().unwrap(), "1.1.1.1".parse().unwrap());

    net.inject(&echo_request(src, dst));
    timeout(Duration::from_secs(2), async {
        while lock(&sink.held).is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        timeout(Duration::from_millis(200), net.take_vec())
            .await
            .is_err()
    );

    let (seen, message, answer) = lock(&sink.held).pop().unwrap();
    assert_eq!(seen, dst);
    assert_eq!(message.first(), Some(&8));
    answer();
    let raw = timeout(Duration::from_secs(2), net.take_vec())
        .await
        .unwrap();
    let (from, to, l4) = split_ip(&raw).unwrap();
    assert_eq!((from, to), (dst, src));
    assert_eq!(l4.first(), Some(&0));

    stop.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn disabled_forwarding_never_reaches_the_sink() {
    let (device, net) = fake_device(256, 2048);
    let sink = Arc::new(Forwarder::default());
    let stop = CancellationToken::new();
    let options = StackOptions {
        mtu: 1500,
        disable_icmp_forwarding: true,
        ..StackOptions::default()
    };
    let task = tokio::spawn(NetStack::new(options).run(device, sink.clone(), stop.clone()));
    let (src, dst): (IpAddr, IpAddr) = ("10.0.0.2".parse().unwrap(), "1.1.1.1".parse().unwrap());

    net.inject(&echo_request(src, dst));
    let raw = timeout(Duration::from_secs(2), net.take_vec())
        .await
        .unwrap();
    assert_eq!(split_ip(&raw).unwrap().0, dst);
    assert!(lock(&sink.held).is_empty());

    stop.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
