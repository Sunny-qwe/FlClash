mod support;

use std::sync::Arc;
use std::time::Duration;

use concord_common::BoxStream;
use concord_tun::testing::fake_device;
use concord_tun::{IpStack, NetStack, StackOptions};
use support::{TcpPeer, channel_sink};
use tokio_util::sync::CancellationToken;

fn rss_kib() -> u64 {
    let pid = std::process::id().to_string();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

/// Run with `--ignored --nocapture`: opens 10,000 idle established flows and prints resident memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "memory measurement, slow in debug builds"]
async fn ten_thousand_idle_flows() {
    const FLOWS: usize = 10_000;
    const BATCH: usize = 100;
    let (device, net) = fake_device(256, 2048);
    let (sink, mut tcp_rx, _udp_rx) = channel_sink();
    let stop = CancellationToken::new();
    let options = StackOptions {
        max_tcp_flows: FLOWS + 10,
        ..StackOptions::default()
    };
    let stats = Arc::clone(&options.stats);
    let task = tokio::spawn(NetStack::new(options).run(device, sink, stop.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before = rss_kib();

    let mut streams: Vec<BoxStream> = Vec::with_capacity(FLOWS);
    let mut buf = vec![0u8; 2048];
    for first in (0..FLOWS).step_by(BATCH) {
        let mut peers: Vec<TcpPeer> = (first..first + BATCH)
            .map(|i| {
                TcpPeer::new(
                    &format!("10.1.{}.{}:{}", i / 250, i % 250 + 1, 20_000 + i % 40_000),
                    "93.184.216.34:443",
                )
            })
            .collect();
        for peer in &mut peers {
            assert!(net.inject(&peer.syn()));
        }
        let mut pending = BATCH;
        while pending > 0 {
            let n = net.take(&mut buf).await;
            let raw = &buf[..n];
            for peer in &mut peers {
                if let Some(seg) = peer.parse(raw) {
                    if seg.syn {
                        peer.absorb(&seg);
                        assert!(net.inject(&peer.ack()));
                        pending -= 1;
                    }
                    break;
                }
            }
        }
        for _ in 0..BATCH {
            streams.push(tcp_rx.recv().await.unwrap().1);
        }
    }
    let snapshot = stats.snapshot();
    let after = rss_kib();
    eprintln!(
        "10k idle flows: active {}, rss before {} KiB, after {} KiB, {:.1} KiB per flow",
        snapshot.tcp_active,
        before,
        after,
        (after.saturating_sub(before)) as f64 / FLOWS as f64
    );
    assert_eq!(snapshot.tcp_active, FLOWS);
    drop(streams);
    tokio::time::sleep(Duration::from_millis(500)).await;
    eprintln!(
        "after dropping the streams: rss {} KiB, active {}",
        rss_kib(),
        stats.snapshot().tcp_active
    );
    stop.cancel();
    task.await.unwrap().unwrap();
}
