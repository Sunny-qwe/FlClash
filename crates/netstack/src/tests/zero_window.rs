use super::*;
use crate::wire::{FLAG_ACK, TcpSegment};

fn segment(packet: &[u8]) -> TcpSegment<'_> {
    let Ok(Parsed::Packet(view)) = parse_packet(packet) else {
        panic!("invalid packet");
    };
    parse_tcp(view.l4).unwrap()
}

fn from_peer(stack: &mut TcpStack, out: &mut Wire, header: TcpHeader, payload: &[u8]) {
    let mut packet = vec![0; 2048];
    let options = TcpOptions {
        mss: (header.flags & FLAG_SYN != 0).then_some(1460),
        ..TcpOptions::default()
    };
    let len = emit_tcp(
        &mut packet,
        &header,
        &options,
        payload.len(),
        L4Checksum::Full,
        |body| {
            body.copy_from_slice(payload);
            Some(())
        },
    )
    .unwrap();
    let Ok(Parsed::Packet(view)) = parse_packet(&packet[..len]) else {
        panic!("invalid peer packet");
    };
    assert_eq!(
        stack.input(view.src, view.dst, view.l4, out, |_, _| Admit::Reject),
        TcpInput::Handled
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_ack_in_a_closed_peer_window_releases_duplex_backpressure() {
    for window in [0, 1024] {
        let mut stack = TcpStack::new(StackConfig::default());
        let mut out = Wire::default();
        let (local, remote) = addrs();
        let mut stream = stack.connect(local, remote, Congestion::Cubic).unwrap();
        stack.poll(&mut out);
        let start = segment(&out.packets.pop().unwrap()).seq.wrapping_add(1);
        let peer_start = u32::MAX - 2000;
        from_peer(
            &mut stack,
            &mut out,
            TcpHeader {
                src: remote,
                dst: local,
                seq: peer_start.wrapping_sub(1),
                ack: start,
                flags: FLAG_SYN | FLAG_ACK,
                window: 48,
            },
            &[],
        );
        stack.poll(&mut out);
        out.packets.clear();
        stream.write_all(&[7; 48]).await.unwrap();
        stack.poll(&mut out);
        let in_flight = out.packets.pop().unwrap();
        assert_eq!(segment(&in_flight).payload, &[7; 48]);
        out.packets.clear();

        let reply = pattern(2920, 3);
        for (i, payload) in reply.chunks(1460).enumerate() {
            from_peer(
                &mut stack,
                &mut out,
                TcpHeader {
                    src: remote,
                    dst: local,
                    seq: peer_start.wrapping_add((i * 1460) as u32),
                    ack: start,
                    flags: FLAG_ACK,
                    window,
                },
                payload,
            );
        }
        stack.poll(&mut out);
        let packet = out.packets.pop().unwrap();
        let ack = segment(&packet);
        assert!(ack.payload.is_empty());
        assert_eq!(ack.ack, peer_start.wrapping_add(reply.len() as u32));
        if window == 0 {
            // A strict zero-window receiver accepts only RCV.NXT, even for an ACK.
            assert_eq!(
                ack.seq, start,
                "the peer must accept the ACK to drain its echo queue"
            );
        } else {
            assert_eq!(ack.seq, start.wrapping_add(48));
        }
        let mut received = vec![0; reply.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, reply);
        stream.write_all(&[9; 48]).await.unwrap();
        out.packets.clear();

        from_peer(
            &mut stack,
            &mut out,
            TcpHeader {
                src: remote,
                dst: local,
                seq: ack.ack,
                ack: start.wrapping_add(48),
                flags: FLAG_ACK,
                window: 48,
            },
            &[],
        );
        stack.poll(&mut out);
        let packet = out.packets.pop().unwrap();
        let resumed = segment(&packet);
        assert_eq!(resumed.seq, start.wrapping_add(48));
        assert_eq!(resumed.payload, &[9; 48]);
    }
}
