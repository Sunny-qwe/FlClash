use super::*;
use crate::sniff::quic_crypto::{self, DRAFT_29, Labels, V1, V2};
use crate::sniff::testdata::{
    QUIC_CLOUDFLARE, QUIC_GOOGLE, QUIC_MANY_OUT_OF_ORDER, QUIC_NGINX, QUIC_OPENAI,
    QUIC_OUT_OF_ORDER, QUIC_V2, QUIC_ZERO_RTT,
};
use crate::sniff::testkit::make_client_hello;

fn sniffer() -> QuicSniffer {
    QuicSniffer::new(Policy::permissive(), true)
}

fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

fn varint(value: u64) -> Vec<u8> {
    match value {
        0..=63 => vec![value as u8],
        64..=16383 => ((value as u16) | 0x4000).to_be_bytes().to_vec(),
        _ => ((value as u32) | 0x8000_0000).to_be_bytes().to_vec(),
    }
}

fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![FRAME_CRYPTO];
    frame.extend(varint(offset));
    frame.extend(varint(data.len() as u64));
    frame.extend_from_slice(data);
    frame
}

/// A protected Initial packet and the offset of its packet number.
fn protected_initial(
    version: &Version,
    dest_conn_id: &[u8],
    labels: &Labels,
    packet_number: i64,
    packet_number_len: usize,
    plaintext: &[u8],
) -> (Vec<u8>, usize) {
    let mut header = vec![0xc0 | (version.type_initial << 4) | (packet_number_len as u8 - 1)];
    header.extend_from_slice(&version.id.to_be_bytes());
    header.push(dest_conn_id.len() as u8);
    header.extend_from_slice(dest_conn_id);
    header.extend_from_slice(&[0, 0]);
    header.extend(varint((packet_number_len + plaintext.len() + 16) as u64));
    let pn_offset = header.len();
    for shift in (0..packet_number_len).rev() {
        header.push((packet_number as u64 >> (shift * 8)) as u8);
    }

    let mut packet = header.clone();
    packet.extend(labels.seal_for_test(packet_number, &header, plaintext));
    let mask = labels
        .mask_for_test(&packet[pn_offset + 4..pn_offset + 20])
        .unwrap();
    packet[0] ^= mask[0] & 0x0f;
    for i in 0..packet_number_len {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    (packet, pn_offset)
}

fn feed_all(sniffer: &mut QuicSniffer, packets: &[Vec<u8>]) {
    for packet in packets {
        sniffer.feed(packet);
    }
}

fn with_stale_keys(sniffer: &mut QuicSniffer, first_packet: &[u8]) {
    let version = sniffer.version_for(&first_packet[1..5]).unwrap();
    sniffer
        .initial_keys
        .push(InitialKey::new(b"stale initial dcid", version).unwrap());
}

fn orderings(packets: &[Vec<u8>]) -> Vec<Vec<Vec<u8>>> {
    let mut reversed = packets.to_vec();
    reversed.reverse();
    let mut rotated = packets.to_vec();
    rotated.rotate_left(1);
    vec![packets.to_vec(), reversed, rotated]
}

struct Vector {
    name: &'static str,
    packets: &'static [&'static str],
    domain: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        name: "single packet google",
        packets: QUIC_GOOGLE,
        domain: "www.google.com",
    },
    Vector {
        name: "single packet cloudflare",
        packets: QUIC_CLOUDFLARE,
        domain: "cloudflare-dns.com",
    },
    Vector {
        name: "fragmented nginx",
        packets: QUIC_NGINX,
        domain: "quic.nginx.org",
    },
    Vector {
        name: "fragmented openai",
        packets: QUIC_OPENAI,
        domain: "chat.openai.com",
    },
    Vector {
        name: "fragmented with zero rtt",
        packets: QUIC_ZERO_RTT,
        domain: "fonts.gstatic.com",
    },
    Vector {
        name: "out of order duplicate fragments",
        packets: QUIC_OUT_OF_ORDER,
        domain: "ogads-pa.clients6.google.com",
    },
    Vector {
        name: "many out of order fragments",
        packets: QUIC_MANY_OUT_OF_ORDER,
        domain: "www.google.com",
    },
    Vector {
        name: "quic v2 fragmented",
        packets: QUIC_V2,
        domain: "test.example.com",
    },
];

#[test]
fn captured_handshakes() {
    for vector in VECTORS {
        let packets: Vec<Vec<u8>> = vector.packets.iter().map(|p| unhex(p)).collect();
        for stale in [false, true] {
            for (n, order) in orderings(&packets).iter().enumerate() {
                let mut q = sniffer();
                if stale {
                    with_stale_keys(&mut q, &packets[0]);
                }
                feed_all(&mut q, order);
                let mode = format!("{} stale={stale} order={n}", vector.name);
                assert_eq!(q.result(), Some(vector.domain), "{mode}");
                assert!(q.finished(), "{mode}");
            }
        }
    }
}

#[test]
fn coalesced_initial_packets() {
    let joined: Vec<u8> = QUIC_NGINX.iter().flat_map(|p| unhex(p)).collect();
    let mut q = sniffer();
    q.feed(&joined);
    assert_eq!(q.result(), Some("quic.nginx.org"));
}

#[test]
fn invalid_packet_finishes_without_a_result() {
    let mut q = sniffer();
    q.feed(&unhex("00000000000000000000"));
    assert!(q.finished());
    assert_eq!(q.result(), None);
}

#[test]
fn a_finished_sniffer_ignores_further_packets() {
    let mut q = sniffer();
    q.feed(&unhex(QUIC_GOOGLE[0]));
    assert_eq!(q.result(), Some("www.google.com"));
    q.feed(&unhex(QUIC_CLOUDFLARE[0]));
    assert_eq!(q.result(), Some("www.google.com"));
}

#[test]
fn client_hello_followed_by_crypto_data() {
    let mut hello = make_client_hello("example.com", 0);
    hello.extend_from_slice(&[0x02, 0, 0, 0]);
    let mut q = sniffer();
    q.add_crypto_data(0, &hello).unwrap();
    assert_eq!(q.try_assemble(), Ok(Some("example.com".to_string())));
}

#[test]
fn one_byte_gap_remains_incomplete() {
    let hello = make_client_hello("example.com", 0);
    let mut q = sniffer();
    q.add_crypto_data(0, &hello[..1]).unwrap();
    q.add_crypto_data(2, &hello[2..]).unwrap();
    assert_eq!(q.try_assemble(), Ok(None));
    assert_eq!(q.contiguous_end, 1);

    q.add_crypto_data(1, &hello[1..2]).unwrap();
    assert_eq!(q.try_assemble(), Ok(Some("example.com".to_string())));
}

#[test]
fn many_sparse_fragments() {
    let hello = make_client_hello("example.com", 4 * 1024);
    let mut q = sniffer();
    for i in (0..hello.len()).step_by(2) {
        q.add_crypto_data(i as u64, &hello[i..i + 1]).unwrap();
    }
    assert_eq!(q.contiguous_end, 1);
    for i in (1..hello.len()).step_by(2) {
        q.add_crypto_data(i as u64, &hello[i..i + 1]).unwrap();
    }
    assert_eq!(q.try_assemble(), Ok(Some("example.com".to_string())));
}

#[test]
fn client_hello_larger_than_16_kib() {
    let hello = make_client_hello("example.com", 20 * 1024);
    assert!(hello.len() > 16 * 1024);
    let mut q = sniffer();
    q.add_crypto_data(0, &hello[..4096]).unwrap();
    assert_eq!(q.crypto.len(), 4096);
    q.add_crypto_data(4096, &hello[4096..]).unwrap();
    assert_eq!(q.crypto.len(), hello.len());
    assert_eq!(q.try_assemble(), Ok(Some("example.com".to_string())));
}

#[test]
fn server_name_before_client_hello_padding() {
    let padding_len = 20 * 1024;
    let hello = make_client_hello("example.com", padding_len);
    let prefix_len = hello.len() - (4 + padding_len);
    let mut q = sniffer();
    q.add_crypto_data(0, &hello[..prefix_len]).unwrap();
    assert!(q.contiguous_end < hello.len());
    assert_eq!(q.try_assemble(), Ok(Some("example.com".to_string())));
}

#[test]
fn crypto_data_is_bounded() {
    let mut q = sniffer();
    assert_eq!(
        q.add_crypto_data(MAX_CRYPTO_STREAM_OFFSET as u64, &[1]),
        Err(SniffError::ShortBuffer)
    );
    assert_eq!(
        q.add_crypto_data(u64::MAX, &[1]),
        Err(SniffError::ShortBuffer)
    );
    assert_eq!(
        q.add_crypto_data(MAX_CRYPTO_STREAM_OFFSET as u64 - 1, &[1]),
        Ok(())
    );

    let mut q = sniffer();
    q.add_crypto_data(0, &[1, 1, 0, 0]).unwrap();
    assert_eq!(q.try_assemble(), Err(SniffError::ShortBuffer));
}

#[test]
fn packet_number_decoding() {
    let cases = [
        ("first packet", -1, 1, 0, 0),
        ("next window", 127, 1, 0, 256),
        ("previous window", 382, 1, 0, 256),
        ("following window", 383, 1, 0, 512),
        ("rfc 9000 appendix a.3", 0xa82f30ea, 2, 0x9b32, 0xa82f9b32),
    ];
    for (name, largest, length, truncated, expected) in cases {
        assert_eq!(
            quic_crypto::decode_packet_number(length, largest, truncated),
            expected,
            "{name}"
        );
    }
}

#[test]
fn uses_reconstructed_packet_number_in_nonce() {
    let dest_conn_id = b"initial dcid";
    let labels = Labels::derive(dest_conn_id, &V1).unwrap();
    let plaintext = b"initial payload";
    let (packet, pn_offset) = protected_initial(&V1, dest_conn_id, &labels, 256, 1, plaintext);

    let (decrypted, packet_number) =
        decrypt_initial(&packet, pn_offset, packet.len(), &labels, 127).unwrap();
    assert_eq!(packet_number, 256);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn retains_retry_epoch_across_header_dcid_changes() {
    let original = b"original dcid";
    let retry = b"retry dcid";
    let retry_key = InitialKey::new(retry, &V1).unwrap();
    let mut original_key = InitialKey::new(original, &V1).unwrap();
    original_key.largest_packet_number = 200;
    let mut q = sniffer();
    q.initial_keys = vec![original_key];

    let plaintext = b"retry payload";
    let (packet, pn_offset) = protected_initial(&V1, retry, &retry_key.labels, 256, 1, plaintext);
    let decrypted = q
        .decrypt_initial_packet(&packet, pn_offset, packet.len(), retry, &V1)
        .unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(q.initial_keys.len(), 2);
    assert_eq!(q.initial_keys[1].largest_packet_number, 256);

    let plaintext = b"changed dcid payload";
    let (packet, pn_offset) =
        protected_initial(&V1, original, &retry_key.labels, 257, 1, plaintext);
    let decrypted = q
        .decrypt_initial_packet(&packet, pn_offset, packet.len(), original, &V1)
        .unwrap();
    assert_eq!(decrypted, plaintext);
    assert_eq!(q.initial_keys[1].largest_packet_number, 257);
}

#[test]
fn continues_after_a_delayed_packet_outside_the_reconstruction_window() {
    let dest_conn_id = b"initial dcid";
    let mut key = InitialKey::new(dest_conn_id, &V1).unwrap();
    key.largest_packet_number = 200;
    let mut q = sniffer();
    q.version = Some(&V1);
    let labels = Labels::derive(dest_conn_id, &V1).unwrap();
    q.initial_keys = vec![key];

    let (delayed, _) = protected_initial(
        &V1,
        dest_conn_id,
        &labels,
        0,
        1,
        &[FRAME_PING, FRAME_PADDING, FRAME_PADDING],
    );
    q.feed(&delayed);
    assert!(!q.finished());

    let hello = make_client_hello("example.com", 0);
    let (next, _) = protected_initial(&V1, dest_conn_id, &labels, 201, 1, &crypto_frame(0, &hello));
    q.feed(&next);
    assert_eq!(q.result(), Some("example.com"));
}

#[test]
fn every_version_decodes_a_generated_initial() {
    for version in [&DRAFT_29, &V1, &V2] {
        let dest_conn_id = [7u8; 8];
        let labels = Labels::derive(&dest_conn_id, version).unwrap();
        let hello = make_client_hello("generated.example", 0);
        let mut frames = vec![FRAME_PING];
        frames.extend(crypto_frame(0, &hello));
        frames.extend([FRAME_PADDING; 40]);
        for packet_number_len in 1..=4 {
            let (packet, _) = protected_initial(
                version,
                &dest_conn_id,
                &labels,
                5,
                packet_number_len,
                &frames,
            );
            let mut q = sniffer();
            q.feed(&packet);
            assert_eq!(q.result(), Some("generated.example"), "{:#x}", version.id);
        }
    }
}

#[test]
fn retry_and_short_header_packets_consume_the_rest_of_the_datagram() {
    let dest_conn_id = [9u8; 8];
    let labels = Labels::derive(&dest_conn_id, &V1).unwrap();
    let hello = make_client_hello("retry.example", 0);
    let (initial, _) =
        protected_initial(&V1, &dest_conn_id, &labels, 0, 1, &crypto_frame(0, &hello));

    let mut datagram = initial.clone();
    datagram.extend_from_slice(&[0x40, 1, 2, 3, 4, 5]);
    let mut q = sniffer();
    q.feed(&datagram);
    assert_eq!(q.result(), Some("retry.example"));

    let retry = [vec![0xf0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0], vec![0xaa; 20]].concat();
    let mut q = sniffer();
    q.feed(&retry);
    assert!(!q.finished());
    assert_eq!(q.result(), None);

    let mut q = sniffer();
    q.feed(&[0x40, 1, 2, 3]);
    assert!(q.finished());
}

#[test]
fn rejects_reason_length_larger_than_remaining_data() {
    let mut data = vec![FRAME_CONNECTION_CLOSE, 0, 0];
    data.extend_from_slice(&[0xff; 8]);
    assert_eq!(sniffer().read_frames(&data), Err(SniffError::UnexpectedEof));
}

#[test]
fn frames_other_than_the_initial_set_are_rejected() {
    assert_eq!(
        sniffer().read_frames(&[0x08]),
        Err(SniffError::NotQuicInitial)
    );
    let mut ack = vec![FRAME_ACK_WITH_ECN, 5, 0, 1, 0, 1, 1, 0, 0, 0];
    assert_eq!(sniffer().read_frames(&ack), Ok(()));
    ack.truncate(8);
    assert_eq!(sniffer().read_frames(&ack), Err(SniffError::UnexpectedEof));
    assert_eq!(
        sniffer().read_frames(&[FRAME_CRYPTO, 0, 5, 1]),
        Err(SniffError::UnexpectedEof)
    );
}

#[test]
fn random_bytes_never_panic() {
    let mut state = 0x0123_4567_89ab_cdefu64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let seeds: Vec<Vec<u8>> = QUIC_NGINX
        .iter()
        .chain(QUIC_V2.iter())
        .map(|p| unhex(p))
        .collect();
    for round in 0..600 {
        let mut data: Vec<u8> = (0..(next() % 1300)).map(|_| next() as u8).collect();
        if round % 3 != 0 {
            data = seeds[round % seeds.len()].clone();
            for _ in 0..(next() % 6) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
            data.truncate((next() as usize) % (data.len() + 1));
        }
        let mut q = sniffer();
        q.feed(&data);
        q.feed(&data);
        let _ = sniffer().read_frames(&data);
        let mut q = sniffer();
        let _ = q.add_crypto_data(next() % 70_000, &data);
        let _ = q.try_assemble();
    }
}
