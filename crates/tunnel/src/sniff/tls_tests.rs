use super::*;
use crate::sniff::testdata::{TLS_CLICKTALE, TLS_IP_NAME, TLS_MICROSOFT, TLS_SHORT_NAME};
use crate::sniff::testkit::{make_client_hello, make_tls_records};

#[test]
fn captured_client_hellos() {
    assert_eq!(sniff_tls(TLS_MICROSOFT).unwrap(), "c.s-microsoft.com");
    assert_eq!(sniff_tls(TLS_CLICKTALE).unwrap(), "www07.clicktale.net");
    assert_eq!(sniff_tls(TLS_SHORT_NAME).unwrap(), "dogfish");
    assert_eq!(sniff_tls(TLS_IP_NAME).unwrap(), "10.42.0.243");
}

#[test]
fn generated_client_hellos() {
    let hello = make_client_hello("example.com", 0);
    let with_trailing = [hello.clone(), vec![0x02, 0, 0, 0]].concat();
    let padded = make_client_hello("example.com", 4 * 1024);
    let padded_prefix_len = padded.len() - (4 + 4 * 1024);

    let across_records = make_tls_records(&hello, &[1, 2, 3, hello.len() / 2, hello.len() - 3]);
    assert_eq!(sniff_tls(&across_records).unwrap(), "example.com");

    let trailing = make_tls_records(&with_trailing, &[2]);
    assert_eq!(sniff_tls(&trailing).unwrap(), "example.com");

    let record = make_tls_records(&padded, &[]);
    let record = &record[..RECORD_HEADER_LEN + padded_prefix_len];
    assert_eq!(sniff_tls(record).unwrap(), "example.com");

    let fragmented = make_tls_records(&padded, &[2]);
    let fragmented = &fragmented[..2 * RECORD_HEADER_LEN + padded_prefix_len];
    assert_eq!(sniff_tls(fragmented).unwrap(), "example.com");

    let incomplete_tail = make_tls_records(&with_trailing, &[]);
    let incomplete_tail = &incomplete_tail[..RECORD_HEADER_LEN + hello.len()];
    assert_eq!(sniff_tls(incomplete_tail).unwrap(), "example.com");
}

#[test]
fn asks_for_the_exact_missing_prefix() {
    let hello = make_client_hello("example.com", 0);
    let fragmented = make_tls_records(&hello, &[2, hello.len() / 2]);
    let cases = [
        ("empty input", 0, RECORD_HEADER_LEN),
        ("one byte record header", 1, RECORD_HEADER_LEN),
        ("two byte record header", 2, RECORD_HEADER_LEN),
        ("three byte record header", 3, RECORD_HEADER_LEN),
        ("four byte record header", 4, RECORD_HEADER_LEN),
        (
            "record payload missing",
            RECORD_HEADER_LEN,
            RECORD_HEADER_LEN + 1,
        ),
        (
            "handshake type only",
            RECORD_HEADER_LEN + 1,
            RECORD_HEADER_LEN + 2,
        ),
        (
            "next record header missing",
            RECORD_HEADER_LEN + 2,
            2 * RECORD_HEADER_LEN + 2,
        ),
        (
            "final record payload incomplete",
            fragmented.len() - 1,
            fragmented.len(),
        ),
    ];
    for (name, have, need) in cases {
        assert_eq!(
            sniff_tls(&fragmented[..have]),
            Err(SniffError::NeedAtLeast(need)),
            "{name}"
        );
    }
}

#[test]
fn rejects_oversized_record_before_its_payload() {
    let input = [RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x40, 0x01];
    assert_eq!(sniff_tls(&input), Err(SniffError::NotTls));
}

#[test]
fn rejects_another_handshake_type_before_record_completion() {
    let input = [RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x40, 0x00, 0x02];
    assert_eq!(sniff_tls(&input), Err(SniffError::NotClientHello));
}

#[test]
fn rejects_invalid_client_hello_prefix_before_record_completion() {
    let mut hello = vec![0u8; 39];
    hello[0] = HANDSHAKE_TYPE_CLIENT_HELLO;
    hello[2] = 0x03;
    hello[3] = 0xe8;
    hello[38] = 33;
    let mut input = vec![RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x03, 0xec];
    input.extend_from_slice(&hello);
    assert_eq!(sniff_tls(&input), Err(SniffError::NotClientHello));
}

#[test]
fn rejects_absent_server_name_before_final_extension_payload() {
    let padding_len = 4 * 1024;
    let hello = make_client_hello("", padding_len);
    let mut input = make_tls_records(&hello, &[]);
    input.truncate(RECORD_HEADER_LEN + hello.len() - padding_len);
    assert_eq!(sniff_tls(&input), Err(SniffError::NotTls));
}

#[test]
fn rejects_trailing_dot_and_zero_length_records() {
    let hello = make_client_hello("example.com.", 0);
    let records = make_tls_records(&hello, &[]);
    assert_eq!(sniff_tls(&records), Err(SniffError::NotClientHello));
    assert_eq!(
        sniff_tls(&[RECORD_TYPE_HANDSHAKE, 3, 1, 0, 0]),
        Err(SniffError::NotClientHello)
    );
    assert_eq!(sniff_tls(&[0x17, 3, 3, 0, 1, 0]), Err(SniffError::NotTls));
}

#[test]
fn every_prefix_of_a_captured_hello_is_decided_without_panic() {
    for hello in [TLS_MICROSOFT, TLS_CLICKTALE, TLS_SHORT_NAME, TLS_IP_NAME] {
        for end in 0..=hello.len() {
            let result = sniff_tls(&hello[..end]);
            if let Err(SniffError::NeedAtLeast(length)) = result {
                assert!(length > end, "a need must go beyond the {end} bytes held");
            }
        }
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let hello = make_client_hello("example.com", 64);
    for round in 0..4000 {
        let len = (next() % 300) as usize;
        let mut data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        if round % 2 == 0 {
            let mut shaped = make_tls_records(&hello, &[round % 7, 40]);
            for _ in 0..(next() % 6) {
                let at = (next() as usize) % shaped.len();
                shaped[at] = next() as u8;
            }
            shaped.truncate((next() as usize) % (shaped.len() + 1));
            data = shaped;
        }
        let _ = sniff_tls(&data);
        let _ = read_client_hello(&data);
    }
}
