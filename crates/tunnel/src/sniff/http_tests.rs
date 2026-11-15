use super::*;

const DOMAIN: &str = "example.com";
const FIRST_SPLIT: usize = 4;
const SECOND_SPLIT: usize = 9;

fn header_block() -> Vec<u8> {
    let mut block = vec![0x41, DOMAIN.len() as u8];
    block.extend_from_slice(DOMAIN.as_bytes());
    block
}

fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        frame_type,
        flags,
    ];
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn h2_input(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut input = H2_CLIENT_PREFACE.to_vec();
    input.extend(frame(H2_FRAME_SETTINGS, 0, 0, &[]));
    for f in frames {
        input.extend_from_slice(f);
    }
    input
}

fn frame_header(frame_type: u8, flags: u8, stream_id: u32, len: usize) -> Vec<u8> {
    frame(frame_type, flags, stream_id, &vec![0; len])[..H2_FRAME_HEADER_LEN].to_vec()
}

fn sniff(data: &[u8]) -> Result<String, SniffError> {
    HttpSniffer.sniff(data)
}

#[test]
fn http1_requests() {
    let ok = [
        ("origin form", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        (
            "uppercase host",
            "GET / HTTP/1.1\r\nHost: EXAMPLE.COM\r\n\r\n",
        ),
        (
            "host before end of headers",
            "GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: ",
        ),
        (
            "absolute form",
            "GET http://example.com/path HTTP/1.1\r\n\r\n",
        ),
        (
            "method case",
            "get / HTTP/1.1\r\nHOST:   example.com  \r\n\r\n",
        ),
        (
            "port and dot",
            "GET / HTTP/1.1\r\nHost: Example.com.:8080\r\n\r\n",
        ),
        (
            "userinfo",
            "GET http://user:pw@example.com:81/x HTTP/1.1\r\n\r\n",
        ),
    ];
    for (name, input) in ok {
        assert_eq!(sniff(input.as_bytes()).unwrap(), DOMAIN, "{name}");
    }
    assert_eq!(
        sniff(b"GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n"),
        Err(SniffError::HostIsIp)
    );
    assert_eq!(
        sniff(b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n"),
        Err(SniffError::HostIsIp)
    );
}

#[test]
fn http1_absolute_form_with_ip_falls_back_to_the_host_header() {
    let input = b"GET http://1.2.3.4/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(sniff(input).unwrap(), DOMAIN);
}

#[test]
fn http1_host_is_trimmed_of_unicode_white_space() {
    let input = "GET / HTTP/1.1\r\nHost: \u{a0}\u{3000}example.com\u{2003}\u{85} \r\n\r\n";
    assert_eq!(sniff(input.as_bytes()).unwrap(), DOMAIN);
    assert_eq!(trim_space(b"\xff \xc2\xa0"), b"\xff");
    assert_eq!(trim_space(b" \t\x0b\x0c"), b"");
}

#[test]
fn http1_rejects_non_http_prefix() {
    assert_eq!(
        sniff(&[0x16, 0x03, 0x01, 0x00, 0x20]),
        Err(SniffError::NotHttp)
    );
}

#[test]
fn http1_waits_for_a_partial_method() {
    assert_eq!(sniff(b"GE"), Err(SniffError::NeedAtLeast(3)));
}

#[test]
fn http1_waits_for_a_complete_host_line() {
    let input = b"GET / HTTP/1.1\r\nHost: example";
    assert_eq!(sniff(input), Err(SniffError::NeedAtLeast(input.len() + 1)));
}

#[test]
fn http2_header_blocks() {
    let block = header_block();
    let cases: Vec<(&str, Vec<u8>, Result<&str, SniffError>)> = vec![
        (
            "single headers frame",
            h2_input(&[frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &block)]),
            Ok(DOMAIN),
        ),
        (
            "continuations",
            h2_input(&[
                frame(H2_FRAME_HEADERS, 0, 1, &block[..FIRST_SPLIT]),
                frame(
                    H2_FRAME_CONTINUATION,
                    0,
                    1,
                    &block[FIRST_SPLIT..SECOND_SPLIT],
                ),
                frame(
                    H2_FRAME_CONTINUATION,
                    H2_FLAG_END_HEADERS,
                    1,
                    &block[SECOND_SPLIT..],
                ),
            ]),
            Ok(DOMAIN),
        ),
        (
            "continuation on another stream",
            h2_input(&[
                frame(H2_FRAME_HEADERS, 0, 1, &block[..FIRST_SPLIT]),
                frame(
                    H2_FRAME_CONTINUATION,
                    H2_FLAG_END_HEADERS,
                    3,
                    &block[FIRST_SPLIT..],
                ),
            ]),
            Err(SniffError::NoClue),
        ),
        (
            "interleaved frame",
            h2_input(&[
                frame(H2_FRAME_HEADERS, 0, 1, &block[..FIRST_SPLIT]),
                frame(H2_FRAME_SETTINGS, 0, 0, &[]),
                frame(
                    H2_FRAME_CONTINUATION,
                    H2_FLAG_END_HEADERS,
                    1,
                    &block[FIRST_SPLIT..],
                ),
            ]),
            Err(SniffError::NoClue),
        ),
        (
            "authority before incomplete frame payload",
            {
                let mut payload = block.clone();
                payload.extend(vec![0; 1024]);
                let full = frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &payload);
                h2_input(&[full[..H2_FRAME_HEADER_LEN + block.len()].to_vec()])
            },
            Ok(DOMAIN),
        ),
        (
            "authority before invalid trailing hpack",
            {
                let mut payload = block.clone();
                payload.push(0x80);
                h2_input(&[frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &payload)])
            },
            Ok(DOMAIN),
        ),
        (
            "host header",
            {
                let mut payload = vec![0x66, 0x0b];
                payload.extend_from_slice(b"Example.Com");
                h2_input(&[frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &payload)])
            },
            Ok(DOMAIN),
        ),
        (
            "padded and prioritized headers",
            {
                let mut payload = vec![3, 0, 0, 0, 0, 0];
                payload.extend_from_slice(&block);
                payload.extend_from_slice(&[0, 0, 0]);
                let flags = H2_FLAG_END_HEADERS | H2_FLAG_PADDED | H2_FLAG_PRIORITY;
                h2_input(&[frame(H2_FRAME_HEADERS, flags, 1, &payload)])
            },
            Ok(DOMAIN),
        ),
        (
            "other frames before the headers",
            h2_input(&[
                frame(0x0, 0, 1, &[1, 2, 3]),
                frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 3, &block),
            ]),
            Ok(DOMAIN),
        ),
    ];
    for (name, input, want) in cases {
        assert_eq!(sniff(&input), want.map(str::to_string), "{name}");
    }
}

#[test]
fn http2_reads_the_preface_incrementally() {
    for end in [1, 3, H2_CLIENT_PREFACE.len() - 1] {
        assert_eq!(
            sniff(&H2_CLIENT_PREFACE[..end]),
            Err(SniffError::NeedAtLeast(end + 1))
        );
    }
}

#[test]
fn http2_rejects_invalid_frame_headers_before_payload() {
    let block = header_block();
    let cases = [
        (
            "first frame is not settings",
            [H2_CLIENT_PREFACE.to_vec(), frame_header(0x0, 0, 1, 1024)].concat(),
        ),
        (
            "first settings is an ack",
            [
                H2_CLIENT_PREFACE.to_vec(),
                frame_header(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, 0),
            ]
            .concat(),
        ),
        (
            "frame exceeds default maximum",
            h2_input(&[frame_header(
                H2_FRAME_HEADERS,
                0,
                1,
                H2_DEFAULT_MAX_FRAME_SIZE + 1,
            )]),
        ),
        (
            "invalid settings length",
            [
                H2_CLIENT_PREFACE.to_vec(),
                frame_header(H2_FRAME_SETTINGS, 0, 0, 1),
            ]
            .concat(),
        ),
        (
            "unexpected continuation",
            h2_input(&[frame_header(H2_FRAME_CONTINUATION, 0, 1, 1024)]),
        ),
        (
            "headers on stream zero",
            h2_input(&[frame_header(H2_FRAME_HEADERS, 0, 0, 1024)]),
        ),
        (
            "interleaved frame",
            h2_input(&[
                frame(H2_FRAME_HEADERS, 0, 1, &block[..FIRST_SPLIT]),
                frame_header(H2_FRAME_SETTINGS, 0, 0, 0),
            ]),
        ),
    ];
    for (name, input) in cases {
        assert_eq!(sniff(&input), Err(SniffError::NoClue), "{name}");
    }
}

#[test]
fn http2_continuation_header_missing() {
    let block = header_block();
    let input = h2_input(&[frame(H2_FRAME_HEADERS, 0, 1, &block[..FIRST_SPLIT])]);
    assert_eq!(
        sniff(&input),
        Err(SniffError::NeedAtLeast(input.len() + H2_FRAME_HEADER_LEN))
    );
}

#[test]
fn http2_continuation_payload_incomplete() {
    let block = header_block();
    let complete = h2_input(&[
        frame(H2_FRAME_HEADERS, 0, 1, &block[..FIRST_SPLIT]),
        frame(
            H2_FRAME_CONTINUATION,
            H2_FLAG_END_HEADERS,
            1,
            &block[FIRST_SPLIT..],
        ),
    ]);
    assert_eq!(
        sniff(&complete[..complete.len() - 1]),
        Err(SniffError::NeedAtLeast(complete.len()))
    );
}

#[test]
fn http2_rejects_missing_authority_before_frame_padding() {
    let padding_len = 128usize;
    let mut payload = vec![padding_len as u8, 0x82];
    payload.extend(vec![0; padding_len]);
    let flags = H2_FLAG_END_HEADERS | H2_FLAG_PADDED;
    let mut input = h2_input(&[frame(H2_FRAME_HEADERS, flags, 1, &payload)]);
    input.truncate(input.len() - padding_len);
    assert_eq!(sniff(&input), Err(SniffError::NoClue));
}

#[test]
fn parse_host_follows_go_split_host_port() {
    assert_eq!(parse_host(b"Example.COM:443").unwrap(), DOMAIN);
    assert_eq!(parse_host(b"example.com:").unwrap(), DOMAIN);
    assert_eq!(parse_host(b"[::1]:443"), Err(SniffError::HostIsIp));
    assert_eq!(parse_host(b"fe80::1%eth0"), Err(SniffError::HostIsIp));
    assert_eq!(parse_host(b"[fe80::1%25eth0]"), Err(SniffError::HostIsIp));
    assert_eq!(parse_host(b""), Err(SniffError::NoClue));
    assert_eq!(parse_host(b"..."), Err(SniffError::NoClue));
    assert_eq!(parse_host(b"1.2.3.4:80"), Err(SniffError::HostIsIp));
    assert_eq!(split_host_port("a:b:c"), None);
    assert_eq!(split_host_port("[a]b:80"), None);
    assert_eq!(split_host_port("a[b:80"), None);
    assert_eq!(split_host_port("host"), None);
}

#[test]
fn every_prefix_of_requests_is_decided_without_panic() {
    let block = header_block();
    let inputs = [
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        h2_input(&[frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, &block)]),
    ];
    for input in inputs {
        for end in 0..=input.len() {
            if let Err(SniffError::NeedAtLeast(length)) = sniff(&input[..end]) {
                assert!(length > end, "a need must go beyond the {end} bytes held");
            }
        }
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut state = 0x1234_5678_9abc_def1u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let block = header_block();
    let seeds = [
        b"GET http://a.example/x HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        h2_input(&[frame(
            H2_FRAME_HEADERS,
            H2_FLAG_END_HEADERS | H2_FLAG_PADDED,
            1,
            &block,
        )]),
    ];
    for round in 0..4000 {
        let mut data: Vec<u8> = (0..(next() % 200)).map(|_| next() as u8).collect();
        if round % 3 != 0 {
            data = seeds[round % 2].clone();
            for _ in 0..(next() % 5) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
            data.truncate((next() as usize) % (data.len() + 1));
        }
        let _ = sniff(&data);
        let _ = sniff_http1(&data);
        let mut h2 = H2_CLIENT_PREFACE.to_vec();
        h2.extend_from_slice(&data);
        let _ = sniff_http2(&h2);
        let _ = parse_host(&data);
    }
}
