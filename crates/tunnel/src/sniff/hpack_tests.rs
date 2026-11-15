use super::*;

type Pair = (&'static str, &'static str);

fn dehex(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn decode_block(decoder: &mut Decoder, block: &[u8]) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    decoder
        .write(block, |name, value| fields.push((text(name), text(value))))
        .unwrap();
    assert!(decoder.saved.is_empty(), "truncated header block");
    decoder.first_field = true;
    fields
}

fn owned(pairs: &[Pair]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|&(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

fn dynamic(decoder: &Decoder) -> Vec<(String, String)> {
    decoder
        .dynamic_table()
        .iter()
        .map(|(n, v)| (text(n), text(v)))
        .collect()
}

struct Step {
    encoded: &'static str,
    fields: &'static [Pair],
    table: &'static [Pair],
    size: usize,
}

fn run_series(max_size: usize, steps: &[Step]) {
    let mut decoder = Decoder::new(max_size);
    for (i, step) in steps.iter().enumerate() {
        let fields = decode_block(&mut decoder, &dehex(step.encoded));
        assert_eq!(fields, owned(step.fields), "headers at step {i}");
        assert_eq!(dynamic(&decoder), owned(step.table), "table at step {i}");
        assert_eq!(decoder.dynamic_size(), step.size, "size at step {i}");
    }
}

#[test]
fn c2_single_representations() {
    let cases: [(&str, &str, &[Pair], &[Pair]); 4] = [
        (
            "C.2.1",
            "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
            &[("custom-key", "custom-header")],
            &[("custom-key", "custom-header")],
        ),
        (
            "C.2.2",
            "040c 2f73 616d 706c 652f 7061 7468",
            &[(":path", "/sample/path")],
            &[],
        ),
        (
            "C.2.3",
            "1008 7061 7373 776f 7264 0673 6563 7265 74",
            &[("password", "secret")],
            &[],
        ),
        ("C.2.4", "82", &[(":method", "GET")], &[]),
    ];
    for (name, encoded, fields, table) in cases {
        let mut decoder = Decoder::new(4096);
        assert_eq!(
            decode_block(&mut decoder, &dehex(encoded)),
            owned(fields),
            "{name}"
        );
        assert_eq!(dynamic(&decoder), owned(table), "{name}");
    }
}

const C3: &[Step] = &[
    Step {
        encoded: "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
        fields: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        table: &[(":authority", "www.example.com")],
        size: 57,
    },
    Step {
        encoded: "8286 84be 5808 6e6f 2d63 6163 6865",
        fields: &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ],
        table: &[
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        size: 110,
    },
    Step {
        encoded: "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
        fields: &[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ],
        table: &[
            ("custom-key", "custom-value"),
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        size: 164,
    },
];

const C4: &[Step] = &[
    Step {
        encoded: "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
        fields: C3[0].fields,
        table: C3[0].table,
        size: 57,
    },
    Step {
        encoded: "8286 84be 5886 a8eb 1064 9cbf",
        fields: C3[1].fields,
        table: C3[1].table,
        size: 110,
    },
    Step {
        encoded: "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        fields: C3[2].fields,
        table: C3[2].table,
        size: 164,
    },
];

const DATE_1: &str = "Mon, 21 Oct 2013 20:13:21 GMT";
const DATE_2: &str = "Mon, 21 Oct 2013 20:13:22 GMT";
const LOCATION: &str = "https://www.example.com";
const COOKIE: &str = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";

const C5: &[Step] = &[
    Step {
        encoded: "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133
                  2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70
                  6c65 2e63 6f6d",
        fields: &[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", DATE_1),
            ("location", LOCATION),
        ],
        table: &[
            ("location", LOCATION),
            ("date", DATE_1),
            ("cache-control", "private"),
            (":status", "302"),
        ],
        size: 222,
    },
    Step {
        encoded: "4803 3330 37c1 c0bf",
        fields: &[
            (":status", "307"),
            ("cache-control", "private"),
            ("date", DATE_1),
            ("location", LOCATION),
        ],
        table: &[
            (":status", "307"),
            ("location", LOCATION),
            ("date", DATE_1),
            ("cache-control", "private"),
        ],
        size: 222,
    },
    Step {
        encoded: "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d
                  54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049
                  5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e
                  3d31",
        fields: &[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", DATE_2),
            ("location", LOCATION),
            ("content-encoding", "gzip"),
            ("set-cookie", COOKIE),
        ],
        table: &[
            ("set-cookie", COOKIE),
            ("content-encoding", "gzip"),
            ("date", DATE_2),
        ],
        size: 215,
    },
];

const C6: &[Step] = &[
    Step {
        encoded: "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6
                  2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
        fields: C5[0].fields,
        table: C5[0].table,
        size: 222,
    },
    Step {
        encoded: "4883 640e ffc1 c0bf",
        fields: C5[1].fields,
        table: C5[1].table,
        size: 222,
    },
    Step {
        encoded: "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab
                  77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f
                  9587 3160 65c0 03ed 4ee5 b106 3d50 07",
        fields: C5[2].fields,
        table: C5[2].table,
        size: 215,
    },
];

#[test]
fn c3_requests_without_huffman() {
    run_series(4096, C3);
}

#[test]
fn c4_requests_with_huffman() {
    run_series(4096, C4);
}

#[test]
fn c5_responses_without_huffman() {
    run_series(256, C5);
}

#[test]
fn c6_responses_with_huffman() {
    run_series(256, C6);
}

#[test]
fn every_series_decodes_when_fed_one_byte_at_a_time() {
    for (max_size, steps) in [(4096, C3), (4096, C4), (256, C5), (256, C6)] {
        let mut decoder = Decoder::new(max_size);
        for step in steps {
            let mut fields = Vec::new();
            for byte in dehex(step.encoded) {
                decoder
                    .write(&[byte], |n, v| fields.push((text(n), text(v))))
                    .unwrap();
            }
            assert!(decoder.saved.is_empty());
            decoder.first_field = true;
            assert_eq!(fields, owned(step.fields));
            assert_eq!(decoder.dynamic_size(), step.size);
        }
    }
}

#[test]
fn huffman_decodes_rfc_strings() {
    assert_eq!(
        huffman_decode(&dehex("f1e3 c2e5 f23a 6ba0 ab90 f4ff")).unwrap(),
        b"www.example.com"
    );
    assert_eq!(
        huffman_decode(&dehex("a8eb 1064 9cbf")).unwrap(),
        b"no-cache"
    );
    assert_eq!(huffman_decode(&[]).unwrap(), b"");
}

#[test]
fn huffman_rejects_excess_padding_and_eos() {
    let cases: [&[u8]; 6] = [
        &[0xff],
        &[0x1f, 0xff],
        &[0x1f, 0xff, 0xff],
        &[0x1f, 0xff, 0xff, 0xff],
        &[0xff, 0x9f, 0xff, 0xff, 0xff],
        &[b'R', 0xbc, b'0', 0xff, 0xff, 0xff, 0xff],
    ];
    for case in cases {
        assert_eq!(huffman_decode(case), Err(DecodeError), "{case:02x?}");
    }
    assert_eq!(
        huffman_decode(&[0xff, 0xff, 0xff, 0xff, 0xfc]),
        Err(DecodeError)
    );
}

#[test]
fn rejects_malformed_blocks() {
    let cases: [(&str, &[u8]); 5] = [
        ("index zero", &[0x80]),
        ("index past the tables", &[0xff, 0x7f]),
        ("size update above the allowed maximum", &[0x3f, 0xe2, 0x1f]),
        (
            "varint overflow",
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ],
        ),
        ("bad huffman string", &[0x00, 0x81, 0x00, 0x00]),
    ];
    for (name, block) in cases {
        let mut decoder = Decoder::new(4096);
        assert_eq!(decoder.write(block, |_, _| {}), Err(DecodeError), "{name}");
    }
}

#[test]
fn size_update_after_a_field_is_rejected_once_the_table_is_used() {
    let mut decoder = Decoder::new(4096);
    let block = dehex("400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572 20");
    assert_eq!(decoder.write(&block, |_, _| {}), Err(DecodeError));

    let mut decoder = Decoder::new(4096);
    assert_eq!(decoder.write(&[0x82, 0x20], |_, _| {}), Ok(()));
}

#[test]
fn dynamic_table_evicts_to_its_maximum() {
    let mut decoder = Decoder::new(100);
    let mut block = vec![0x40, 0x03];
    block.extend_from_slice(b"foo");
    block.push(0x03);
    block.extend_from_slice(b"bar");
    decoder.write(&block, |_, _| {}).unwrap();
    assert_eq!(decoder.dynamic_size(), 6 + 32);

    let mut block = vec![0x40, 0x04];
    block.extend_from_slice(b"long");
    block.push(0x7f);
    block.push(0x45);
    block.extend(std::iter::repeat_n(b'x', 200));
    decoder.write(&block, |_, _| {}).unwrap();
    assert_eq!(decoder.dynamic_size(), 0);
    assert!(decoder.dynamic_table().is_empty());
}

#[test]
fn random_bytes_never_panic() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let seeds = [
        dehex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"),
        dehex("4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005"),
    ];
    for round in 0..3000 {
        let mut data: Vec<u8> = (0..(next() % 80)).map(|_| next() as u8).collect();
        if round % 2 == 0 {
            data = seeds[round % 2 + (next() as usize % 2)].clone();
            for _ in 0..(next() % 4) {
                let at = (next() as usize) % data.len();
                data[at] = next() as u8;
            }
        }
        let mut decoder = Decoder::new(4096);
        for chunk in data.chunks(1 + (next() as usize % 9)) {
            let _ = decoder.write(chunk, |_, _| {});
        }
        let _ = huffman_decode(&data);
    }
}
