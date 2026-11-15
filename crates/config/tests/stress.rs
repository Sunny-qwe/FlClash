use std::fmt::Write as _;
use std::time::Instant;

use concord_config::{LoadOptions, load_str, parse_raw_str};

fn large_profile(proxies: usize, rules: usize) -> String {
    let mut text = String::with_capacity(proxies * 110 + rules * 45);
    text.push_str("mixed-port: 7890\nproxies:\n");
    for i in 0..proxies {
        let _ = writeln!(
            text,
            "  - {{name: node-{i}, type: ss, server: 10.{}.{}.{}, port: 8388, cipher: aes-128-gcm, password: p{i}}}",
            (i >> 16) & 255,
            (i >> 8) & 255,
            i & 255
        );
    }
    text.push_str("proxy-groups:\n  - {name: all, type: select, include-all-proxies: true}\n  - {name: auto, type: url-test, proxies: [node-1, node-2]}\nrules:\n");
    for i in 0..rules {
        let _ = writeln!(text, "  - DOMAIN-SUFFIX,d{i}.example.com,all");
    }
    text.push_str("  - MATCH,DIRECT\n");
    text
}

#[test]
#[ignore = "generates 100k proxies and 2M rules; run with --release -- --ignored --nocapture"]
fn a_large_profile_loads() {
    let text = large_profile(100_000, 2_000_000);
    let started = Instant::now();
    let raw = parse_raw_str(&text).map(|raw| (raw.proxies.len(), raw.rules.len()));
    println!("parse_raw: {:?} in {:?}", raw, started.elapsed());
    let started = Instant::now();
    let profile = load_str(&text, &LoadOptions::default());
    println!("load: ok={} in {:?}", profile.is_ok(), started.elapsed());
    let profile = profile.map(|p| (p.proxies.len(), p.rules.len(), p.groups.len()));
    assert_eq!(profile.ok(), Some((100_000, 2_000_001, 3)));
}

#[test]
fn a_medium_profile_loads() {
    let text = large_profile(2_000, 20_000);
    let profile =
        load_str(&text, &LoadOptions::default()).map(|p| (p.proxies.len(), p.rules.len()));
    assert_eq!(profile.ok(), Some((2_000, 20_001)));
}
