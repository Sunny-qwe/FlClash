#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = concord_config::share_link::decode_subscription_bytes(data);
    if let Ok(line) = std::str::from_utf8(data) {
        let _ = concord_config::share_link::decode_link(line);
    }
});
