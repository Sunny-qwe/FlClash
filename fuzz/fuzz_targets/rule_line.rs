#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|line: &str| {
    let _ = concord_config::parse_rule(line);
});
