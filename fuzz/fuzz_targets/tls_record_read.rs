#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| concord_tls::fuzzing::read_records(data));
