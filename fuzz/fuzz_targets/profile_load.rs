#![no_main]

use concord_config::LoadOptions;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = concord_config::load_str(text, &LoadOptions::default());
});
