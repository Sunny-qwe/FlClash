use std::fs;
use std::path::PathBuf;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn inputs() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(corpus())
        .unwrap()
        .filter_map(|entry| Some(entry.ok()?.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    found.sort();
    found
}

fn render(path: &std::path::Path) -> String {
    let bytes = fs::read(path).unwrap();
    let raw =
        concord_config::parse_raw(&bytes).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
    let mut text = serde_json::to_string_pretty(&raw.to_json()).unwrap();
    text.push('\n');
    text
}

#[test]
fn config_read_matches_the_committed_output_of_every_synthetic_config() {
    let bless = std::env::var_os("CONCORD_BLESS").is_some();
    let mut stale = Vec::new();
    for input in inputs() {
        let expected = input.with_extension("json");
        let actual = render(&input);
        if bless {
            fs::write(&expected, &actual).unwrap();
        } else if fs::read_to_string(&expected).ok().as_deref() != Some(actual.as_str()) {
            stale.push(expected.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    assert!(
        stale.is_empty(),
        "{stale:?} differ; run with CONCORD_BLESS=1 after checking the change"
    );
}

#[test]
fn the_corpus_covers_every_top_level_tier() {
    let text: String = inputs()
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect();
    for key in [
        "dns:",
        "tun:",
        "sniffer:",
        "hosts:",
        "proxy-groups:",
        "rules:",
        "sub-rules:",
    ] {
        assert!(text.contains(key), "no golden config has {key}");
    }
}

#[test]
fn every_golden_output_has_its_input() {
    let inputs: Vec<PathBuf> = inputs()
        .iter()
        .map(|path| path.with_extension("json"))
        .collect();
    for entry in fs::read_dir(corpus()).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            assert!(inputs.contains(&path), "{} has no input", path.display());
        }
    }
}
