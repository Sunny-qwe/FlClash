use std::fs;
use std::path::{Path, PathBuf};

fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../schema")
}

fn render() -> Result<Vec<(&'static str, String)>, String> {
    let files = [
        ("config-schema.json", concord_config::config_schema()),
        ("api.json", concord_proto::api_schema()),
    ];
    files
        .into_iter()
        .map(|(name, value)| {
            let mut text = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
            text.push('\n');
            Ok((name, text))
        })
        .collect()
}

pub fn run(check: bool) -> Result<(), String> {
    let dir = schema_dir();
    let mut stale = Vec::new();
    for (name, text) in render()? {
        let path = dir.join(name);
        if fs::read_to_string(&path).is_ok_and(|current| current == text) {
            continue;
        }
        if check {
            stale.push(name);
        } else {
            fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;
            fs::write(&path, text).map_err(|err| format!("{}: {err}", path.display()))?;
        }
    }
    if stale.is_empty() {
        return Ok(());
    }
    Err(format!(
        "schema/{} out of date; run `cargo run -p xtask -- schema`",
        stale.join(", schema/")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_schema_is_current() {
        run(true).unwrap();
    }
}
