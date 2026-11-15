//! Holds `vendor/` to `vendor/PATCHES.md`: every file that differs from the pinned crates.io
//! package, by the hashes in `vendor/UPSTREAM.sha256`, is named in its crate's section, and every
//! file a section names does differ.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sha2::{Digest, Sha256};

const MANIFEST: &str = "vendor/UPSTREAM.sha256";
const PATCHES: &str = "vendor/PATCHES.md";

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let manifest =
        std::fs::read_to_string(root.join(MANIFEST)).map_err(|err| format!("{MANIFEST}: {err}"))?;
    let patches =
        std::fs::read_to_string(root.join(PATCHES)).map_err(|err| format!("{PATCHES}: {err}"))?;
    let upstream = parse_manifest(&manifest)?;
    let sections = sections(&patches);
    let mut problems = Vec::new();
    let crates: BTreeSet<&str> = upstream
        .keys()
        .filter_map(|path| path.split_once('/').map(|(name, _)| name))
        .collect();
    for name in crates {
        let mut vendored = BTreeMap::new();
        hash_tree(&root.join("vendor").join(name), "", &mut vendored)?;
        let pinned: BTreeMap<String, String> = upstream
            .iter()
            .filter_map(|(path, hash)| {
                let rest = path.strip_prefix(name)?.strip_prefix('/')?;
                Some((rest.to_string(), hash.clone()))
            })
            .collect();
        let changed = differences(&pinned, &vendored);
        match sections.get(name) {
            Some(listed) => problems.extend(
                coverage_problems(&changed, listed)
                    .into_iter()
                    .map(|problem| format!("vendor/{name}: {problem}")),
            ),
            None => problems.push(format!("{PATCHES}: no section for `{name}`")),
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

fn parse_manifest(text: &str) -> Result<BTreeMap<String, String>, String> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split_once("  ")
                .map(|(hash, path)| (path.to_string(), hash.to_string()))
                .ok_or_else(|| format!("{MANIFEST}: `{line}` is not `<sha256>  <crate>/<path>`"))
        })
        .collect()
}

fn hash_tree(dir: &Path, prefix: &str, out: &mut BTreeMap<String, String>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| err.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = format!("{prefix}{name}");
        let path = entry.path();
        if path.is_dir() {
            hash_tree(&path, &format!("{relative}/"), out)?;
        } else {
            let bytes = std::fs::read(&path).map_err(|err| format!("{}: {err}", path.display()))?;
            out.insert(relative, hex(&Sha256::digest(&bytes)));
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Paths changed, added or removed against the pinned package.
fn differences(
    pinned: &BTreeMap<String, String>,
    vendored: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut changed: Vec<String> = pinned
        .iter()
        .filter(|(path, hash)| vendored.get(*path) != Some(*hash))
        .map(|(path, _)| path.clone())
        .collect();
    changed.extend(
        vendored
            .keys()
            .filter(|path| !pinned.contains_key(*path))
            .cloned(),
    );
    changed.sort();
    changed
}

/// The files each crate's section lists: the backticked names that open a bullet, before its
/// first colon, keyed by the crate named in the `## <crate> <version>` heading.
fn sections(patches: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in patches.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            let name = heading
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            out.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }
        let (Some(name), Some(bullet)) = (current.as_ref(), line.strip_prefix("- `")) else {
            continue;
        };
        let lead = bullet.split("`:").next().unwrap_or_default();
        let files = format!("`{lead}`")
            .split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect::<Vec<_>>();
        out.entry(name.clone()).or_default().extend(files);
    }
    out
}

/// A listed name covers a path when it is the path, a trailing part of it after a `/`, or a
/// directory (ending in `/`) the path is under.
fn covers(listed: &str, path: &str) -> bool {
    if let Some(dir) = listed.strip_suffix('/') {
        return path.starts_with(&format!("{dir}/"));
    }
    path == listed || path.ends_with(&format!("/{listed}"))
}

fn coverage_problems(changed: &[String], listed: &[String]) -> Vec<String> {
    let mut problems: Vec<String> = changed
        .iter()
        .filter(|path| !listed.iter().any(|name| covers(name, path)))
        .map(|path| {
            format!("`{path}` differs from the pinned package but {PATCHES} does not list it")
        })
        .collect();
    problems.extend(
        listed
            .iter()
            .filter(|name| !changed.iter().any(|path| covers(name, path)))
            .map(|name| {
                format!("{PATCHES} lists `{name}`, which does not differ from the pinned package")
            }),
    );
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vendored_crates_differ_only_where_patches_says() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, hash)| (path.to_string(), hash.to_string()))
            .collect()
    }

    #[test]
    fn changed_added_and_removed_files_are_differences() {
        let pinned = map(&[("a.rs", "1"), ("b.rs", "2"), ("gone.rs", "3")]);
        let vendored = map(&[("a.rs", "1"), ("b.rs", "9"), ("new.rs", "4")]);
        assert_eq!(
            differences(&pinned, &vendored),
            ["b.rs", "gone.rs", "new.rs"]
        );
    }

    #[test]
    fn a_bullet_lists_the_files_before_its_colon() {
        let patches = "## shadowsocks 1.25.0\n\n- `src/x/aead.rs`, `crypto_io.rs`: seals `caller` frames.\n\
                       - `Cargo.toml`, `tests/`: removed.\n- Prose naming `src/other.rs` is not a list.\n\
                       ## quinn 0.11.12\n- `src/connection.rs`:\n  - nested\n";
        let found = sections(patches);
        assert_eq!(
            found["shadowsocks"],
            ["src/x/aead.rs", "crypto_io.rs", "Cargo.toml", "tests/"]
        );
        assert_eq!(found["quinn"], ["src/connection.rs"]);
    }

    #[test]
    fn unlisted_and_stale_entries_are_reported() {
        let listed: Vec<String> = ["crypto_io.rs", "tests/", "src/stale.rs"]
            .map(String::from)
            .to_vec();
        let changed: Vec<String> = ["src/relay/crypto_io.rs", "tests/a.rs", "src/aead.rs"]
            .map(String::from)
            .to_vec();
        let found = coverage_problems(&changed, &listed);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found[0].contains("`src/aead.rs` differs"));
        assert!(found[1].contains("lists `src/stale.rs`"));
    }

    #[test]
    fn a_short_name_matches_only_at_a_path_boundary() {
        assert!(covers("crypto_io.rs", "src/relay/crypto_io.rs"));
        assert!(!covers("io.rs", "src/relay/crypto_io.rs"));
        assert!(covers("benches/", "benches/send.rs"));
        assert!(!covers("benches/", "src/benches.rs"));
    }
}
