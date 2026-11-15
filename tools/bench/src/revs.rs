//! `rev:` cores, cached by commit and built in their own target directory: cargo keys
//! workspace crates by their path in the workspace, so a shared one mixes revisions.

use std::env::consts::EXE_SUFFIX;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Revisions before the desktop binary was renamed build `FlClashCore`.
const BINARY_NAMES: [&str; 2] = ["concord", "FlClashCore"];

pub fn build(rev: &str) -> Result<PathBuf, String> {
    let root = PathBuf::from(git(None, &["rev-parse", "--show-toplevel"])?);
    let sha = git(
        Some(&root),
        &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
    )?;
    let cached = root
        .join("target/bench/bin")
        .join(&sha)
        .join(format!("{}{EXE_SUFFIX}", BINARY_NAMES[0]));
    if cached.exists() {
        return Ok(cached);
    }
    let tree = root.join("target/bench/src").join(&sha);
    if tree.exists() {
        let _ = git(
            Some(&root),
            &["worktree", "remove", "--force", &tree.to_string_lossy()],
        );
    }
    git(
        Some(&root),
        &["worktree", "add", "--detach", &tree.to_string_lossy(), &sha],
    )?;
    eprintln!("building Concord at {rev} ({})", &sha[..12]);
    let target = root.join("target/bench/rev-target");
    let release = target.join("release");
    let binaries: Vec<PathBuf> = BINARY_NAMES
        .iter()
        .map(|name| release.join(format!("{name}{EXE_SUFFIX}")))
        .collect();
    for binary in &binaries {
        let _ = std::fs::remove_file(binary);
    }
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--locked",
            "-p",
            "concord-desktop",
            "--target-dir",
        ])
        .arg(&target)
        .current_dir(&tree)
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    let built = binaries.iter().find(|binary| binary.exists());
    let result = if let (true, Some(built)) = (status.success(), built) {
        std::fs::create_dir_all(cached.parent().unwrap_or(&root))
            .and_then(|()| std::fs::copy(built, &cached))
            .map(|_| cached.clone())
            .map_err(|e| format!("cache {}: {e}", cached.display()))
    } else {
        Err(format!("building {rev} failed"))
    };
    let _ = git(
        Some(&root),
        &["worktree", "remove", "--force", &tree.to_string_lossy()],
    );
    result
}

fn git(dir: Option<&Path>, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("git");
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let out = command
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn describe_head() -> Option<String> {
    let sha = git(None, &["rev-parse", "--short=12", "HEAD"]).ok()?;
    let dirty = git(None, &["status", "--porcelain", "--untracked-files=no"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    Some(if dirty { format!("{sha}-dirty") } else { sha })
}
