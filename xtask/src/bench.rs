//! `xtask bench`: builds the release core and `concord-bench`, then measures the
//! working tree against a baseline build and, given a mihomo binary, the Go core.

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run(args: Vec<String>) -> Result<(), String> {
    let mut tier = "quick";
    let mut baseline: Option<String> = None;
    let mut no_baseline = false;
    let mut mihomo: Option<PathBuf> = std::env::var_os("CONCORD_BENCH_MIHOMO")
        .or_else(|| std::env::var_os("MIHOMO"))
        .map(PathBuf::from);
    let mut rest = Vec::new();
    let mut args = args.into_iter();
    let value = |flag: &str, args: &mut std::vec::IntoIter<String>| {
        args.next().ok_or(format!("{flag} needs a value"))
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--quick" => tier = "quick",
            "--full" => tier = "full",
            "--base" | "--baseline" => baseline = Some(value(&arg, &mut args)?),
            "--no-baseline" => no_baseline = true,
            "--mihomo" => mihomo = Some(value(&arg, &mut args)?.into()),
            "--only" => rest.extend(["--cases".to_string(), value(&arg, &mut args)?]),
            "--secs" => rest.extend(["--duration".to_string(), value(&arg, &mut args)?]),
            "--" => rest.extend(args.by_ref()),
            _ => rest.push(arg),
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("no workspace root")?;
    let status = Command::new(env!("CARGO"))
        .args(["build", "--release", "-p", "concord-desktop", "-p", "bench"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    if !status.success() {
        return Err("release build failed".into());
    }
    if baseline.is_none() && !no_baseline && dirty(root) {
        baseline = Some("HEAD".into());
    }
    let mut command = Command::new(root.join("target/release/concord-bench"));
    command.current_dir(root).args([
        "run",
        "--tier",
        tier,
        "--core",
        "concord=concord:target/release/concord",
    ]);
    match &baseline {
        // A clean tree against its own HEAD is a noise-floor run, which is worth keeping.
        Some(rev) => {
            command.args(["--core", &format!("base=rev:{rev}")]);
        }
        None if !no_baseline => eprintln!(
            "the tree is clean, so there is no pre-change build to compare with; pass --base <rev>"
        ),
        None => {}
    }
    match &mihomo {
        Some(mihomo) => {
            command
                .arg("--mihomo")
                .arg(mihomo)
                .arg("--core")
                .arg(format!("go=mihomo:{}", mihomo.display()));
        }
        None => {
            eprintln!(
                "no mihomo (--mihomo, CONCORD_BENCH_MIHOMO or MIHOMO): no Go comparison, and only the direct case can run"
            );
            if !rest.iter().any(|a| a.starts_with("--cases")) {
                command.args(["--cases", "direct"]);
            }
        }
    }
    let status = command
        .args(rest)
        .status()
        .map_err(|e| format!("concord-bench: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("concord-bench exited with {status}"))
    }
}
fn dirty(root: &Path) -> bool {
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(root)
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}
