//! `xtask check-commits <git log revisions>`: holds commit messages to `rules.md`, Commits: a Conventional
//! Commits subject with a scope, and no trailer or line that credits or links a coding agent.

use std::process::Command;

const TYPES: &[&str] = &[
    "build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style", "test",
];
const AGENT_KEYS: &[&str] = &[
    "co-authored-by",
    "assisted-by",
    "generated-by",
    "claude-session",
];
const AGENT_NAMES: &[&str] = &[
    "claude",
    "anthropic",
    "codex",
    "openai",
    "copilot",
    "cursor",
    "gemini",
];

pub fn check(revisions: &[String]) -> Result<(), String> {
    if revisions.is_empty() {
        return Err("usage: xtask check-commits <git log revisions, e.g. origin/dev..HEAD>".into());
    }
    let output = Command::new("git")
        .args(["log", "--no-merges", "--format=%H%x00%B%x1e"])
        .args(revisions)
        .output()
        .map_err(|err| format!("git: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git log: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let log = String::from_utf8_lossy(&output.stdout);
    let mut problems = Vec::new();
    let mut count = 0;
    for record in log.split('\x1e').map(str::trim).filter(|r| !r.is_empty()) {
        let (hash, message) = record.split_once('\0').unwrap_or((record, ""));
        count += 1;
        for problem in message_problems(message) {
            problems.push(format!("{}: {problem}", &hash[..hash.len().min(12)]));
        }
    }
    println!("checked {count} commit messages");
    if problems.is_empty() {
        Ok(())
    } else {
        problems.push(format!(
            "types: {}; `Revert \"...\"` subjects pass as git writes them",
            TYPES.join(", ")
        ));
        Err(problems.join("\n"))
    }
}

fn message_problems(message: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let subject = message.lines().next().unwrap_or("");
    if !subject_ok(subject) {
        problems.push(format!(
            "subject `{subject}` is not `<type>(<scope>): <summary>`"
        ));
    }
    for line in message.lines().skip(1) {
        if credits_an_agent(line) {
            problems.push(format!("`{line}` credits or links a coding agent"));
        }
    }
    problems
}

fn subject_ok(subject: &str) -> bool {
    if subject.starts_with("Revert \"") {
        return true;
    }
    let Some((kind, rest)) = subject.split_once('(') else {
        return false;
    };
    let Some((scope, rest)) = rest.split_once(')') else {
        return false;
    };
    let rest = rest.strip_prefix('!').unwrap_or(rest);
    TYPES.contains(&kind)
        && !scope.is_empty()
        && scope
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_./, ".contains(c))
        && rest
            .strip_prefix(": ")
            .is_some_and(|summary| !summary.trim().is_empty())
}

fn credits_an_agent(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    if let Some((key, value)) = lower.split_once(':')
        && !key.contains(' ')
    {
        if AGENT_KEYS.contains(&key) {
            return true;
        }
        if AGENT_NAMES.iter().any(|name| value.contains(name)) {
            return true;
        }
    }
    lower.starts_with("generated with") || lower.contains("noreply@anthropic.com")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_subjects_pass() {
        for subject in [
            "fix(tun): keep the queue whole",
            "feat(mitm)!: drop the old rewrite form",
            "docs(agents, ci): name the weekly checks",
            "Revert \"fix(proxy): keep the AnyTLS session connection whole under a lock\"",
        ] {
            assert!(subject_ok(subject), "{subject}");
        }
    }

    #[test]
    fn unscoped_or_untyped_subjects_fail() {
        for subject in [
            "fix: no scope",
            "fix(): empty scope",
            "Fix(tun): capital type",
            "wip(tun): unknown type",
            "fix(tun):no space",
            "fix(tun): ",
            "Initial commit",
        ] {
            assert!(!subject_ok(subject), "{subject}");
        }
    }

    #[test]
    fn agent_trailers_are_reported() {
        for line in [
            "Co-authored-by: Someone <someone@example.com>",
            "Claude-Session: https://example.com/session",
            "Generated with an assistant",
            "Reviewed-by: Codex",
        ] {
            assert!(credits_an_agent(line), "{line}");
        }
    }

    #[test]
    fn ordinary_body_lines_pass() {
        for line in [
            "The cursor in the ring buffer now wraps: it no longer reads past the end.",
            "Measured on the Linux VM: 5 rounds, the same as main.",
            "Refs: crates/tun/src/queue.rs",
        ] {
            assert!(!credits_an_agent(line), "{line}");
        }
    }
}
