use fancy_regex::Regex;

use super::issue::{IssueKind, LineError};

/// Compiles a line's regex to check it and drops it: the rule that runs it compiles its own.
pub fn check_pattern(pattern: &str) -> Result<(), LineError> {
    compile(pattern)
}

/// As [check_pattern] for a body regex, which matches line by line.
pub fn check_multiline(pattern: &str) -> Result<(), LineError> {
    compile(&format!("(?m){pattern}"))
}

fn compile(source: &str) -> Result<(), LineError> {
    Regex::new(source)
        .map(drop)
        .map_err(|err| LineError::new(IssueKind::Pattern, err.to_string()))
}
