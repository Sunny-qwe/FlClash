//! Holds every `concord_common::Stream` impl to an explicit capability policy, the
//! `stream_policy!` declaration in `crates/common/src/stream.rs`. A wrapper that forgets a
//! forward compiles and silently takes a slower path, so the policy is checked from source.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const TRAIT_FILE: &str = "crates/common/src/stream.rs";
const SOURCE_ROOTS: &[&str] = &["crates", "bins", "tools"];
const KINDS: &[&str] = &["forward", "own", "default"];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let trait_source = std::fs::read_to_string(root.join(TRAIT_FILE))
        .map_err(|err| format!("{TRAIT_FILE}: {err}"))?;
    let methods = trait_methods(&blank(&trait_source))?;
    let mut problems = macro_problems(&blank(&trait_source), &methods);
    let mut files = Vec::new();
    for dir in SOURCE_ROOTS {
        rust_files(&root.join(dir), &mut files)?;
    }
    files.sort();
    for file in files {
        let source =
            std::fs::read_to_string(&file).map_err(|err| format!("{}: {err}", file.display()))?;
        let name = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .display()
            .to_string();
        if name != TRAIT_FILE && defines_own_stream_trait(&blank(&source)) {
            continue;
        }
        problems.extend(impl_problems(&name, &source, &methods));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n"))
    }
}

pub(crate) fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|err| err.to_string())?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Replaces comments and the contents of string and char literals with spaces, keeping line
/// breaks, so braces and names inside them do not count.
pub(crate) fn blank(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let keep = |c: char| if c == '\n' { '\n' } else { ' ' };
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while let Some(&c) = chars.get(i).filter(|&&c| c != '\n') {
                out.push(keep(c));
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while let Some(&c) = chars.get(i) {
                let next = chars.get(i + 1).copied();
                if c == '/' && next == Some('*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if c == '*' && next == Some('/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(keep(c));
                    i += 1;
                }
            }
        } else if let Some(hashes) = raw_string_start(&chars, i) {
            let prefix = chars.iter().skip(i).take_while(|&&c| c != '"').count() + 1;
            out.extend(std::iter::repeat_n(' ', prefix));
            i += prefix;
            while let Some(&c) = chars.get(i) {
                let closes =
                    c == '"' && (1..=hashes).all(|offset| chars.get(i + offset) == Some(&'#'));
                if closes {
                    out.extend(std::iter::repeat_n(' ', hashes + 1));
                    i += hashes + 1;
                    break;
                }
                out.push(keep(c));
                i += 1;
            }
        } else if c == '"' {
            out.push(' ');
            i += 1;
            while let Some(&c) = chars.get(i) {
                out.push(keep(c));
                i += 1;
                if c == '\\' {
                    if let Some(&escaped) = chars.get(i) {
                        out.push(keep(escaped));
                        i += 1;
                    }
                } else if c == '"' {
                    break;
                }
            }
        } else if c == '\'' && is_char_literal(&chars, i) {
            out.push(' ');
            i += 1;
            while let Some(&c) = chars.get(i) {
                out.push(' ');
                i += 1;
                if c == '\\' {
                    out.push(' ');
                    i += 1;
                } else if c == '\'' {
                    break;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn raw_string_start(chars: &[char], i: usize) -> Option<usize> {
    let before = i.checked_sub(1).and_then(|j| chars.get(j)).copied();
    if before.is_some_and(is_ident) {
        return None;
    }
    let mut j = i;
    if chars.get(j) == Some(&'b') || chars.get(j) == Some(&'c') {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let hashes = chars.iter().skip(j).take_while(|&&c| c == '#').count();
    (chars.get(j + hashes) == Some(&'"')).then_some(hashes)
}

/// A quote starts a char literal when it is `'\…'` or `'x'`; otherwise it is a lifetime.
fn is_char_literal(chars: &[char], i: usize) -> bool {
    match chars.get(i + 1) {
        Some('\\') => true,
        Some(_) => chars.get(i + 2) == Some(&'\''),
        None => false,
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Drops whitespace except between two identifier characters, so a call reads the same however
/// it is wrapped.
fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut gap = false;
    for c in text.chars() {
        if c.is_whitespace() {
            gap = true;
            continue;
        }
        if gap && is_ident(c) && out.chars().next_back().is_some_and(is_ident) {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    out
}

fn line_of(source: &str, at: usize) -> usize {
    source.get(..at).unwrap_or_default().matches('\n').count() + 1
}

/// The index just past the bracket that closes the one at `open`.
fn closing(source: &str, open: usize, pair: (char, char)) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, c) in source.get(open..)?.char_indices() {
        if c == pair.0 {
            depth += 1;
        } else if c == pair.1 {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open + offset + c.len_utf8());
            }
        }
    }
    None
}

fn words<'a>(text: &'a str, word: &'a str) -> impl Iterator<Item = usize> + 'a {
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(move |&at| {
            let before = text.get(..at).and_then(|s| s.chars().next_back());
            let after = text.get(at + word.len()..).and_then(|s| s.chars().next());
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
}

/// The items one level inside the braces of `body`: functions with their name and body, and
/// `stream_policy!` invocations with their arguments.
struct Items {
    functions: Vec<(String, String)>,
    policies: Vec<String>,
}

fn items(body: &str) -> Items {
    let mut functions = Vec::new();
    let mut policies = Vec::new();
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(c) = body.get(i..).and_then(|s| s.chars().next()) {
        match c {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth = depth.saturating_sub(1),
            _ => {}
        }
        let rest = body.get(i..).unwrap_or_default();
        let boundary = !body
            .get(..i)
            .and_then(|s| s.chars().next_back())
            .is_some_and(is_ident);
        if depth == 0 && boundary && rest.starts_with("fn ") {
            let name: String = rest
                .get(3..)
                .unwrap_or_default()
                .trim_start()
                .chars()
                .take_while(|&c| is_ident(c))
                .collect();
            let Some(open) = rest.find(['{', ';']) else {
                break;
            };
            if rest.get(open..open + 1) == Some(";") {
                functions.push((name, String::new()));
                i += open + 1;
                continue;
            }
            let end = closing(rest, open, ('{', '}')).unwrap_or(rest.len());
            let inner = rest.get(open + 1..end - 1).unwrap_or_default().to_string();
            functions.push((name, inner));
            i += end;
            continue;
        }
        if depth == 0 && boundary && rest.starts_with("stream_policy!") {
            let Some(open) = rest.find('(') else { break };
            let end = closing(rest, open, ('(', ')')).unwrap_or(rest.len());
            policies.push(rest.get(open + 1..end - 1).unwrap_or_default().to_string());
            i += end;
            continue;
        }
        i += c.len_utf8();
    }
    Items {
        functions,
        policies,
    }
}

fn trait_methods(blanked: &str) -> Result<Vec<String>, String> {
    let at = blanked
        .find("pub trait Stream:")
        .ok_or_else(|| format!("{TRAIT_FILE}: no `pub trait Stream`"))?;
    let open = at + blanked.get(at..).and_then(|s| s.find('{')).unwrap_or(0);
    let end = closing(blanked, open, ('{', '}')).ok_or("unclosed `trait Stream`")?;
    let body = blanked.get(open + 1..end - 1).unwrap_or_default();
    Ok(items(body)
        .functions
        .into_iter()
        .map(|(name, _)| name)
        .collect())
}

fn defines_own_stream_trait(blanked: &str) -> bool {
    words(blanked, "trait").any(|at| {
        blanked
            .get(at + 5..)
            .unwrap_or_default()
            .trim_start()
            .starts_with("Stream")
    })
}

fn macro_problems(blanked: &str, methods: &[String]) -> Vec<String> {
    let Some(at) = blanked.find("macro_rules! stream_policy") else {
        return vec![format!("{TRAIT_FILE}: no `stream_policy!` macro")];
    };
    let open = at + blanked.get(at..).and_then(|s| s.find('{')).unwrap_or(0);
    let end = closing(blanked, open, ('{', '}')).unwrap_or(blanked.len());
    let body = compact(blanked.get(open..end).unwrap_or_default());
    methods
        .iter()
        .filter(|name| {
            !body.contains(&format!("(@known {name})"))
                || !body.contains(&format!("[$($post)*]{name});"))
                || !body.contains(&format!("[$($post:tt)*]{name})=>"))
                || !body.contains(&format!("fn {name}("))
        })
        .map(|name| format!("{TRAIT_FILE}: `stream_policy!` cannot forward or name `{name}`"))
        .collect()
}

struct Policy {
    field: bool,
    kinds: Vec<(String, Vec<String>)>,
}

fn parse_policy(args: &str) -> Result<Policy, String> {
    let mut field = false;
    let mut kinds = Vec::new();
    for (index, segment) in args.split(';').map(str::trim).enumerate() {
        if segment.is_empty() {
            continue;
        }
        match segment.split_once(':') {
            Some((kind, names)) => kinds.push((
                kind.trim().to_string(),
                names
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
                    .collect(),
            )),
            None if index == 0 => field = true,
            None => return Err(format!("`{segment}` is not `kind: names`")),
        }
    }
    Ok(Policy { field, kinds })
}

/// A method body that only calls the same method on a field, or on the boxed stream.
fn forwards_by_hand(name: &str, body: &str) -> bool {
    let compact = compact(body);
    let call = format!(".{name}(");
    let Some(receiver) = compact.strip_suffix(')').and_then(|s| s.split_once(&call)) else {
        return false;
    };
    let plain_args = receiver.1.chars().all(|c| is_ident(c) || c == ',');
    let field = receiver
        .0
        .strip_prefix("self.")
        .is_some_and(|f| f.chars().all(is_ident));
    plain_args && (field || receiver.0 == "(**self)")
}

/// A call of the same method on something reached from `self`: the impl relays this
/// capability from a stream it holds.
fn relays(name: &str, body: &str) -> bool {
    let compact = compact(body);
    let call = format!(".{name}(");
    compact.match_indices(&call).any(|(at, _)| {
        let before = compact.get(..at).unwrap_or_default();
        let start = before
            .rfind(|c: char| !(is_ident(c) || "().*".contains(c)))
            .map_or(0, |i| i + 1);
        let receiver = before
            .get(start..)
            .unwrap_or_default()
            .trim_start_matches(['(', '*']);
        receiver == "self" || receiver.starts_with("self.") || receiver.starts_with("self)")
    })
}

fn impl_problems(file: &str, source: &str, methods: &[String]) -> Vec<String> {
    let blanked = blank(source);
    let mut problems = Vec::new();
    for at in words(&blanked, "impl") {
        let Some(open) = blanked
            .get(at..)
            .and_then(|s| s.find(['{', ';']))
            .map(|o| at + o)
        else {
            continue;
        };
        if blanked.get(open..open + 1) != Some("{") {
            continue;
        }
        let header = blanked.get(at + 4..open).unwrap_or_default();
        let Some(bounds) = stream_impl_bounds(header) else {
            continue;
        };
        let end = closing(&blanked, open, ('{', '}')).unwrap_or(blanked.len());
        let body = blanked.get(open + 1..end - 1).unwrap_or_default();
        if words(body, "poll_next").next().is_some() || words(body, "Item").next().is_some() {
            continue;
        }
        let place = format!("{file}:{}", line_of(&blanked, at));
        problems.extend(
            policy_problems(body, methods, words(&bounds, "Stream").next().is_some())
                .into_iter()
                .map(|problem| format!("{place}: {problem}")),
        );
    }
    problems
}

/// For an impl of a trait whose last path segment is `Stream`, the header without the trait
/// path: the generics, the self type and any where clause.
fn stream_impl_bounds(header: &str) -> Option<String> {
    let trimmed = header.trim_start();
    let generics_end = if trimmed.starts_with('<') {
        closing(trimmed, 0, ('<', '>'))?
    } else {
        0
    };
    let (generics, rest) = trimmed.split_at(generics_end);
    let rest = rest.trim_start();
    let path_end = rest.find(char::is_whitespace)?;
    let (path, after) = rest.split_at(path_end);
    if path.rsplit("::").next() != Some("Stream") || path.contains('<') {
        return None;
    }
    let self_type = after.trim_start().strip_prefix("for")?;
    Some(format!("{generics} {self_type}"))
}

fn policy_problems(body: &str, methods: &[String], generic: bool) -> Vec<String> {
    let found = items(body);
    let written: Vec<&str> = found
        .functions
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| methods.iter().any(|m| m == name))
        .collect();
    let mut problems: Vec<String> = found
        .functions
        .iter()
        .filter(|(name, inner)| forwards_by_hand(name, inner))
        .map(|(name, _)| {
            format!("`{name}` forwards by hand; name it under `forward:` in stream_policy!")
        })
        .collect();
    let relaying = found
        .functions
        .iter()
        .any(|(name, inner)| relays(name, inner));
    let policy = match found.policies.as_slice() {
        [] if generic || relaying => {
            problems.push(
                "wraps another stream without stream_policy!; declare each capability".to_string(),
            );
            return problems;
        }
        [] => return problems,
        [one] => one,
        _ => {
            problems.push("more than one stream_policy!".to_string());
            return problems;
        }
    };
    let policy = match parse_policy(policy) {
        Ok(policy) => policy,
        Err(problem) => {
            problems.push(problem);
            return problems;
        }
    };
    let mut named: Vec<String> = Vec::new();
    let mut owned = BTreeSet::new();
    for (kind, names) in &policy.kinds {
        if !KINDS.contains(&kind.as_str()) {
            problems.push(format!("unknown kind `{kind}`"));
            continue;
        }
        if kind == "forward" && !policy.field {
            problems.push("`forward:` needs the field to forward to".to_string());
        }
        if names.iter().any(|name| name == "all") {
            if policy.kinds.len() != 1 || names.len() != 1 || kind == "own" {
                problems
                    .push("`all` stands alone, as `forward: all` or `default: all`".to_string());
            }
            named.extend(methods.iter().cloned());
            continue;
        }
        if kind == "own" {
            owned.extend(names.iter().cloned());
        }
        named.extend(names.iter().cloned());
    }
    for method in methods {
        match named.iter().filter(|name| *name == method).count() {
            0 => problems.push(format!("`{method}` is not declared")),
            1 => {}
            _ => problems.push(format!("`{method}` is declared more than once")),
        }
    }
    for name in named.iter().collect::<BTreeSet<_>>() {
        if !methods.contains(name) {
            problems.push(format!("`{name}` is not a method of Stream"));
        }
    }
    for name in &written {
        if !owned.contains(*name) {
            problems.push(format!(
                "`{name}` is written by hand but not declared `own:`"
            ));
        }
    }
    for name in &owned {
        if !written.contains(&name.as_str()) {
            problems.push(format!("`{name}` is declared `own:` but not written"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn methods() -> Vec<String> {
        ["tcp", "peer_addr", "direct"].map(String::from).to_vec()
    }

    fn problems(source: &str) -> Vec<String> {
        impl_problems("x.rs", source, &methods())
    }

    #[test]
    fn the_workspace_declares_every_wrapper_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        if let Err(problems) = check(&root) {
            panic!("{problems}");
        }
    }

    #[test]
    fn a_real_wrapper_without_its_policy_fails() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let trait_source = std::fs::read_to_string(root.join(TRAIT_FILE)).unwrap();
        let methods = trait_methods(&blank(&trait_source)).unwrap();
        let lazy = std::fs::read_to_string(root.join("crates/proxy/src/lazy.rs")).unwrap();
        assert!(impl_problems("lazy.rs", &lazy, &methods).is_empty());
        let stripped = lazy.replace("stream_policy!", "stream_policy_removed!");
        let found = impl_problems("lazy.rs", &stripped, &methods);
        assert!(
            found.iter().any(|p| p.contains("without stream_policy!")),
            "{found:?}"
        );
    }

    #[test]
    fn the_trait_methods_are_read_from_the_trait() {
        let source = "pub trait Stream: AsyncRead {\n    fn tcp(&self) -> Option<&T> { None }\n    \
                      /// x { y\n    fn direct(&mut self) {}\n}";
        assert_eq!(trait_methods(&blank(source)).unwrap(), ["tcp", "direct"]);
    }

    #[test]
    fn an_opaque_leaf_needs_no_policy() {
        assert!(problems("impl Stream for TlsConn {}").is_empty());
        assert!(
            problems("impl Stream for Net {\n fn direct(&mut self) -> X { Some(self) }\n}")
                .is_empty()
        );
    }

    #[test]
    fn a_generic_wrapper_without_a_policy_is_reported() {
        let found = problems("impl<S: Stream> Stream for Framed<S> {}");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("x.rs:1: wraps another stream"));
        assert!(
            problems("impl<S: Stream> Stream for Framed<S> { stream_policy!(default: all); }")
                .is_empty()
        );
    }

    #[test]
    fn a_hand_written_forward_is_reported() {
        let found = problems("impl Stream for W {\n fn tcp(&self) -> X { self.inner.tcp() }\n}");
        assert!(
            found.iter().any(|p| p.contains("`tcp` forwards by hand")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|p| p.contains("without stream_policy!")),
            "{found:?}"
        );
    }

    #[test]
    fn a_policy_names_every_method_exactly_once() {
        let found = problems(
            "impl<S: Stream> Stream for W<S> {\n stream_policy!(inner; forward: tcp; default: tcp);\n}",
        );
        assert!(
            found
                .iter()
                .any(|p| p.contains("`tcp` is declared more than once")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|p| p.contains("`peer_addr` is not declared")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|p| p.contains("`direct` is not declared")),
            "{found:?}"
        );
    }

    #[test]
    fn own_matches_the_methods_written() {
        let source = "impl<S: Stream> Stream for W<S> {\n \
                      concord_common::stream_policy!(inner; forward: tcp; own: direct; default: peer_addr);\n \
                      fn peer_addr(&self) -> X { None }\n}";
        let found = problems(source);
        assert!(
            found
                .iter()
                .any(|p| p.contains("`peer_addr` is written by hand")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|p| p.contains("`direct` is declared `own:` but not written")),
            "{found:?}"
        );
    }

    #[test]
    fn a_complete_policy_passes() {
        let source = "impl<S: Stream> Stream for W<S> {\n \
                      stream_policy!(inner;\n forward: tcp;\n own: direct;\n default: peer_addr);\n \
                      fn direct(&mut self) -> X { if self.ready { self.inner.direct() } else { None } }\n}";
        assert_eq!(problems(source), Vec::<String>::new());
        assert!(problems("impl Stream for B {\n stream_policy!(box; forward: all);\n}").is_empty());
    }

    #[test]
    fn all_stands_alone() {
        let found = problems(
            "impl<S: Stream> Stream for W<S> { stream_policy!(inner; forward: all; own: tcp); }",
        );
        assert!(
            found.iter().any(|p| p.contains("`all` stands alone")),
            "{found:?}"
        );
    }

    #[test]
    fn other_stream_traits_are_not_checked() {
        assert!(problems("impl<S: Stream> futures::Stream for Q<S> {\n type Item = u8;\n fn poll_next() {}\n}").is_empty());
        assert!(problems("impl<S: Stream> AsyncRead for W<S> {}").is_empty());
        assert!(defines_own_stream_trait("pub trait Stream: AsyncRead {}"));
    }

    #[test]
    fn comments_and_literals_do_not_count() {
        let source = "impl Stream for W { // }\n fn tcp(&self) -> X { let _ = \"}{\"; let _ = '}'; None }\n}";
        assert!(problems(source).is_empty());
        let blanked = blank("let a = r#\"x\"#; let b: &'static str = \"{\"; /* { /* } */ */");
        assert!(
            !blanked.contains('{') && !blanked.contains('}'),
            "{blanked}"
        );
        assert!(blanked.contains("'static"));
    }

    #[test]
    fn the_macro_must_cover_every_method() {
        let found = macro_problems(
            "macro_rules! stream_policy { (@known tcp) => {}; (@all [$($pre:tt)*] [$($post:tt)*]) => { \
             x!(@forward [$($pre)*] [$($post)*] tcp); x!(@forward [$($pre)*] [$($post)*] direct); }; \
             (@forward [$($pre:tt)*] [$($post:tt)*] tcp) => { fn tcp(&self) {} }; }",
            &methods(),
        );
        assert_eq!(found.len(), 2, "{found:?}");
    }
}
