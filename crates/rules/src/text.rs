//! Byte-level string matching shared by the rule kinds.

/// Go's `strings.ToLower`: a per-rune simple mapping, so no final-sigma rule and
/// `İ` becomes a plain `i`.
pub(crate) fn go_lower(text: &str) -> String {
    text.chars()
        .flat_map(|c| match c {
            '\u{130}' => 'i'.to_lowercase(),
            c => c.to_lowercase(),
        })
        .collect()
}

/// `*` matches any run of bytes, `?` exactly one byte. With `fold` the text is
/// compared ASCII-lowercased against a pattern that is already lowercase.
pub(crate) fn wildcard_match(pattern: &[u8], text: &[u8], fold: bool) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern == b"*" {
        return true;
    }
    let at = |s: usize| {
        let byte = text.get(s).copied().unwrap_or(0);
        if fold {
            byte.to_ascii_lowercase()
        } else {
            byte
        }
    };
    let mut p = 0usize;
    let mut s = 0usize;
    let mut last_star = 0usize;
    let mut star: Option<usize> = None;
    loop {
        if s >= text.len() {
            while pattern.get(p) == Some(&b'*') {
                p += 1;
            }
            return p == pattern.len();
        }
        let Some(&pc) = pattern.get(p) else {
            match star {
                Some(at_star) => {
                    p = at_star + 1;
                    last_star += 1;
                    s = last_star;
                    continue;
                }
                None => return false,
            }
        };
        match pc {
            b'?' => {}
            b'*' => {
                star = Some(p);
                last_star = s;
                p += 1;
                continue;
            }
            _ => {
                if pc != at(s) {
                    match star {
                        Some(at_star) => {
                            p = at_star + 1;
                            last_star += 1;
                            s = last_star;
                            continue;
                        }
                        None => return false,
                    }
                }
            }
        }
        p += 1;
        s += 1;
    }
}

pub(crate) fn equal_fold(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars()
        .flat_map(char::to_lowercase)
        .eq(b.chars().flat_map(char::to_lowercase))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, text: &str) -> bool {
        wildcard_match(pattern.as_bytes(), text.as_bytes(), false)
    }

    #[test]
    fn wildcard_cases_from_the_go_suite() {
        assert!(m("", ""));
        assert!(m("*", ""));
        assert!(m("**", ""));
        assert!(!m("?", ""));
        assert!(!m("?*", ""));
        assert!(!m("*?", ""));
        assert!(!m("", "a"));
        assert!(m("a", "a"));
        assert!(m("?*", "a"));
        assert!(m("*?", "a"));
        assert!(m("match a string *", "match a string with a *"));
        assert!(m(
            "* at the beginning",
            "match a string with a * at the beginning"
        ));
        assert!(m("match * with *", "match a string with two *"));
        assert!(!m(
            "do not match a string * with more",
            "do not match a string with extra and a *"
        ));
        assert!(m("match ? string with a ?", "match a string with a ?"));
        assert!(!m(
            "do not match a string with extra ??",
            "do not match a string with extra ?"
        ));
        assert!(m("abc.*.hjg", "abc.edf.hjg"));
        assert!(!m("abc.*.hjq", "abc.edf.hjg"));
        assert!(m("abc*hjg", "abc.edf.hjg"));
        assert!(m("a*g", "abc.edf.hjg"));
        assert!(!m("a*q", "abc.edf.hjg"));
        assert!(m("ab?.edf.hjg", "abc.edf.hjg"));
        assert!(m("??c.edf.hjg", "abc.edf.hjg"));
        assert!(!m("ab??.edf.hjg", "abc.edf.hjg"));
        assert!(!m("??.edf.hjg", "abc.edf.hjg"));
    }

    #[test]
    fn folded_text_matches_a_lowercase_pattern() {
        assert!(wildcard_match(b"cur*", b"CURL.exe", true));
        assert!(!wildcard_match(b"cur*", b"wget", true));
    }

    #[test]
    fn equal_fold_handles_non_ascii() {
        assert!(equal_fold("Curl", "cURL"));
        assert!(equal_fold("Ünï", "üNÏ"));
        assert!(!equal_fold("a", "b"));
    }
}
