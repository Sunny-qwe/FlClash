use crate::text::{quote, quote_char};

const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostEntry {
    pattern: String,
    exclude: bool,
    bare: bool,
    port: u16,
}

/// Surge's `[MITM] hostname`: entries match in order, so an exclusion has to
/// come before the wider entry it carves out of.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostList(Vec<HostEntry>);

impl HostList {
    pub fn parse(lines: &[String]) -> (HostList, Vec<String>) {
        let mut list = HostList::default();
        let mut errors = Vec::new();
        for line in lines {
            let (entries, line_errors) = parse_host_line(line);
            list.0.extend(entries.0);
            errors.extend(line_errors.into_iter().map(|err| format!("hostname {err}")));
        }
        (list, errors)
    }

    /// A bare entry covers 443, and 80, which Surge's HTTP engine rewrites without an entry.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.find(host, port, false)
    }

    /// Widens a bare entry to any port, as Surge does for a connection whose server
    /// name was read from its first bytes.
    pub fn matches_sniffed(&self, host: &str, port: u16) -> bool {
        self.find(host, port, true)
    }

    pub fn includes_any(&self) -> bool {
        self.0.iter().any(|entry| !entry.exclude)
    }

    fn find(&self, host: &str, port: u16, sniffed: bool) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        self.0
            .iter()
            .find(|entry| entry.covers(port, sniffed) && glob(&entry.pattern, &host))
            .is_some_and(|entry| !entry.exclude)
    }

    pub(crate) fn extend(&mut self, other: HostList) {
        self.0.extend(other.0);
    }
}

impl HostEntry {
    fn covers(&self, port: u16, sniffed: bool) -> bool {
        if self.bare {
            return self.exclude || sniffed || port == HTTPS_PORT || port == HTTP_PORT;
        }
        self.port == 0 || self.port == port
    }
}

/// One error per bad item; the caller joins them with newlines when it needs a line's message.
pub(crate) fn parse_host_line(line: &str) -> (HostList, Vec<String>) {
    let mut list = HostList::default();
    let mut errors = Vec::new();
    for item in line.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        match parse_host_entry(item) {
            Ok(entry) => list.0.push(entry),
            Err(err) => errors.push(format!("{}: {err}", quote(item))),
        }
    }
    (list, errors)
}

fn parse_host_entry(item: &str) -> Result<HostEntry, String> {
    let (exclude, item) = match item.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, item),
    };
    let (host, port) = split_host_pattern(item)?;
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    if let Some(bad) = host.chars().find(|c| !is_host_pattern_char(*c)) {
        return Err(format!("unsupported character {}", quote_char(bad)));
    }
    Ok(HostEntry {
        pattern: host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase(),
        exclude,
        bare: port.is_none(),
        port: port.unwrap_or(0),
    })
}

fn split_host_pattern(item: &str) -> Result<(&str, Option<u16>), String> {
    if let Some(rest) = item.strip_prefix('[') {
        let end = rest.find(']').ok_or("unclosed bracket")?;
        let (host, tail) = (&rest[..end], &rest[end + 1..]);
        if tail.is_empty() {
            return Ok((host, None));
        }
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("unexpected {} after the address", quote(tail)))?;
        return Ok((host, Some(parse_port(port)?)));
    }
    if item.matches(':').count() != 1 {
        return Ok((item, None));
    }
    let (host, port) = item.split_once(':').unwrap_or((item, ""));
    Ok((host, Some(parse_port(port)?)))
}

pub(crate) fn parse_port(text: &str) -> Result<u16, String> {
    text.parse::<u16>()
        .map_err(|_| format!("invalid port {}", quote(text)))
}

fn is_host_pattern_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._*?:".contains(c)
}

/// `*` and `?` over bytes; the name is already lower-case.
pub(crate) fn glob(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut p, mut n) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'?') => {
                p += 1;
                n += 1;
            }
            Some(b'*') => {
                star = Some(p);
                mark = n;
                p += 1;
            }
            Some(&c) if c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                Some(at) => {
                    p = at + 1;
                    mark += 1;
                    n = mark;
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn follows_surge_semantics() {
        let (list, errors) = HostList::parse(&lines(&[
            "-skip.example.com",
            "*.example.com, api.other.com:8443",
            "all.ports.com:0",
            "[2001:db8::1]:443",
            "10.0.0.?",
        ]));
        assert!(errors.is_empty(), "{errors:?}");
        let cases = [
            ("a.example.com", 443, true),
            ("A.Example.COM.", 443, true),
            ("a.b.example.com", 443, true),
            ("example.com", 443, false),
            ("a.example.com", 80, true),
            ("a.example.com", 8443, false),
            ("skip.example.com", 443, false),
            ("skip.example.com", 80, false),
            ("api.other.com", 8443, true),
            ("api.other.com", 443, false),
            ("all.ports.com", 22, true),
            ("2001:db8::1", 443, true),
            ("10.0.0.7", 443, true),
            ("10.0.0.17", 443, false),
            ("", 443, false),
        ];
        for (host, port, want) in cases {
            assert_eq!(list.matches(host, port), want, "{host}:{port}");
        }
    }

    #[test]
    fn order_decides() {
        let (list, _) = HostList::parse(&lines(&["*", "-a.com"]));
        assert!(list.matches("a.com", 443));
    }

    #[test]
    fn sniffed_widens_bare_entries() {
        let (list, _) = HostList::parse(&lines(&["a.com"]));
        assert!(!list.matches("a.com", 8080));
        assert!(list.matches_sniffed("a.com", 8080));
    }

    #[test]
    fn reports_bad_entries() {
        let (list, errors) = HostList::parse(&lines(&[
            "good.com",
            "bad host.com",
            "x.com:99999",
            "<ip-address>",
            "[::1",
        ]));
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(list.matches("good.com", 443));
        assert_eq!(
            errors.first().map(String::as_str),
            Some("hostname \"bad host.com\": unsupported character ' '")
        );
    }

    #[test]
    fn glob_cases() {
        let cases = [
            ("*", "anything.at.all", true),
            ("*.a.com", "x.a.com", true),
            ("*.a.com", "a.com", false),
            ("a*c", "abbbc", true),
            ("a*c", "abbbd", false),
            ("?.a.com", "x.a.com", true),
            ("?.a.com", "xy.a.com", false),
            ("*x*y*", "1x2y3", true),
        ];
        for (pattern, name, want) in cases {
            assert_eq!(glob(pattern, name), want, "{pattern} {name}");
        }
    }
}
