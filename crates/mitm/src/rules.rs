use std::path::{Component, Path};

use http::StatusCode;
use http::header::{HeaderMap, HeaderName, HeaderValue};

use crate::jq::{Jq, JqOutcome};
use crate::pattern::Pattern;
use crate::script::Script;
use crate::text::{Field, canonical_header, decode_base64, quote, remainder, split_fields, texts};

const TINY_GIF_BASE64: &str = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlAction {
    Header,
    Redirect302,
    Redirect307,
    Reject,
    Reject200,
    RejectImg,
    RejectDict,
    RejectArray,
}

impl UrlAction {
    fn named(text: &str) -> Option<UrlAction> {
        Some(match text {
            "header" => UrlAction::Header,
            "302" => UrlAction::Redirect302,
            "307" => UrlAction::Redirect307,
            "reject" => UrlAction::Reject,
            "reject-200" => UrlAction::Reject200,
            "reject-img" | "reject-tinygif" => UrlAction::RejectImg,
            "reject-dict" => UrlAction::RejectDict,
            "reject-array" => UrlAction::RejectArray,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            UrlAction::Header => "header",
            UrlAction::Redirect302 => "302",
            UrlAction::Redirect307 => "307",
            UrlAction::Reject => "reject",
            UrlAction::Reject200 => "reject-200",
            UrlAction::RejectImg => "reject-img",
            UrlAction::RejectDict => "reject-dict",
            UrlAction::RejectArray => "reject-array",
        }
    }

    pub fn rejects(self) -> bool {
        matches!(
            self,
            UrlAction::Reject
                | UrlAction::Reject200
                | UrlAction::RejectImg
                | UrlAction::RejectDict
                | UrlAction::RejectArray
        )
    }
}

#[derive(Debug)]
pub struct UrlRewrite {
    pattern: Pattern,
    pub replacement: String,
    pub action: UrlAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderAction {
    Add,
    Del,
    Replace,
    ReplaceRegex,
}

#[derive(Debug)]
pub struct HeaderRewrite {
    response: bool,
    pattern: Pattern,
    action: HeaderAction,
    name: HeaderName,
    value: HeaderValue,
    value_regex: Option<Pattern>,
    replacement: String,
}

#[derive(Debug)]
struct BodyReplacement {
    pattern: Pattern,
    with: String,
}

#[derive(Debug)]
enum BodyAction {
    Replace(Vec<BodyReplacement>),
    Jq(Jq),
}

#[derive(Debug)]
pub struct BodyRewrite {
    response: bool,
    pattern: Pattern,
    action: BodyAction,
}

#[derive(Debug)]
pub struct MapLocal {
    pattern: Pattern,
    pub status: StatusCode,
    pub header: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Rules {
    pub(crate) url_rewrites: Vec<UrlRewrite>,
    pub(crate) header_rewrites: Vec<HeaderRewrite>,
    pub(crate) body_rewrites: Vec<BodyRewrite>,
    pub(crate) map_locals: Vec<MapLocal>,
    pub(crate) scripts: Vec<std::sync::Arc<Script>>,
}

pub fn tiny_gif() -> Vec<u8> {
    decode_base64(TINY_GIF_BASE64).unwrap_or_default()
}

pub(crate) fn parse_url_rewrite(line: &str) -> Result<UrlRewrite, String> {
    let fields = split_fields(line)?;
    if fields.len() < 2 {
        return Err("expected a pattern and a replacement or type".to_string());
    }
    let args = texts(fields.get(1..).unwrap_or_default());
    let first = args.first().copied().unwrap_or_default();
    let mut action = UrlAction::Header;
    let mut replacement = String::new();
    match args.len() {
        _ if first == "url" && args.len() >= 2 => {
            action = url_action_of(args.get(1).copied().unwrap_or_default())?;
            if let Some(third) = args.get(2) {
                replacement = (*third).to_string();
            }
        }
        1 => match UrlAction::named(first) {
            Some(named) if named.rejects() => action = named,
            _ => replacement = first.to_string(),
        },
        2 => {
            let second = args.get(1).copied().unwrap_or_default();
            if let Some(named) = UrlAction::named(second) {
                (replacement, action) = (first.to_string(), named);
            } else if let Some(named) = UrlAction::named(first) {
                (action, replacement) = (named, second.to_string());
            } else {
                return Err(format!("unknown type {}", quote(second)));
            }
        }
        _ => return Err("too many fields".to_string()),
    }
    if action.rejects() {
        replacement.clear();
    } else if replacement.is_empty() || replacement == "_" {
        return Err(format!("{} needs a replacement URL", action.name()));
    }
    let pattern = Pattern::new(&field_text(&fields, 0))?;
    Ok(UrlRewrite {
        pattern,
        replacement,
        action,
    })
}

fn field_text(fields: &[Field], at: usize) -> String {
    fields
        .get(at)
        .map(|field| field.text.clone())
        .unwrap_or_default()
}

fn url_action_of(text: &str) -> Result<UrlAction, String> {
    UrlAction::named(text).ok_or_else(|| format!("unknown type {}", quote(text)))
}

pub(crate) fn parse_header_rewrite(line: &str) -> Result<HeaderRewrite, String> {
    let mut fields = split_fields(line)?;
    let mut response = false;
    if let Some(first) = fields.first() {
        match first.text.to_ascii_lowercase().as_str() {
            "http-response" => {
                response = true;
                fields.remove(0);
            }
            "http-request" => {
                fields.remove(0);
            }
            _ => {}
        }
    }
    if fields.len() < 3 {
        return Err("expected a pattern, an action and a header name".to_string());
    }
    let action_text = field_text(&fields, 1).to_ascii_lowercase();
    let name_text = canonical_header(&field_text(&fields, 2));
    if matches!(name_text.as_str(), "Content-Length" | "Transfer-Encoding") {
        return Err(format!(
            "{name_text} frames the message and cannot be rewritten"
        ));
    }
    let name = HeaderName::from_bytes(name_text.as_bytes())
        .map_err(|_| format!("invalid header name {}", quote(&name_text)))?;
    let rest = fields.get(3..).unwrap_or_default();
    let mut value = HeaderValue::from_static("");
    let mut value_regex = None;
    let mut replacement = String::new();
    let action = match action_text.as_str() {
        "header-add" | "header-replace" => {
            let text = fields
                .get(2)
                .map(|name_field| remainder(line, name_field))
                .unwrap_or_default();
            value = HeaderValue::from_str(&text)
                .map_err(|_| format!("invalid header value {}", quote(&text)))?;
            if action_text == "header-add" {
                HeaderAction::Add
            } else {
                HeaderAction::Replace
            }
        }
        "header-del" => HeaderAction::Del,
        "header-replace-regex" => {
            if rest.len() < 2 {
                return Err("header-replace-regex needs a pattern and a replacement".to_string());
            }
            value_regex = Some(Pattern::new(&field_text(rest, 0))?);
            replacement = field_text(rest, 1);
            HeaderAction::ReplaceRegex
        }
        _ => return Err(format!("unknown action {}", quote(&field_text(&fields, 1)))),
    };
    let pattern = Pattern::new(&field_text(&fields, 0))?;
    Ok(HeaderRewrite {
        response,
        pattern,
        action,
        name,
        value,
        value_regex,
        replacement,
    })
}

impl HeaderRewrite {
    fn apply(&self, header: &mut HeaderMap) -> bool {
        match self.action {
            HeaderAction::Add => {
                header.append(self.name.clone(), self.value.clone());
            }
            HeaderAction::Del => {
                if !header.contains_key(&self.name) {
                    return false;
                }
                header.remove(&self.name);
            }
            HeaderAction::Replace => {
                if !header.contains_key(&self.name) {
                    return false;
                }
                header.insert(self.name.clone(), self.value.clone());
            }
            HeaderAction::ReplaceRegex => {
                if !header.contains_key(&self.name) {
                    return false;
                }
                let Some(regex) = &self.value_regex else {
                    return false;
                };
                let values: Vec<HeaderValue> = header
                    .get_all(&self.name)
                    .iter()
                    .map(|value| {
                        value
                            .to_str()
                            .ok()
                            .and_then(|text| regex.replace(text, &self.replacement, true))
                            .and_then(|text| HeaderValue::from_str(&text).ok())
                            .unwrap_or_else(|| value.clone())
                    })
                    .collect();
                header.remove(&self.name);
                for value in values {
                    header.append(self.name.clone(), value);
                }
            }
        }
        true
    }
}

pub(crate) fn parse_body_rewrite(line: &str) -> Result<BodyRewrite, String> {
    let kind = line.split_whitespace().next().unwrap_or_default();
    let jq_response = match kind.to_ascii_lowercase().as_str() {
        "http-request-jq" => Some(false),
        "http-response-jq" => Some(true),
        _ => None,
    };
    if let Some(response) = jq_response {
        let rest = line.trim_start().get(kind.len()..).unwrap_or_default();
        let (pattern, expression) = leading_field(rest).ok_or("unclosed quote")?;
        let expression = unwrap_quotes(expression.trim());
        if pattern.is_empty() || expression.is_empty() {
            return Err("expected a pattern and a jq expression".to_string());
        }
        return Ok(BodyRewrite {
            response,
            pattern: Pattern::new(&pattern)?,
            action: BodyAction::Jq(Jq::compile(expression).map_err(|err| err.to_string())?),
        });
    }
    let fields = split_fields(line)?;
    if fields.len() < 4 {
        return Err("expected a type, a pattern and a regex with its replacement".to_string());
    }
    let first = field_text(&fields, 0);
    let response = match first.to_ascii_lowercase().as_str() {
        "http-request" => false,
        "http-response" => true,
        _ => return Err(format!("unknown type {}", quote(&first))),
    };
    let pairs = fields.get(2..).unwrap_or_default();
    if pairs.len() % 2 != 0 {
        return Err("a regex is missing its replacement".to_string());
    }
    let mut replacements = Vec::new();
    for pair in pairs.chunks(2) {
        let pattern = Pattern::multiline(&field_text(pair, 0))?;
        replacements.push(BodyReplacement {
            pattern,
            with: field_text(pair, 1),
        });
    }
    Ok(BodyRewrite {
        response,
        pattern: Pattern::new(&field_text(&fields, 1))?,
        action: BodyAction::Replace(replacements),
    })
}

/// The pattern of a jq line, and the expression after it as written: its own quotes and
/// spaces are jq's, not the line's.
fn leading_field(text: &str) -> Option<(String, &str)> {
    let text = text.trim_start();
    let Some(quoted) = text.strip_prefix('"') else {
        let end = text.find([' ', '\t']).unwrap_or(text.len());
        return Some((text[..end].to_string(), &text[end..]));
    };
    let mut out = String::new();
    let mut chars = quoted.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '\\' if quoted[at + 1..].starts_with('"') => {
                out.push('"');
                chars.next();
            }
            '"' => return Some((out, &quoted[at + 1..])),
            c => out.push(c),
        }
    }
    None
}

fn unwrap_quotes(text: &str) -> &str {
    for mark in ['\'', '"'] {
        if text.len() >= 2 && text.starts_with(mark) && text.ends_with(mark) {
            return &text[1..text.len() - 1];
        }
    }
    text
}

impl BodyRewrite {
    pub(crate) fn apply(&self, body: String) -> String {
        match &self.action {
            BodyAction::Replace(replacements) => {
                replacements.iter().fold(body, |body, replacement| {
                    replacement
                        .pattern
                        .replace(&body, &replacement.with, true)
                        .unwrap_or(body)
                })
            }
            BodyAction::Jq(jq) => match jq.run(&body) {
                JqOutcome::Rewritten(rewritten) => rewritten,
                JqOutcome::NotJson => {
                    tracing::debug!("[MITM] jq rewrite skipped: the body is not JSON");
                    body
                }
                JqOutcome::Empty => body,
                JqOutcome::Failed(err) => {
                    tracing::warn!("[MITM] jq rewrite failed: {err}");
                    body
                }
            },
        }
    }
}

fn is_local(name: &str) -> bool {
    if name.is_empty() || name.contains('\\') {
        return false;
    }
    let mut depth: i32 = 0;
    for component in Path::new(name).components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            _ => return false,
        }
    }
    true
}

pub(crate) fn read_resource(dir: &Path, param: &str, name: &str) -> Result<Vec<u8>, String> {
    if !is_local(name) {
        return Err(format!(
            "{param} {} is not a file in the resources directory",
            quote(name)
        ));
    }
    let path = dir.join(name);
    let info = std::fs::symlink_metadata(&path).map_err(|err| {
        let reason = match err.kind() {
            std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
            std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
            _ => "cannot be read".to_string(),
        };
        format!("{param} {}: {reason}", quote(name))
    })?;
    if !info.file_type().is_file() {
        return Err(format!("{param} {} is not a regular file", quote(name)));
    }
    std::fs::read(&path).map_err(|_| format!("{param} {} cannot be read", quote(name)))
}

fn mime_by_extension(name: &str) -> Option<&'static str> {
    let ext = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "avif" => "image/avif",
        "css" => "text/css; charset=utf-8",
        "gif" => "image/gif",
        "htm" | "html" => "text/html; charset=utf-8",
        "jpeg" | "jpg" => "image/jpeg",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "wasm" => "application/wasm",
        "webp" => "image/webp",
        "xml" => "text/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        _ => return None,
    })
}

pub(crate) fn parse_map_local(line: &str, resources: &Path) -> Result<MapLocal, String> {
    let fields = split_fields(line)?;
    if fields.len() < 2 {
        return Err("expected a pattern and the data to answer with".to_string());
    }
    let mut params = std::collections::HashMap::new();
    for field in fields.get(1..).unwrap_or_default() {
        let (key, value) = field
            .text
            .split_once('=')
            .ok_or_else(|| format!("expected key=value, got {}", quote(&field.text)))?;
        params.insert(key.to_ascii_lowercase(), value.to_string());
    }
    let get = |key: &str| params.get(key).map(String::as_str).unwrap_or_default();
    let (body, content_type) = match get("data-type") {
        "text" => (
            get("data").as_bytes().to_vec(),
            "text/plain; charset=utf-8".to_string(),
        ),
        "tiny-gif" => (tiny_gif(), "image/gif".to_string()),
        "base64" => (
            decode_base64(get("data")).map_err(|err| format!("data: {err}"))?,
            "application/octet-stream".to_string(),
        ),
        "" | "file" => (
            read_resource(resources, "data", get("data"))?,
            mime_by_extension(get("data"))
                .unwrap_or("application/octet-stream")
                .to_string(),
        ),
        other => return Err(format!("unknown data-type {}", quote(other))),
    };
    let mut status = StatusCode::OK;
    if let Some(text) = params.get("status-code") {
        status = text
            .parse::<u16>()
            .ok()
            .filter(|code| (200..=999).contains(code))
            .and_then(|code| StatusCode::from_u16(code).ok())
            .ok_or_else(|| format!("invalid status-code {}", quote(text)))?;
    }
    let mut header = HeaderMap::new();
    let header_text = get("header");
    if !header_text.is_empty() {
        parse_map_local_header(header_text, &mut header)?;
    }
    if !header.contains_key(http::header::CONTENT_TYPE) {
        let value =
            HeaderValue::from_str(&content_type).map_err(|_| "invalid content type".to_string())?;
        header.insert(http::header::CONTENT_TYPE, value);
    }
    Ok(MapLocal {
        pattern: Pattern::new(&field_text(&fields, 0))?,
        status,
        header,
        body,
    })
}

fn parse_map_local_header(text: &str, header: &mut HeaderMap) -> Result<(), String> {
    let decoded;
    let (text, separator) = if text.contains(':') {
        (text, '|')
    } else {
        let bytes = decode_base64(text).map_err(|err| format!("header: {err}"))?;
        decoded = String::from_utf8_lossy(&bytes).into_owned();
        (decoded.as_str(), '\n')
    };
    for line in text.split(separator) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("header {} has no value", quote(line)))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| format!("invalid header name {}", quote(name.trim())))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| format!("invalid header value {}", quote(value.trim())))?;
        header.append(name, value);
    }
    Ok(())
}

impl Rules {
    pub(crate) fn rewrite_url(&self, url: &str) -> Option<(&UrlRewrite, String)> {
        for rule in &self.url_rewrites {
            if !rule.pattern.is_match(url) {
                continue;
            }
            if rule.action.rejects() {
                return Some((rule, String::new()));
            }
            let replaced = rule.pattern.replace(url, &rule.replacement, false)?;
            return Some((rule, replaced));
        }
        None
    }

    pub(crate) fn map_local(&self, url: &str) -> Option<&MapLocal> {
        self.map_locals
            .iter()
            .find(|rule| rule.pattern.is_match(url))
    }

    pub(crate) fn rewrite_headers(
        &self,
        url: &str,
        header: &mut HeaderMap,
        response: bool,
    ) -> usize {
        self.header_rewrites
            .iter()
            .filter(|rule| rule.response == response && rule.pattern.is_match(url))
            .filter(|rule| rule.apply(header))
            .count()
    }

    pub(crate) fn body_rewrites_for(&self, url: &str, response: bool) -> Vec<&BodyRewrite> {
        self.body_rewrites
            .iter()
            .filter(|rule| rule.response == response && rule.pattern.is_match(url))
            .collect()
    }

    pub(crate) fn script_for(&self, url: &str, response: bool) -> Option<&std::sync::Arc<Script>> {
        self.scripts
            .iter()
            .find(|script| script.matches_http(url, response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(line: &str) -> (UrlAction, String) {
        let rule = parse_url_rewrite(line).unwrap_or_else(|err| panic!("{line}: {err}"));
        (rule.action, rule.replacement)
    }

    #[test]
    fn url_rewrite_reads_surge_loon_and_quantumult_x() {
        let cases = [
            (r"^https?://ad\.com/ _ reject", UrlAction::Reject, ""),
            (r"^https?://ad\.com/ reject-dict", UrlAction::RejectDict, ""),
            (
                r"^https?://ad\.com/ url reject-img",
                UrlAction::RejectImg,
                "",
            ),
            (
                r"^https?://ad\.com/ url 302 https://b.com/",
                UrlAction::Redirect302,
                "https://b.com/",
            ),
            (
                r"^https?://ad\.com/ 302 https://b.com/",
                UrlAction::Redirect302,
                "https://b.com/",
            ),
            (
                r"^http://a\.com/(.*) http://b.com/$1 307",
                UrlAction::Redirect307,
                "http://b.com/$1",
            ),
            (
                r"^http://a\.com http://b.com",
                UrlAction::Header,
                "http://b.com",
            ),
            (
                r"^http://a\.com http://b.com header",
                UrlAction::Header,
                "http://b.com",
            ),
        ];
        for (line, action, replacement) in cases {
            assert_eq!(rewrite(line), (action, replacement.to_string()), "{line}");
        }
    }

    #[test]
    fn url_rewrite_rejects_bad_lines() {
        for line in [
            "^a",
            "^a b c d",
            "^a b nope",
            "^a _ 302",
            "(unclosed b",
            "^a \"b",
        ] {
            assert!(parse_url_rewrite(line).is_err(), "{line}");
        }
    }

    fn rules_with(urls: &[&str]) -> Rules {
        let mut rules = Rules::default();
        for line in urls {
            rules.url_rewrites.push(parse_url_rewrite(line).unwrap());
        }
        rules
    }

    #[test]
    fn rewrite_url_replaces_the_match_and_stops_at_the_first_rule() {
        let rules = rules_with(&[
            r"^http://www\.google\.cn http://www.google.com",
            r"^http://www\.google\.cn _ reject",
            r"^https://a\.com/(\w+)/(\d+) https://b.com/$2/$1 302",
        ]);
        let (rule, replaced) = rules
            .rewrite_url("http://www.google.cn/search?q=x")
            .unwrap();
        assert_eq!(rule.action, UrlAction::Header);
        assert_eq!(replaced, "http://www.google.com/search?q=x");
        let (_, replaced) = rules.rewrite_url("https://a.com/item/42").unwrap();
        assert_eq!(replaced, "https://b.com/42/item");
        assert!(rules.rewrite_url("https://c.com/").is_none());
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        map
    }

    #[test]
    fn header_rewrite_actions() {
        let lines = [
            r"http-request ^https://a\.com header-add X-Added one",
            r"^https://a\.com header-add User-Agent Mozilla/5.0 (iPhone; CPU OS 18_0)",
            r"http-request ^https://a\.com header-del Cookie",
            r"http-request ^https://a\.com header-replace Accept text/html",
            r"http-request ^https://a\.com header-replace Missing value",
            r"http-request ^https://a\.com header-replace-regex Referer http https",
            r"http-response ^https://a\.com header-del Set-Cookie",
        ];
        let mut rules = Rules::default();
        for line in lines {
            rules
                .header_rewrites
                .push(parse_header_rewrite(line).unwrap_or_else(|e| panic!("{line}: {e}")));
        }
        let mut header = headers(&[
            ("cookie", "a=b"),
            ("accept", "*/*"),
            ("referer", "http://a.com/x"),
            ("set-cookie", "c=d"),
        ]);
        assert_eq!(
            rules.rewrite_headers("https://a.com/", &mut header, false),
            5
        );
        let get = |name: &str| {
            header
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        assert_eq!(get("x-added").as_deref(), Some("one"));
        assert_eq!(
            get("user-agent").as_deref(),
            Some("Mozilla/5.0 (iPhone; CPU OS 18_0)")
        );
        assert_eq!(get("accept").as_deref(), Some("text/html"));
        assert_eq!(get("referer").as_deref(), Some("https://a.com/x"));
        assert_eq!(get("set-cookie").as_deref(), Some("c=d"));
        assert_eq!(get("cookie"), None);
        assert_eq!(header.len(), 5);
    }

    #[test]
    fn header_rewrite_keeps_framing_headers() {
        for line in [
            r"^https://a\.com header-del Content-Length",
            r"http-response ^https://a\.com header-replace transfer-encoding chunked",
        ] {
            assert!(parse_header_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn body_rewrite_chains_pairs() {
        let rule = parse_body_rewrite(
            r#"http-response ^https://a\.com "\"ad\":true" "\"ad\":false" ^line$ replaced"#,
        )
        .unwrap();
        let got = rule.apply("{\"ad\":true}\nline\nkeep line".to_string());
        assert_eq!(got, "{\"ad\":false}\nreplaced\nkeep line");
        for line in [
            "http-response ^a only",
            "http-response-jq ^a '.a ='",
            "http-response-jq ^a",
            "sideways ^a b c",
        ] {
            assert!(parse_body_rewrite(line).is_err(), "{line}");
        }
    }

    #[test]
    fn map_local_parameters() {
        let nowhere = Path::new("/nonexistent-resources");
        let rule = parse_map_local(
            r#"^https://a\.com/json data-type=text data="{\"ok\":1}" status-code=500 header="Content-Type:application/json|X-A:b""#,
            nowhere,
        )
        .unwrap();
        assert_eq!(rule.body, br#"{"ok":1}"#);
        assert_eq!(rule.status.as_u16(), 500);
        assert_eq!(rule.header.get("content-type").unwrap(), "application/json");
        assert_eq!(rule.header.get("x-a").unwrap(), "b");
        let gif = parse_map_local(r"^https://a\.com/gif data-type=tiny-gif", nowhere).unwrap();
        assert_eq!(gif.header.get("content-type").unwrap(), "image/gif");
        assert!(!gif.body.is_empty());
        let encoded = parse_map_local(
            r#"^https://a\.com/b data-type=base64 data="dGVzdA==" header=WC1COiBj"#,
            nowhere,
        )
        .unwrap();
        assert_eq!(encoded.body, b"test");
        assert_eq!(encoded.header.get("x-b").unwrap(), "c");
        for line in [
            r#"^https://a\.com/x data="missing.json""#,
            r"^https://a\.com/x data-type=text status-code=99",
            r"^https://a\.com/x data-type=base64 data=%%%",
            r"^https://a\.com/x novalue",
        ] {
            assert!(parse_map_local(line, nowhere).is_err(), "{line}");
        }
    }

    #[test]
    fn map_local_serves_files_from_the_resources_directory_only() {
        let home = tempfile::tempdir().unwrap();
        let resources = home.path().join("resources");
        std::fs::create_dir_all(resources.join("sub")).unwrap();
        std::fs::write(resources.join("a.json"), br#"{"ok":1}"#).unwrap();
        std::fs::write(resources.join("sub/b"), b"raw").unwrap();
        std::fs::write(home.path().join("secret.txt"), b"secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(home.path().join("secret.txt"), resources.join("link.txt"))
            .unwrap();

        let rule = parse_map_local(r#"^https://a\.com/x data="a.json""#, &resources).unwrap();
        assert_eq!(rule.body, br#"{"ok":1}"#);
        assert_eq!(rule.header.get("content-type").unwrap(), "application/json");
        let rule = parse_map_local(
            r#"^https://a\.com/x data-type=file data="sub/b" header="Content-Type:text/x""#,
            &resources,
        )
        .unwrap();
        assert_eq!(rule.body, b"raw");
        assert_eq!(rule.header.get("content-type").unwrap(), "text/x");

        let secret = home.path().join("secret.txt").display().to_string();
        for data in [
            "../secret.txt",
            "sub/../../secret.txt",
            &secret,
            r"sub\b",
            "link.txt",
            "sub",
            "",
        ] {
            let line = format!(r#"^https://a\.com/x data-type=file data="{data}""#);
            let err = parse_map_local(&line, &resources).expect_err(data);
            assert!(
                !err.contains(&resources.display().to_string()),
                "{data}: {err}"
            );
        }
    }
}
