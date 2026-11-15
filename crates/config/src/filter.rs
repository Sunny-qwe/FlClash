use crate::error::{ConfigError, Result};

#[derive(Clone, Debug)]
pub enum Matcher {
    Plain(regex::Regex),
    Fancy(fancy_regex::Regex),
}

impl Matcher {
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Matcher::Plain(re) => re.is_match(text),
            Matcher::Fancy(re) => re.is_match(text).unwrap_or(false),
        }
    }
}

impl Matcher {
    pub fn replace_all(&self, text: &str, replacement: &str) -> String {
        match self {
            Matcher::Plain(re) => re.replace_all(text, replacement).into_owned(),
            Matcher::Fancy(re) => re.replace_all(text, replacement).into_owned(),
        }
    }
}

pub fn compile_pattern(pattern: &str, ignore_case: bool) -> Result<Matcher> {
    let translated = translate_class_subtraction(pattern);
    let plain = regex::RegexBuilder::new(&translated)
        .case_insensitive(ignore_case)
        .size_limit(10 << 20)
        .build();
    match plain {
        Ok(re) => Ok(Matcher::Plain(re)),
        Err(_) => {
            let source = if ignore_case {
                format!("(?i){translated}")
            } else {
                translated
            };
            fancy_regex::Regex::new(&source)
                .map(Matcher::Fancy)
                .map_err(|err| ConfigError::new(format!("error parsing regexp: {err}")))
        }
    }
}

fn translate_class_subtraction(pattern: &str) -> String {
    if !pattern.contains("-[") {
        return pattern.to_string();
    }
    let mut out = String::with_capacity(pattern.len() + 2);
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    let mut escaped = false;
    let mut prev: Option<char> = None;
    while let Some(c) = chars.next() {
        if escaped {
            escaped = false;
            out.push(c);
            prev = Some(c);
            continue;
        }
        match c {
            '\\' => {
                escaped = true;
                out.push(c);
            }
            '[' if !in_class => {
                in_class = true;
                out.push(c);
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            '-' if in_class && chars.peek() == Some(&'[') && prev != Some('[') => {
                out.push_str("--");
            }
            _ => out.push(c),
        }
        prev = Some(c);
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct CompiledFilter {
    parts: Vec<Matcher>,
}

impl CompiledFilter {
    pub fn compile(filter: &str) -> Result<CompiledFilter> {
        let mut parts = Vec::new();
        for part in filter.split('`') {
            parts.push(compile_pattern(part, false)?);
        }
        Ok(CompiledFilter { parts })
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.parts.iter().any(|part| part.is_match(text))
    }

    pub fn len(&self) -> usize {
        self.parts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }
}

pub fn validate(filter: &str) -> Result<()> {
    CompiledFilter::compile(filter).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_backtick_part_must_compile() {
        let cases = [
            ("", true),
            ("(?i)港|(?<![a-z])hk(?![a-z])", true),
            ("hk`jp", true),
            ("[a-z-[aeiou]]", true),
            ("(abc", false),
            ("hk`(", false),
        ];
        for (filter, valid) in cases {
            assert_eq!(validate(filter).is_ok(), valid, "filter {filter:?}");
        }
    }

    #[test]
    fn any_part_may_match() {
        let filter = CompiledFilter::compile("hk`jp").unwrap();
        assert!(filter.is_match("JP-hk-01"));
        assert!(filter.is_match("jp 1"));
        assert!(!filter.is_match("us 1"));
    }

    #[test]
    fn lookaround_survives_the_fallback() {
        let filter = CompiledFilter::compile("(?i)(?<![a-z])hk(?![a-z])").unwrap();
        assert!(filter.is_match("HK 01"));
        assert!(!filter.is_match("CHKS 1"));
    }

    #[test]
    fn dotnet_class_subtraction_is_translated() {
        let filter = CompiledFilter::compile("^[a-z-[aeiou]]+$").unwrap();
        assert!(filter.is_match("xyz"));
        assert!(!filter.is_match("abc"));
    }

    #[test]
    fn the_app_presets_match_their_names_only() {
        let hong_kong = CompiledFilter::compile("(?i)港|\\bhk\\b|hong ?kong|🇭🇰").unwrap();
        assert!(hong_kong.is_match("🇭🇰 HK 01"));
        assert!(hong_kong.is_match("Hong Kong-02"));
        assert!(!hong_kong.is_match("Japan 01"));
    }

    fn presets() -> Option<Vec<(String, String)>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../lib/models/config.dart");
        let source = std::fs::read_to_string(path).ok()?;
        let body = source.split_once("const defaultFilters = [")?.1;
        let body = body.split_once("\n];")?.0;
        let entry = regex::Regex::new(
            r"Filter\(\s*label:\s*'([^']*)',\s*regex:\s*((?:r'[^']*'\s*)+),?\s*\)",
        )
        .ok()?;
        let raw = regex::Regex::new(r"r'([^']*)'").ok()?;
        Some(
            entry
                .captures_iter(body)
                .map(|cap| {
                    let pattern: String = raw
                        .captures_iter(&cap[2])
                        .map(|part| part[1].to_string())
                        .collect();
                    (cap[1].to_string(), pattern)
                })
                .collect(),
        )
    }

    #[test]
    fn the_dart_presets_match_their_names_only() {
        let matches: &[(&str, &[&str])] = &[
            ("Hong Kong", &["🇭🇰 HK 01", "香港 IPLC", "Hong Kong-02"]),
            ("Taiwan", &["🇹🇼 TW", "台湾 家宽", "Taiwan 03"]),
            ("Japan", &["JP01", "日本 东京", "Tokyo 2"]),
            ("Singapore", &["SG-1", "新加坡", "Singapore"]),
            ("United States", &["US 01", "USA", "美国 洛杉矶", "美西"]),
            ("South Korea", &["KR 1", "韩国", "South Korea"]),
            ("United Kingdom", &["UK-London", "英国", "GB 2"]),
            (
                "Remaining Traffic",
                &[
                    "剩余流量：10 GB",
                    "剩餘流量: 1.2 TB",
                    "已用流量 20%",
                    "流量：10G / 100G",
                    "Traffic: 10 GB",
                    "Remaining 1 TB",
                ],
            ),
            (
                "Expiry Date",
                &[
                    "套餐到期：2026-12-31",
                    "过期时间：2026-01-01",
                    "Expire: 2026-12-31",
                    "Expiration 2026-12-31",
                ],
            ),
            (
                "Traffic Reset",
                &["距离下次重置剩余：12 天", "Next Reset: 12 days"],
            ),
            (
                "Website & Notices",
                &[
                    "官网：example.com",
                    "最新网址 example.com",
                    "公告：请更新订阅",
                    "当前套餐：Pro",
                    "Telegram 群组",
                    "TG 频道",
                    "Website: example.com",
                ],
            ),
        ];
        let misses: &[(&str, &[&str])] = &[
            ("Hong Kong", &["CHKS 1", "Japan 01"]),
            ("United States", &["Russia 01", "Australia", "Plus"]),
            ("United Kingdom", &["Ukraine 01"]),
            ("Remaining Traffic", &["香港 01", "US 大带宽", "HK 大流量"]),
            ("Expiry Date", &["香港 01", "Japan 01"]),
            ("Traffic Reset", &["香港 01", "US Reserved"]),
            (
                "Website & Notices",
                &["香港 01", "US Montgomery", "Taiwan 01"],
            ),
        ];
        let Some(presets) = presets() else {
            return;
        };
        assert!(
            !presets.is_empty(),
            "found no presets; the parser lost track of defaultFilters"
        );
        for (name, pattern) in &presets {
            let samples = matches.iter().find(|(n, _)| n == name).map(|(_, s)| *s);
            let samples =
                samples.unwrap_or_else(|| panic!("preset {name} has no sample names here"));
            let matcher = compile_pattern(pattern, false).unwrap();
            for sample in samples {
                assert!(matcher.is_match(sample), "preset {name} misses {sample:?}");
            }
            for (n, bad) in misses {
                if n == name {
                    for sample in *bad {
                        assert!(
                            !matcher.is_match(sample),
                            "preset {name} matches {sample:?}"
                        );
                    }
                }
            }
        }
        for (name, _) in matches {
            assert!(
                presets.iter().any(|(n, _)| n == name),
                "preset {name} is gone from defaultFilters"
            );
        }
    }
}
