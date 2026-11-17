use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize};

use crate::hostlist::{HostList, parse_host_line};
use crate::issue::{IssueKind, LineError};
use crate::limits::{Limits, RawLimits};
use crate::rules::{
    Rules, parse_body_rewrite, parse_header_rewrite, parse_map_local, parse_url_rewrite,
};
use crate::script::{ScriptHost, parse_script};
use crate::sources::SourceList;
use crate::text::quote;
use crate::view::{LineView, SourcesView};

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Lines in Surge's syntax; one that cannot be read is skipped, not fatal to the config.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct RawConfig {
    #[serde(deserialize_with = "null_default")]
    pub enable: bool,
    #[serde(deserialize_with = "null_default")]
    pub hostname: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub skip_server_cert_verify: bool,
    /// Hosts whose servers' certificates go unchecked while the switch above is off, as a
    /// module that skips verifying asks for its own hostnames only.
    #[serde(deserialize_with = "null_default")]
    pub skip_server_cert_verify_hostname: Vec<String>,
    /// The clients decrypted for, in Surge's syntax; all of them while it is empty.
    #[serde(deserialize_with = "null_default")]
    pub client_source_address: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_quic_block: Option<bool>,
    #[serde(deserialize_with = "null_default")]
    pub url_rewrite: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub header_rewrite: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub body_rewrite: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub map_local: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub request_body_mock: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    pub script: Vec<String>,
    /// Off while the device does not trust the CA: HTTPS is then relayed as
    /// is, and only plain HTTP is rewritten.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decrypt_tls: Option<bool>,
    /// The CA the host verified; TLS is decrypted only with it, so a CA that
    /// another process replaced is read again rather than used stale.
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub ca_fingerprint: String,
    /// Offers HTTP/2 to clients, as Surge's h2; servers are always offered it.
    #[serde(deserialize_with = "null_default")]
    pub h2: bool,
    #[serde(deserialize_with = "null_default")]
    pub limits: RawLimits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub index: usize,
    pub kind: IssueKind,
    pub message: String,
}

pub struct ParseEnv {
    pub resources: PathBuf,
    pub scripts: Arc<ScriptHost>,
}

pub struct Config {
    pub enable: bool,
    pub decrypt_tls: bool,
    pub ca_fingerprint: String,
    pub hosts: HostList,
    pub skip_server_cert_verify: bool,
    pub skip_verify_hosts: HostList,
    pub(crate) sources: SourceList,
    pub auto_quic_block: bool,
    pub h2: bool,
    pub limits: Limits,
    pub(crate) rules: Rules,
    /// Plain HTTP on port 80 is read whatever its host while a rule can act on a request, as
    /// Surge's HTTP engine reads it without a hostname entry.
    pub(crate) plain_http: bool,
    raw: RawConfig,
}

/// What a line put in force and what of it could not be read: a hostname or source line has
/// both when some of its items apply.
struct LineRead {
    view: Option<LineView>,
    error: Option<LineError>,
}

type AddLine = fn(&mut Config, &ParseEnv, &str) -> LineRead;

struct ListSpec {
    key: &'static str,
    lines: fn(&RawConfig) -> &[String],
    add: AddLine,
}

fn read<T>(parsed: Result<T, LineError>, add: impl FnOnce(T) -> LineView) -> LineRead {
    match parsed {
        Ok(rule) => LineRead {
            view: Some(add(rule)),
            error: None,
        },
        Err(err) => LineRead {
            view: None,
            error: Some(err),
        },
    }
}

fn read_hosts(list: &mut HostList, line: &str) -> LineRead {
    let (hosts, errors) = parse_host_line(line);
    let view = hosts.view();
    list.extend(hosts);
    LineRead {
        view,
        error: host_errors(errors),
    }
}

const LISTS: [ListSpec; 9] = [
    ListSpec {
        key: "hostname",
        lines: |raw| &raw.hostname,
        add: |config, _, line| read_hosts(&mut config.hosts, line),
    },
    ListSpec {
        key: "skip-server-cert-verify-hostname",
        lines: |raw| &raw.skip_server_cert_verify_hostname,
        add: |config, _, line| read_hosts(&mut config.skip_verify_hosts, line),
    },
    ListSpec {
        key: "client-source-address",
        lines: |raw| &raw.client_source_address,
        add: |config, _, line| {
            let (entries, result) = config.sources.add_line(line);
            LineRead {
                view: (!entries.is_empty()).then_some(LineView::Sources(SourcesView { entries })),
                error: result.err().map(LineError::from),
            }
        },
    },
    ListSpec {
        key: "url-rewrite",
        lines: |raw| &raw.url_rewrite,
        add: |config, _, line| {
            read(parse_url_rewrite(line), |rule| {
                let view = rule.view();
                config.rules.url_rewrites.push(rule);
                view
            })
        },
    },
    ListSpec {
        key: "header-rewrite",
        lines: |raw| &raw.header_rewrite,
        add: |config, _, line| {
            read(parse_header_rewrite(line), |rule| {
                let view = rule.view();
                config.rules.header_rewrites.push(rule);
                view
            })
        },
    },
    ListSpec {
        key: "body-rewrite",
        lines: |raw| &raw.body_rewrite,
        add: |config, _, line| {
            read(parse_body_rewrite(line), |rule| {
                let view = rule.view();
                config.rules.body_rewrites.push(Arc::new(rule));
                view
            })
        },
    },
    ListSpec {
        key: "map-local",
        lines: |raw| &raw.map_local,
        add: |config, env, line| {
            read(
                parse_map_local(line, &env.resources, false),
                |(rule, view)| {
                    config.rules.map_locals.push(rule);
                    view
                },
            )
        },
    },
    ListSpec {
        key: "request-body-mock",
        lines: |raw| &raw.request_body_mock,
        add: |config, env, line| {
            read(
                parse_map_local(line, &env.resources, true),
                |(rule, view)| {
                    config.rules.request_mocks.push(rule);
                    view
                },
            )
        },
    },
    ListSpec {
        key: "script",
        lines: |raw| &raw.script,
        add: |config, env, line| {
            read(parse_script(line, &env.resources, &env.scripts), |script| {
                let view = script.view();
                config.rules.scripts.push(Arc::new(script));
                view
            })
        },
    },
];

/// A line's bad items as one error, of the first item's kind.
fn host_errors(errors: Vec<LineError>) -> Option<LineError> {
    let first = errors.first()?;
    let message = errors
        .iter()
        .map(|err| err.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    Some(LineError::new(first.kind, message))
}

fn each_line(lines: &[String], mut visit: impl FnMut(usize, &str)) {
    for (index, line) in lines.iter().enumerate() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            visit(index, line);
        }
    }
}

impl Config {
    fn empty(raw: RawConfig) -> Config {
        Config {
            enable: raw.enable,
            decrypt_tls: raw.decrypt_tls.unwrap_or(true),
            ca_fingerprint: normalize_fingerprint(&raw.ca_fingerprint),
            hosts: HostList::default(),
            skip_server_cert_verify: raw.skip_server_cert_verify,
            skip_verify_hosts: HostList::default(),
            sources: SourceList::default(),
            auto_quic_block: raw.auto_quic_block.unwrap_or(true),
            h2: raw.h2,
            limits: raw.limits.resolve(),
            rules: Rules::default(),
            plain_http: false,
            raw,
        }
    }

    /// Lines that cannot be read are skipped and named in the errors.
    pub fn parse(raw: RawConfig, env: &ParseEnv) -> (Config, Vec<String>) {
        let mut config = Config::empty(raw.clone());
        let mut errors = Vec::new();
        for list in &LISTS {
            each_line((list.lines)(&raw), |_, line| {
                if let Some(err) = (list.add)(&mut config, env, line).error {
                    errors.push(format!("{} {}: {err}", list.key, quote(line)));
                }
            });
        }
        env.scripts.keep(&config.rules.scripts);
        config.plain_http = config.rules.acts_on_requests();
        (config, errors)
    }

    pub fn same(&self, other: &Config) -> bool {
        self.raw == other.raw
    }

    pub fn raw(&self) -> &RawConfig {
        &self.raw
    }

    pub fn script_names(&self) -> Vec<&str> {
        self.rules
            .scripts
            .iter()
            .map(|script| script.name.as_str())
            .collect()
    }
}

/// By list, the lines that cannot be read, and how each line in force reads; a line some of
/// whose items apply is in both.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Validation {
    pub issues: BTreeMap<String, Vec<Issue>>,
    pub views: BTreeMap<String, Vec<LineEntry>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LineEntry {
    pub index: usize,
    pub view: LineView,
}

pub fn check(raw: &RawConfig, env: &ParseEnv) -> Validation {
    let mut validation = Validation::default();
    let mut scratch = Config::empty(RawConfig::default());
    for list in &LISTS {
        each_line((list.lines)(raw), |index, line| {
            let read = (list.add)(&mut scratch, env, line);
            if let Some(err) = read.error {
                let issue = Issue {
                    index,
                    kind: err.kind,
                    message: err.message,
                };
                validation
                    .issues
                    .entry(list.key.to_string())
                    .or_default()
                    .push(issue);
            }
            if let Some(view) = read.view {
                let entry = LineEntry { index, view };
                validation
                    .views
                    .entry(list.key.to_string())
                    .or_default()
                    .push(entry);
            }
        });
    }
    validation
}

/// Upper-case hex pairs joined by colons.
pub fn normalize_fingerprint(text: &str) -> String {
    let hex: String = text
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != ' ')
        .collect::<String>()
        .to_uppercase();
    let mut pairs = Vec::with_capacity(hex.len() / 2 + 1);
    let mut rest = hex.as_str();
    while rest.len() > 2 {
        let (pair, tail) = rest.split_at(2);
        pairs.push(pair);
        rest = tail;
    }
    if !rest.is_empty() {
        pairs.push(rest);
    }
    pairs.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> (tempfile::TempDir, ParseEnv) {
        let home = tempfile::tempdir().unwrap();
        let env = ParseEnv {
            resources: home.path().join("resources"),
            scripts: Arc::new(ScriptHost::default()),
        };
        (home, env)
    }

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn check_names_the_item_of_a_hostname_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            hostname: lines(&["b.com", "a.com, bad host"]),
            ..RawConfig::default()
        };
        let issues = check(&raw, &env).issues;
        let want = vec![Issue {
            index: 1,
            kind: IssueKind::Invalid,
            message: "\"bad host\": unsupported character ' '".to_string(),
        }];
        assert_eq!(issues, BTreeMap::from([("hostname".to_string(), want)]));
    }

    #[test]
    fn validate_names_the_lines_of_each_list() {
        let (_home, env) = env();
        let raw = RawConfig {
            hostname: lines(&["a.test"]),
            url_rewrite: lines(&["^ok _ reject", "(broken _ reject", "# note"]),
            ..RawConfig::default()
        };
        let issues = check(&raw, &env).issues;
        assert_eq!(issues.len(), 1);
        assert_eq!(issues["url-rewrite"].len(), 1);
        assert_eq!(issues["url-rewrite"][0].index, 1);
    }

    #[test]
    fn parse_names_the_bad_line() {
        let (_home, env) = env();
        let raw = RawConfig {
            url_rewrite: lines(&["# comment", "", "^ok _ reject", "broken"]),
            map_local: lines(&["^x data-type=nope"]),
            ..RawConfig::default()
        };
        let (_, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(
            errors[0].contains("url-rewrite \"broken\""),
            "{}",
            errors[0]
        );
        assert!(errors[1].contains("map-local"), "{}", errors[1]);
    }

    #[test]
    fn defaults_follow_the_go_core() {
        let (_home, env) = env();
        let (config, errors) = Config::parse(
            RawConfig {
                enable: true,
                ..RawConfig::default()
            },
            &env,
        );
        assert!(errors.is_empty());
        assert!(config.decrypt_tls && config.auto_quic_block && !config.h2);
    }

    #[test]
    fn same_compares_the_section_not_the_compiled_rules() {
        let (_home, env) = env();
        let raw = RawConfig {
            enable: true,
            hostname: lines(&["a.test"]),
            ..RawConfig::default()
        };
        let (a, _) = Config::parse(raw.clone(), &env);
        let (b, _) = Config::parse(raw.clone(), &env);
        let (c, _) = Config::parse(
            RawConfig {
                enable: false,
                ..raw
            },
            &env,
        );
        assert!(a.same(&b) && !a.same(&c));
    }

    #[test]
    fn raw_config_reads_the_wire_names_and_nulls() {
        let raw: RawConfig = serde_json::from_str(
            r#"{"enable":true,"hostname":null,"skip-server-cert-verify":true,"decrypt-tls":false,
            "ca-fingerprint":"ab","h2":true,"limits":{"max-body-size":10}}"#,
        )
        .unwrap();
        assert!(raw.enable && raw.skip_server_cert_verify && raw.h2);
        assert_eq!(raw.decrypt_tls, Some(false));
        assert_eq!(raw.limits.max_body_size, 10);
        assert!(raw.hostname.is_empty());
    }

    #[test]
    fn the_section_reads_its_hosts_and_switches() {
        let (_home, env) = env();
        let raw: RawConfig = serde_json::from_value(serde_json::json!({
            "enable": true,
            "hostname": ["-skip.a.test", "*.a.test"],
            "url-rewrite": [r"^https://x\.a\.test/ad _ reject", "broken"],
        }))
        .unwrap();
        let (config, errors) = Config::parse(raw, &env);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(config.enable && config.auto_quic_block);
        assert!(config.hosts.matches("x.a.test", 443) && !config.hosts.matches("skip.a.test", 443));

        let raw: RawConfig = serde_json::from_value(serde_json::json!({
            "enable": true,
            "decrypt-tls": false,
            "ca-fingerprint": "aa:bb",
            "h2": true,
        }))
        .unwrap();
        let (config, _) = Config::parse(raw, &env);
        assert!(!config.decrypt_tls && config.h2);
        assert_eq!(config.ca_fingerprint, "AA:BB");
    }

    #[test]
    fn fingerprints_normalize() {
        assert_eq!(normalize_fingerprint(" ab:cd ef "), "AB:CD:EF");
        assert_eq!(normalize_fingerprint("aabbcc"), "AA:BB:CC");
        assert_eq!(normalize_fingerprint(" AA:bb:CC "), "AA:BB:CC");
        assert_eq!(normalize_fingerprint("aa bb cc"), "AA:BB:CC");
        assert_eq!(normalize_fingerprint("AA:BB:CC:DD"), "AA:BB:CC:DD");
        assert_eq!(normalize_fingerprint("abc"), "AB:C");
        assert_eq!(normalize_fingerprint(""), "");
    }
}
