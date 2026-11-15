use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize};

use crate::hostlist::{HostList, parse_host_line};
use crate::limits::{Limits, RawLimits};
use crate::rules::{
    Rules, parse_body_rewrite, parse_header_rewrite, parse_map_local, parse_url_rewrite,
};
use crate::script::{ScriptHost, parse_script};
use crate::text::quote;

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
    pub auto_quic_block: bool,
    pub h2: bool,
    pub limits: Limits,
    pub(crate) rules: Rules,
    raw: RawConfig,
}

type AddLine = fn(&mut Config, &ParseEnv, &str) -> Result<(), String>;

struct ListSpec {
    key: &'static str,
    lines: fn(&RawConfig) -> &[String],
    add: AddLine,
}

const LISTS: [ListSpec; 6] = [
    ListSpec {
        key: "hostname",
        lines: |raw| &raw.hostname,
        add: |config, _, line| {
            let (hosts, errors) = parse_host_line(line);
            config.hosts.extend(hosts);
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("\n"))
            }
        },
    },
    ListSpec {
        key: "url-rewrite",
        lines: |raw| &raw.url_rewrite,
        add: |config, _, line| {
            config.rules.url_rewrites.push(parse_url_rewrite(line)?);
            Ok(())
        },
    },
    ListSpec {
        key: "header-rewrite",
        lines: |raw| &raw.header_rewrite,
        add: |config, _, line| {
            config
                .rules
                .header_rewrites
                .push(parse_header_rewrite(line)?);
            Ok(())
        },
    },
    ListSpec {
        key: "body-rewrite",
        lines: |raw| &raw.body_rewrite,
        add: |config, _, line| {
            config.rules.body_rewrites.push(parse_body_rewrite(line)?);
            Ok(())
        },
    },
    ListSpec {
        key: "map-local",
        lines: |raw| &raw.map_local,
        add: |config, env, line| {
            config
                .rules
                .map_locals
                .push(parse_map_local(line, &env.resources)?);
            Ok(())
        },
    },
    ListSpec {
        key: "script",
        lines: |raw| &raw.script,
        add: |config, env, line| {
            let script = parse_script(line, &env.resources, &env.scripts)?;
            config.rules.scripts.push(Arc::new(script));
            Ok(())
        },
    },
];

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
            auto_quic_block: raw.auto_quic_block.unwrap_or(true),
            h2: raw.h2,
            limits: raw.limits.resolve(),
            rules: Rules::default(),
            raw,
        }
    }

    /// Lines that cannot be read are skipped and named in the errors.
    pub fn parse(raw: RawConfig, env: &ParseEnv) -> (Config, Vec<String>) {
        let mut config = Config::empty(raw.clone());
        let mut errors = Vec::new();
        for list in &LISTS {
            each_line((list.lines)(&raw), |_, line| {
                if let Err(err) = (list.add)(&mut config, env, line) {
                    errors.push(format!("{} {}: {err}", list.key, quote(line)));
                }
            });
        }
        env.scripts.keep(&config.rules.scripts);
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

/// Issues by list, naming the lines that cannot be read.
pub fn check(raw: &RawConfig, env: &ParseEnv) -> BTreeMap<String, Vec<Issue>> {
    let mut issues: BTreeMap<String, Vec<Issue>> = BTreeMap::new();
    let mut scratch = Config::empty(RawConfig::default());
    for list in &LISTS {
        each_line((list.lines)(raw), |index, line| {
            if let Err(message) = (list.add)(&mut scratch, env, line) {
                issues
                    .entry(list.key.to_string())
                    .or_default()
                    .push(Issue { index, message });
            }
        });
    }
    issues
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
        let issues = check(&raw, &env);
        let want = vec![Issue {
            index: 1,
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
        let issues = check(&raw, &env);
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
