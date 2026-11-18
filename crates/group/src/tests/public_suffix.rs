use std::collections::HashSet;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use psl::Type;

use crate::public_suffix::registrable_domain;

const PROBE: &str = "concordprobe";

fn data(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data/public-suffix")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn ascii_label(label: &str) -> String {
    match label.is_ascii() {
        true => label.to_owned(),
        false => format!(
            "xn--{}",
            idna::punycode::encode_str(label).expect("punycode")
        ),
    }
}

/// Every rule of the pinned list, an internationalised one also in Punycode, and whether it is in
/// the ICANN section.
fn rules() -> Vec<(String, bool)> {
    let mut icann = false;
    let mut rules = Vec::new();
    for line in data("public_suffix_list.dat").lines().map(str::trim) {
        if line.contains("===BEGIN ICANN DOMAINS===") {
            icann = true;
        } else if line.contains("===END ICANN DOMAINS===") {
            icann = false;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        rules.push((line.to_owned(), icann));
        if !line.is_ascii() {
            let ascii: Vec<String> = line.split('.').map(ascii_label).collect();
            rules.push((ascii.join("."), icann));
        }
    }
    rules
}

fn psl_domain(host: &str) -> Option<String> {
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let domain = psl::domain(host.as_bytes())?;
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_owned)
}

fn psl_suffix(name: &str) -> Option<(String, Option<Type>)> {
    let suffix = psl::suffix(name.as_bytes())?;
    Some((
        String::from_utf8(suffix.as_bytes().to_vec()).ok()?,
        suffix.typ(),
    ))
}

fn probes() -> Vec<String> {
    let mut probes: Vec<String> = [
        "",
        "localhost",
        "com",
        "example.com",
        "WWW.Example.COM",
        "a.b.unknowntld",
        "a.b.example.com.",
        ".example.com",
        "a..b.com",
        "1.2.3.4",
        "例子.测试",
        "a.b.c.d.e.f.co.uk",
    ]
    .map(str::to_owned)
    .into();
    for (rule, _) in rules() {
        let name = rule.trim_start_matches("*.").trim_start_matches('!');
        probes.extend([
            name.to_owned(),
            format!("a.{name}"),
            format!("b.a.{name}"),
            format!("B.A.{}", name.to_ascii_uppercase()),
        ]);
        let (first, rest) = name
            .split_once('.')
            .map_or((name, ""), |(first, rest)| (first, rest));
        let mut chars = first.chars();
        chars.next_back();
        let shorter = chars.as_str();
        let mut chars = first.chars();
        chars.next();
        let later = chars.as_str();
        for near in [shorter, later, &format!("{first}x")] {
            if !near.is_empty() {
                let near = if rest.is_empty() {
                    near.to_owned()
                } else {
                    format!("{near}.{rest}")
                };
                probes.extend([format!("a.{near}"), near]);
            }
        }
        let labels: Vec<&str> = name.split('.').collect();
        if !name.is_ascii() && labels.len() > 1 {
            for mixed in 0..labels.len() {
                let mixed: Vec<String> = labels
                    .iter()
                    .enumerate()
                    .map(|(at, label)| {
                        if at == mixed {
                            ascii_label(label)
                        } else {
                            (*label).to_owned()
                        }
                    })
                    .collect();
                probes.push(format!("a.{}", mixed.join(".")));
            }
        }
    }
    probes
}

#[test]
fn psl_was_built_from_the_pinned_list() {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    let lock = std::fs::read_to_string(lock_path).expect("Cargo.lock");
    let locked = lock
        .split("[[package]]")
        .find(|package| package.contains("\nname = \"psl\"\n"))
        .and_then(|package| {
            package
                .lines()
                .find_map(|line| line.strip_prefix("version = "))
        })
        .map(|version| version.trim_matches('"').to_owned());
    let pinned = data("VERSION")
        .lines()
        .find_map(|line| line.strip_prefix("psl ").map(str::to_owned));
    assert_eq!(
        locked, pinned,
        "Cargo.lock's psl is not the release VERSION pairs with the list"
    );
    let mut wrong = Vec::new();
    for (rule, icann) in rules() {
        let section = Some(if icann { Type::Icann } else { Type::Private });
        let (probe, expected) = if let Some(parent) = rule.strip_prefix("*.") {
            let probe = format!("{PROBE}.{parent}");
            (probe.clone(), Some((probe, section)))
        } else if let Some(exception) = rule.strip_prefix('!') {
            let parent = exception
                .split_once('.')
                .map(|(_, parent)| parent.to_owned());
            (exception.to_owned(), parent.map(|parent| (parent, section)))
        } else {
            (rule.clone(), Some((rule.clone(), section)))
        };
        let found = psl_suffix(&probe);
        if found != expected {
            wrong.push(format!("{rule}: psl gives {found:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "psl was not built from the list VERSION pins; upgrade psl to the release built from the same \
         list revision. {} rules differ, first: {:?}",
        wrong.len(),
        &wrong[..wrong.len().min(20)]
    );
}

/// The list as publicsuffix.org's algorithm reads it: the names of normal and exception rules,
/// the parents of wildcard rules, and every name a rule passes through.
struct Rules {
    normal: HashSet<String>,
    exception: HashSet<String>,
    wildcard: HashSet<String>,
    nodes: HashSet<String>,
}

impl Rules {
    fn new() -> Self {
        let mut rules = Self {
            normal: HashSet::new(),
            exception: HashSet::new(),
            wildcard: HashSet::new(),
            nodes: HashSet::new(),
        };
        for (rule, _) in self::rules() {
            let name = if let Some(parent) = rule.strip_prefix("*.") {
                rules.wildcard.insert(parent.to_owned());
                parent
            } else if let Some(name) = rule.strip_prefix('!') {
                rules.exception.insert(name.to_owned());
                name
            } else {
                rules.normal.insert(rule.clone());
                &rule
            };
            let labels: Vec<&str> = name.split('.').collect();
            for start in 0..labels.len() {
                rules.nodes.insert(labels[start..].join("."));
            }
        }
        rules
    }

    /// The prevailing rule is an exception if one matches, else the longest match, else `*`.
    fn registrable_domain(&self, host: &str) -> Option<String> {
        if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
            return None;
        }
        let host = host.to_ascii_lowercase();
        let labels: Vec<&str> = host.split('.').collect();
        let (mut suffix, mut exception) = (1, None);
        for len in 1..=labels.len() {
            let name = labels[labels.len() - len..].join(".");
            if self.exception.contains(&name) {
                exception = Some(len - 1);
            }
            if self.normal.contains(&name)
                || (len > 1
                    && self
                        .wildcard
                        .contains(&labels[labels.len() - len + 1..].join(".")))
            {
                suffix = len;
            }
        }
        let suffix = exception.unwrap_or(suffix);
        (suffix < labels.len()).then(|| labels[labels.len() - suffix - 1..].join("."))
    }

    /// Whether `host` ends in a name a wildcard rule covers that is in the rule tree without
    /// being a rule itself (`ex.futurecms.at`, under `*.futurecms.at` and `*.ex.futurecms.at`).
    /// psl drops the covering wildcard once it descends into such a name; Go's
    /// `EffectiveTLDPlusOne` and the table keep it.
    fn passes_a_covered_inner_name(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let labels: Vec<&str> = host.split('.').collect();
        (1..labels.len()).any(|start| {
            let name = labels[start - 1..].join(".");
            self.wildcard.contains(&labels[start..].join("."))
                && self.nodes.contains(&name)
                && !self.normal.contains(&name)
                && !self.exception.contains(&name)
        })
    }
}

#[test]
fn registrable_domains_follow_the_list_and_match_psl() {
    let rules = Rules::new();
    let probes = probes();
    let (mut wrong, mut covered) = (Vec::new(), 0);
    for probe in &probes {
        let (table, listed, psl) = (
            registrable_domain(probe),
            rules.registrable_domain(probe),
            psl_domain(probe),
        );
        if table != listed {
            wrong.push(format!("{probe}: table {table:?}, by the rules {listed:?}"));
        }
        if psl != listed {
            match rules.passes_a_covered_inner_name(probe) {
                true => covered += 1,
                false => wrong.push(format!("{probe}: psl {psl:?}, by the rules {listed:?}")),
            }
        }
    }
    assert!(covered > 0, "no probe reaches a name psl reads differently");
    assert!(
        wrong.is_empty(),
        "{} of {} probes differ, first: {:?}",
        wrong.len(),
        probes.len(),
        &wrong[..wrong.len().min(20)]
    );
}

const HOSTS: [&str; 20] = [
    "www.google.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "a.b.github.io",
    "www.bbc.co.uk",
    "s3.us-east-1.amazonaws.com",
    "x.app.vercel.app",
    "cdn.jsdelivr.net",
    "www.example.com.au",
    "static.xx.fbcdn.net",
    "i.ytimg.com",
    "www.baidu.com",
    "weibo.cn",
    "news.yahoo.co.jp",
    "edge-mqtt.facebook.com",
    "clients4.google.com",
    "www.gov.uk",
    "foo.unknowntld",
    "mail.qq.com",
    "update.microsoft.com",
];

fn time(hosts: &[&str], lookup: fn(&str) -> Option<String>) -> f64 {
    let rounds = (2_000_000 / hosts.len()).max(10);
    let started = Instant::now();
    for _ in 0..rounds {
        for host in hosts {
            black_box(lookup(black_box(host)));
        }
    }
    started.elapsed().as_nanos() as f64 / (rounds * hosts.len()) as f64
}

#[test]
#[ignore = "timing; run with --release --ignored --nocapture"]
fn lookup_time_against_psl() {
    let probes = probes();
    let derived: Vec<&str> = probes.iter().map(String::as_str).collect();
    for (corpus, hosts) in [("hosts", &HOSTS[..]), ("rules", &derived[..])] {
        let (psl, table) = (time(hosts, psl_domain), time(hosts, registrable_domain));
        println!(
            "{corpus}: {} lookups, psl {psl:.1} ns, table {table:.1} ns",
            hosts.len()
        );
    }
}
