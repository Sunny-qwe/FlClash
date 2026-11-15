use std::net::IpAddr;

use indexmap::IndexMap;
use percent_encoding::percent_decode_str;

use crate::Map;
use crate::error::{ConfigError, Result};
use crate::lenient::Fields;
use crate::net::IpCidr;
use crate::rule::{self, Cond, RuleDef};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rcode {
    Success,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

impl Rcode {
    fn parse(name: &str) -> Option<Rcode> {
        Some(match name {
            "success" => Rcode::Success,
            "format_error" => Rcode::FormatError,
            "server_failure" => Rcode::ServerFailure,
            "name_error" => Rcode::NameError,
            "not_implemented" => Rcode::NotImplemented,
            "refused" => Rcode::Refused,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamScheme {
    Udp,
    Tcp,
    Tls,
    Https,
    Http,
    Quic,
    System,
    Dhcp(String),
    Rcode(Rcode),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    pub scheme: UpstreamScheme,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub userinfo: String,
    pub proxy: Option<String>,
    pub params: IndexMap<String, String>,
    pub text: String,
}

impl Upstream {
    fn same_target(&self, other: &Upstream) -> bool {
        self.scheme == other.scheme
            && self.host == other.host
            && self.port == other.port
            && self.path == other.path
            && self.userinfo == other.userinfo
            && self.proxy == other.proxy
            && self.params == other.params
    }

    pub fn is_pure_ip(&self) -> bool {
        matches!(self.scheme, UpstreamScheme::System) || self.host.parse::<IpAddr>().is_ok()
    }
}

fn pure_server(server: &str) -> String {
    if server == "system" {
        return "system://".to_string();
    }
    match server.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => format!("udp://{server}"),
        Ok(IpAddr::V6(_)) => format!("udp://[{server}]"),
        Err(_) if server.contains("://") => server.to_string(),
        Err(_) => format!("udp://{server}"),
    }
}

fn split_host_port(hostport: &str, default_port: u16) -> Result<(String, u16)> {
    if hostport.is_empty() {
        return Ok((String::new(), default_port));
    }
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| ConfigError::new(format!("missing ']' in address {hostport}")))?;
        return match after.strip_prefix(':') {
            None if after.is_empty() => Ok((host.to_string(), default_port)),
            Some(port) => Ok((host.to_string(), parse_port(port)?)),
            None => Err(ConfigError::new(format!("invalid address {hostport}"))),
        };
    }
    match hostport.matches(':').count() {
        0 => Ok((hostport.to_string(), default_port)),
        1 => {
            let (host, port) = hostport.split_once(':').unwrap_or((hostport, ""));
            Ok((host.to_string(), parse_port(port)?))
        }
        _ => Err(ConfigError::new(format!(
            "address {hostport}: too many colons in address"
        ))),
    }
}

fn parse_port(text: &str) -> Result<u16> {
    text.parse::<u16>()
        .map_err(|_| ConfigError::new(format!("invalid port \":{text}\" after host")))
}

pub fn parse_upstream(server: &str) -> Result<Upstream> {
    let normalized = pure_server(server);
    let (scheme, rest) = normalized
        .split_once("://")
        .ok_or_else(|| ConfigError::new(format!("invalid DNS server {server}")))?;
    let scheme = scheme.to_ascii_lowercase();
    let (body, fragment) = match rest.split_once('#') {
        Some((body, fragment)) => (body, Some(fragment)),
        None => (rest, None),
    };
    let mut proxy = None;
    let mut params = IndexMap::new();
    if let Some(fragment) = fragment {
        let decoded = percent_decode_str(fragment)
            .decode_utf8_lossy()
            .into_owned();
        for part in decoded.split('&') {
            match part.split_once('=') {
                Some((key, value)) => {
                    params.insert(key.to_string(), value.to_string());
                }
                None => proxy = Some(part.to_string()),
            }
        }
    }
    let authority_end = body.find(['/', '?']).unwrap_or(body.len());
    let authority = body.get(..authority_end).unwrap_or_default();
    let path = body.get(authority_end..).unwrap_or_default().to_string();
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((user, host)) => (user.to_string(), host),
        None => (String::new(), authority),
    };
    let make = |scheme: UpstreamScheme, host: String, port: u16, path: String| Upstream {
        scheme,
        host,
        port,
        path,
        userinfo: userinfo.clone(),
        proxy: proxy.clone(),
        params: params.clone(),
        text: server.to_string(),
    };
    let upstream = match scheme.as_str() {
        "udp" => {
            let (host, port) = split_host_port(hostport, 53)?;
            make(UpstreamScheme::Udp, host, port, String::new())
        }
        "tcp" => {
            let (host, port) = split_host_port(hostport, 53)?;
            make(UpstreamScheme::Tcp, host, port, String::new())
        }
        "tls" => {
            let (host, port) = split_host_port(hostport, 853)?;
            make(UpstreamScheme::Tls, host, port, String::new())
        }
        "quic" => {
            let (host, port) = split_host_port(hostport, 853)?;
            make(UpstreamScheme::Quic, host, port, String::new())
        }
        "https" => {
            let (host, port) = split_host_port(hostport, 443)?;
            make(UpstreamScheme::Https, host, port, path)
        }
        "http" => {
            let (host, port) = split_host_port(hostport, 80)?;
            make(UpstreamScheme::Http, host, port, path)
        }
        "system" => make(UpstreamScheme::System, String::new(), 0, String::new()),
        "dhcp" => {
            let iface = body.to_string();
            if iface == "system" {
                make(UpstreamScheme::System, String::new(), 0, String::new())
            } else {
                make(UpstreamScheme::Dhcp(iface), String::new(), 0, String::new())
            }
        }
        "rcode" => {
            let name = authority.to_string();
            let code = Rcode::parse(&name)
                .ok_or_else(|| ConfigError::new(format!("unsupported RCode type: {name}")))?;
            make(UpstreamScheme::Rcode(code), name, 0, String::new())
        }
        "ts" | "tailscale" | "et" | "easytier" => {
            return Err(ConfigError::new(format!(
                "unsupported DNS scheme {scheme}://, tailscale and easytier are not supported by this core"
            )));
        }
        other => {
            return Err(ConfigError::new(format!("unsupport scheme: {other}")));
        }
    };
    Ok(upstream)
}

pub fn parse_upstreams(servers: &[String], what: &str) -> Result<Vec<Upstream>> {
    let mut out: Vec<Upstream> = Vec::with_capacity(servers.len());
    for (index, server) in servers.iter().enumerate() {
        let upstream = parse_upstream(server)
            .map_err(|err| {
                ConfigError::new(format!(
                    "DNS NameServer[{index}] format error: {}",
                    err.message
                ))
            })
            .map_err(|err| err.prefixed(&format!("{what}: ")))?;
        if !out.iter().any(|existing| existing.same_target(&upstream)) {
            out.push(upstream);
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyKey {
    Domain(String),
    GeoSite(String),
    RuleSet(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEntry {
    pub key: PolicyKey,
    pub servers: Vec<Upstream>,
}

fn policy_keys(key: &str) -> Vec<PolicyKey> {
    let lower = key.to_lowercase();
    let prefixed = |prefix: &str, make: fn(String) -> PolicyKey| -> Option<Vec<PolicyKey>> {
        if !lower.starts_with(prefix) {
            return None;
        }
        let body = key.get(prefix.len()..).unwrap_or_default();
        Some(if body.contains(',') {
            body.split(',').map(|part| make(part.to_string())).collect()
        } else {
            vec![make(body.to_string())]
        })
    };
    if let Some(keys) = prefixed("geosite:", PolicyKey::GeoSite) {
        return keys;
    }
    if let Some(keys) = prefixed("rule-set:", PolicyKey::RuleSet) {
        return keys;
    }
    if key.contains(',') {
        return key
            .split(',')
            .map(|part| PolicyKey::Domain(part.to_string()))
            .collect();
    }
    vec![PolicyKey::Domain(key.to_string())]
}

pub fn parse_policy(map: Option<&Map>, what: &str) -> Result<Vec<PolicyEntry>> {
    let Some(map) = map else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (key, value) in map {
        let servers = crate::lenient::value_to_strings(value);
        let upstreams = parse_upstreams(&servers, what)?;
        for policy_key in policy_keys(key) {
            out.push(PolicyEntry {
                key: policy_key,
                servers: upstreams.clone(),
            });
        }
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnhancedMode {
    Normal,
    FakeIp,
    #[default]
    RedirHost,
}

impl EnhancedMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EnhancedMode::Normal => "normal",
            EnhancedMode::FakeIp => "fake-ip",
            EnhancedMode::RedirHost => "redir-host",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FakeIpFilterMode {
    #[default]
    Blacklist,
    Whitelist,
    Rule,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FallbackFilter {
    pub geoip: bool,
    pub geoip_code: String,
    pub geosite: Vec<String>,
    pub ipcidr: Vec<IpCidr>,
    pub domain: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsConfig {
    pub enable: bool,
    pub enhanced_mode: EnhancedMode,
    pub nameserver: Vec<Upstream>,
    pub default_nameserver: Vec<Upstream>,
    pub nameserver_policy: Vec<PolicyEntry>,
    pub proxy_server_nameserver: Vec<Upstream>,
    pub direct_nameserver: Vec<Upstream>,
    pub direct_nameserver_follow_policy: bool,
    pub use_hosts: bool,
    pub use_system_hosts: bool,
    pub respect_rules: bool,
    pub ipv6: bool,
    pub fake_ip_range: Option<IpCidr>,
    pub fake_ip_filter: Vec<String>,
    pub fake_ip_filter_rules: Vec<RuleDef>,
    pub fake_ip_filter_mode: FakeIpFilterMode,
    pub fake_ip_ttl: u32,
    pub fallback: Vec<Upstream>,
    pub fallback_lazy_query: bool,
    pub fallback_filter: FallbackFilter,
    pub ipv6_timeout: u32,
    pub prefer_h3: bool,
    pub cache_algorithm: String,
    pub cache_max_size: i32,
    pub fake_ip_range6: Option<IpCidr>,
    pub proxy_server_nameserver_policy: Vec<PolicyEntry>,
    pub listen: String,
    pub listen_routing_mark: u32,
}

fn parse_enhanced(text: &str) -> Result<EnhancedMode> {
    match text.to_ascii_lowercase().as_str() {
        "normal" => Ok(EnhancedMode::Normal),
        "fake-ip" => Ok(EnhancedMode::FakeIp),
        "redir-host" | "" => Ok(EnhancedMode::RedirHost),
        _ => Err(ConfigError::new("invalid mode")),
    }
}

fn parse_filter_mode(text: &str) -> Result<FakeIpFilterMode> {
    match text.to_ascii_lowercase().as_str() {
        "blacklist" | "" => Ok(FakeIpFilterMode::Blacklist),
        "whitelist" => Ok(FakeIpFilterMode::Whitelist),
        "rule" => Ok(FakeIpFilterMode::Rule),
        _ => Err(ConfigError::new("invalid mode")),
    }
}

fn domain_rule(cond: &Cond) -> bool {
    matches!(
        cond,
        Cond::Domain(_)
            | Cond::DomainSuffix(_)
            | Cond::DomainKeyword(_)
            | Cond::DomainRegex(_)
            | Cond::DomainWildcard(_)
            | Cond::GeoSite(_)
            | Cond::RuleSet(_)
            | Cond::Match
    )
}

fn fake_ip_rules(lines: &[String]) -> Result<Vec<RuleDef>> {
    let mut out = Vec::with_capacity(lines.len());
    for (index, line) in lines.iter().enumerate() {
        let rule = rule::parse_rule(line).map_err(|err| {
            ConfigError::new(format!(
                "dns.fake-ip-filter[{index}] [{line}] error: {}",
                err.message
            ))
        })?;
        let action = rule.target.to_lowercase();
        if action != "fake-ip" && action != "real-ip" {
            return Err(ConfigError::new(format!(
                "dns.fake-ip-filter[{index}] [{line}] error: invalid action '{action}', must be 'fake-ip' or 'real-ip'"
            )));
        }
        if !domain_rule(&rule.cond) {
            return Err(ConfigError::new(format!(
                "dns.fake-ip-filter[{index}] [{line}] error: rule type '{}' not supported, only domain-based rules allowed",
                rule.cond.type_name()
            )));
        }
        out.push(rule);
    }
    Ok(out)
}

fn cidr_entry(text: &str) -> Result<IpCidr> {
    if let Some(cidr) = IpCidr::parse(text.trim()) {
        return Ok(cidr);
    }
    let ip: IpAddr = text
        .trim()
        .parse()
        .map_err(|_| ConfigError::new(format!("netip.ParsePrefix(\"{text}\"): invalid prefix")))?;
    Ok(IpCidr {
        addr: ip,
        prefix: if ip.is_ipv4() { 32 } else { 128 },
    })
}

impl DnsConfig {
    /// Every `dhcp://<interface>` upstream, by the key it was written under. The core runs it as
    /// `system://`, so the interface is not bound.
    pub fn dhcp_interfaces<'a>(&'a self) -> Vec<(&'static str, &'a str)> {
        let lists: [(&'static str, &'a [Upstream]); 5] = [
            ("dns.nameserver", &self.nameserver),
            ("dns.default-nameserver", &self.default_nameserver),
            ("dns.proxy-server-nameserver", &self.proxy_server_nameserver),
            ("dns.direct-nameserver", &self.direct_nameserver),
            ("dns.fallback", &self.fallback),
        ];
        let policies: [(&'static str, &'a [PolicyEntry]); 2] = [
            ("dns.nameserver-policy", &self.nameserver_policy),
            (
                "dns.proxy-server-nameserver-policy",
                &self.proxy_server_nameserver_policy,
            ),
        ];
        let mut found = Vec::new();
        let mut note = |key: &'static str, upstream: &'a Upstream| {
            if let UpstreamScheme::Dhcp(iface) = &upstream.scheme
                && !found.contains(&(key, iface.as_str()))
            {
                found.push((key, iface.as_str()));
            }
        };
        for (key, list) in lists {
            list.iter().for_each(|upstream| note(key, upstream));
        }
        for (key, entries) in policies {
            entries
                .iter()
                .flat_map(|entry| &entry.servers)
                .for_each(|upstream| note(key, upstream));
        }
        found
    }

    pub fn from_map(map: &Map) -> Result<DnsConfig> {
        let mut f = Fields::new(map, "dns", false);
        let enable = f.boolean("enable")?;
        let respect_rules = f.boolean("respect-rules")?;
        let nameserver_text = f.strings("nameserver")?;
        let proxy_server_text = f.strings("proxy-server-nameserver")?;
        if enable && nameserver_text.is_empty() {
            return Err(ConfigError::new(
                "if DNS configuration is turned on, NameServer cannot be empty",
            ));
        }
        if respect_rules && proxy_server_text.is_empty() {
            return Err(ConfigError::new(
                "if “respect-rules” is turned on, “proxy-server-nameserver” cannot be empty",
            ));
        }
        let mut dns = DnsConfig {
            enable,
            respect_rules,
            enhanced_mode: parse_enhanced(&f.string("enhanced-mode")?)?,
            use_hosts: f.boolean("use-hosts")?,
            use_system_hosts: f.boolean("use-system-hosts")?,
            ipv6: f.boolean("ipv6")?,
            prefer_h3: f.boolean("prefer-h3")?,
            ipv6_timeout: f.u32("ipv6-timeout")?,
            fake_ip_ttl: f.u32("fake-ip-ttl")?,
            fake_ip_filter_mode: parse_filter_mode(&f.string("fake-ip-filter-mode")?)?,
            fallback_lazy_query: f.boolean("fallback-lazy-query")?,
            direct_nameserver_follow_policy: f.boolean("direct-nameserver-follow-policy")?,
            cache_algorithm: f.string("cache-algorithm")?,
            cache_max_size: f.i32("cache-max-size")?,
            listen: f.string("listen")?,
            listen_routing_mark: f.u32("listen-routing-mark")?,
            ..DnsConfig::default()
        };
        dns.nameserver = parse_upstreams(&nameserver_text, "dns.nameserver")?;
        dns.fallback = parse_upstreams(&f.strings("fallback")?, "dns.fallback")?;
        dns.nameserver_policy =
            parse_policy(f.object("nameserver-policy")?, "dns.nameserver-policy")?;
        dns.proxy_server_nameserver =
            parse_upstreams(&proxy_server_text, "dns.proxy-server-nameserver")?;
        dns.proxy_server_nameserver_policy = parse_policy(
            f.object("proxy-server-nameserver-policy")?,
            "dns.proxy-server-nameserver-policy",
        )?;
        if !dns.proxy_server_nameserver_policy.is_empty() && dns.proxy_server_nameserver.is_empty()
        {
            return Err(ConfigError::new(
                "disallow empty `proxy-server-nameserver` when `proxy-server-nameserver-policy` is set",
            ));
        }
        dns.direct_nameserver =
            parse_upstreams(&f.strings("direct-nameserver")?, "dns.direct-nameserver")?;
        let defaults = f.strings("default-nameserver")?;
        if defaults.is_empty() {
            return Err(ConfigError::new(
                "default nameserver should have at least one nameserver",
            ));
        }
        dns.default_nameserver = parse_upstreams(&defaults, "dns.default-nameserver")?;
        if dns.default_nameserver.iter().any(|ns| !ns.is_pure_ip()) {
            return Err(ConfigError::new("default nameserver should be pure IP"));
        }
        let range = f.string("fake-ip-range")?;
        if !range.is_empty() {
            let cidr = crate::net::parse_cidr(&range)?;
            if !cidr.is_ipv4() {
                return Err(ConfigError::new("dns.fake-ip-range must be a IPv4 prefix"));
            }
            dns.fake_ip_range = Some(cidr);
        }
        let range6 = f.string("fake-ip-range6")?;
        if !range6.is_empty() {
            let cidr = crate::net::parse_cidr(&range6)?;
            if cidr.is_ipv4() {
                return Err(ConfigError::new("dns.fake-ip-range6 must be a IPv6 prefix"));
            }
            dns.fake_ip_range6 = Some(cidr);
        }
        dns.fake_ip_filter = f.strings("fake-ip-filter")?;
        if dns.enhanced_mode == EnhancedMode::FakeIp {
            if dns.fake_ip_filter_mode == FakeIpFilterMode::Rule {
                dns.fake_ip_filter_rules = fake_ip_rules(&dns.fake_ip_filter)?;
            }
            if dns.fake_ip_range.is_none() && dns.fake_ip_range6.is_none() {
                return Err(ConfigError::new(
                    "disallow `fake-ip-range` and `fake-ip-range6` both empty with fake-ip mode",
                ));
            }
        }
        if let Some(mut filter) = f.sub("fallback-filter")? {
            dns.fallback_filter.geoip = filter.boolean("geoip")?;
            dns.fallback_filter.geoip_code = filter.string("geoip-code")?;
            dns.fallback_filter.geosite = filter.strings("geosite")?;
            dns.fallback_filter.domain = filter.strings("domain")?;
            for (index, text) in filter.strings("ipcidr")?.iter().enumerate() {
                dns.fallback_filter
                    .ipcidr
                    .push(cidr_entry(text).map_err(|err| {
                        ConfigError::new(format!(
                            "DNS FallbackIP[{index}] format error: {}",
                            err.message
                        ))
                    })?);
            }
        }
        Ok(dns)
    }

    pub fn upstream_proxy_names(&self) -> impl Iterator<Item = &str> {
        let direct = [
            &self.nameserver,
            &self.fallback,
            &self.default_nameserver,
            &self.proxy_server_nameserver,
            &self.direct_nameserver,
        ];
        let lists = direct.into_iter().flatten();
        let policies = self
            .nameserver_policy
            .iter()
            .chain(&self.proxy_server_nameserver_policy)
            .flat_map(|entry| entry.servers.iter());
        lists.chain(policies).filter_map(|up| up.proxy.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::dns_defaults;
    use serde_json::json;

    fn dns_with(patch: serde_json::Value) -> Result<DnsConfig> {
        let mut map = dns_defaults();
        if let serde_json::Value::Object(patch) = patch {
            for (key, value) in patch {
                map.insert(key, value);
            }
        }
        DnsConfig::from_map(&map)
    }

    #[test]
    fn defaults_parse() {
        let dns = DnsConfig::from_map(&dns_defaults()).unwrap();
        assert!(!dns.enable);
        assert_eq!(dns.nameserver.len(), 2);
        assert_eq!(dns.nameserver[0].scheme, UpstreamScheme::Https);
        assert_eq!(dns.nameserver[0].host, "doh.pub");
        assert_eq!(dns.nameserver[0].port, 443);
        assert_eq!(dns.nameserver[0].path, "/dns-query");
        assert_eq!(dns.nameserver[1].scheme, UpstreamScheme::Tls);
        assert_eq!(dns.nameserver[1].port, 853);
        assert_eq!(dns.default_nameserver.len(), 4);
        assert_eq!(dns.fake_ip_range, IpCidr::parse("198.18.0.1/16"));
    }

    #[test]
    fn upstream_forms() {
        let up = parse_upstream("8.8.8.8").unwrap();
        assert_eq!(
            (up.scheme.clone(), up.host.as_str(), up.port),
            (UpstreamScheme::Udp, "8.8.8.8", 53)
        );
        let up = parse_upstream("2001:4860:4860::8888").unwrap();
        assert_eq!((up.host.as_str(), up.port), ("2001:4860:4860::8888", 53));
        let up = parse_upstream("tcp://1.1.1.1:5353").unwrap();
        assert_eq!((up.scheme.clone(), up.port), (UpstreamScheme::Tcp, 5353));
        let up = parse_upstream("system://").unwrap();
        assert_eq!(up.scheme, UpstreamScheme::System);
        assert_eq!(
            parse_upstream("system").unwrap().scheme,
            UpstreamScheme::System
        );
        assert_eq!(
            parse_upstream("dhcp://system").unwrap().scheme,
            UpstreamScheme::System
        );
        let up = parse_upstream("dhcp://en0").unwrap();
        assert_eq!(up.scheme, UpstreamScheme::Dhcp("en0".into()));
        let up = parse_upstream("rcode://refused").unwrap();
        assert_eq!(up.scheme, UpstreamScheme::Rcode(Rcode::Refused));
        let up = parse_upstream("quic://dns.adguard.com").unwrap();
        assert_eq!((up.scheme.clone(), up.port), (UpstreamScheme::Quic, 853));
        let up = parse_upstream("http://dns.example/q").unwrap();
        assert_eq!((up.scheme.clone(), up.port), (UpstreamScheme::Http, 80));
    }

    #[test]
    fn fragments_carry_a_proxy_and_params() {
        let up = parse_upstream("https://dns.google/dns-query#My%20Proxy&h3=true&ecs=1.2.3.0/24")
            .unwrap();
        assert_eq!(up.proxy.as_deref(), Some("My Proxy"));
        assert_eq!(up.params.get("h3").map(String::as_str), Some("true"));
        assert_eq!(up.params.get("ecs").map(String::as_str), Some("1.2.3.0/24"));
        let up = parse_upstream("1.1.1.1#proxy").unwrap();
        assert_eq!(up.proxy.as_deref(), Some("proxy"));
        let up = parse_upstream("tls://[2606:4700::1111]:853").unwrap();
        assert_eq!((up.host.as_str(), up.port), ("2606:4700::1111", 853));
    }

    #[test]
    fn unsupported_forms_are_errors() {
        for bad in [
            "ts://node",
            "tailscale://node",
            "et://node",
            "easytier://node",
            "ftp://x",
            "rcode://nope",
            "tcp://a:b:c:d",
        ] {
            assert!(parse_upstream(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nameserver_policy_keeps_document_order_and_splits_lists() {
        let dns = dns_with(json!({
            "nameserver-policy": {
                "geosite:cn,private": "223.5.5.5",
                "rule-set:ads": ["https://a/dns-query#proxy"],
                "+.lan": "system://",
                "a.com,b.com": ["1.1.1.1", "1.1.1.1"]
            }
        }))
        .unwrap();
        let keys: Vec<&PolicyKey> = dns.nameserver_policy.iter().map(|p| &p.key).collect();
        assert_eq!(
            keys,
            [
                &PolicyKey::GeoSite("cn".into()),
                &PolicyKey::GeoSite("private".into()),
                &PolicyKey::RuleSet("ads".into()),
                &PolicyKey::Domain("+.lan".into()),
                &PolicyKey::Domain("a.com".into()),
                &PolicyKey::Domain("b.com".into()),
            ]
        );
        assert_eq!(dns.nameserver_policy[5].servers.len(), 1);
        assert_eq!(dns.upstream_proxy_names().collect::<Vec<_>>(), ["proxy"]);
    }

    #[test]
    fn invalid_dns_is_rejected() {
        assert!(dns_with(json!({"enable": true, "nameserver": []})).is_err());
        assert!(dns_with(json!({"respect-rules": true})).is_err());
        assert!(dns_with(json!({"default-nameserver": ["dns.google"]})).is_err());
        assert!(dns_with(json!({"default-nameserver": []})).is_err());
        assert!(dns_with(json!({"fake-ip-range": "fc00::/64"})).is_err());
        assert!(dns_with(json!({"enhanced-mode": "fake-ip", "fake-ip-range": ""})).is_err());
        assert!(dns_with(json!({"enhanced-mode": "mapping"})).is_err());
        assert!(dns_with(json!({"nameserver": ["ts://node"]})).is_err());
        assert!(dns_with(json!({"proxy-server-nameserver-policy": {"a.com": "1.1.1.1"}})).is_err());
    }

    #[test]
    fn fake_ip_rule_mode_validates_actions() {
        let ok = dns_with(json!({
            "enhanced-mode": "fake-ip",
            "fake-ip-filter-mode": "rule",
            "fake-ip-filter": ["DOMAIN-SUFFIX,lan,real-ip", "MATCH,fake-ip"]
        }))
        .unwrap();
        assert_eq!(ok.fake_ip_filter_rules.len(), 2);
        let bad = dns_with(json!({
            "enhanced-mode": "fake-ip",
            "fake-ip-filter-mode": "rule",
            "fake-ip-filter": ["IP-CIDR,10.0.0.0/8,real-ip"]
        }));
        assert!(
            bad.unwrap_err()
                .message
                .contains("only domain-based rules allowed")
        );
    }
}
