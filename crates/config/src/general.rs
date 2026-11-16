use concord_common::{FindProcessMode, LogLevel, TunnelMode};

use crate::Map;
use crate::error::{ConfigError, Result};
use crate::keys::DEFAULT_GLOBAL_UA;
use crate::lenient::Fields;
use crate::net::IpCidr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GeodataLoader {
    Standard,
    #[default]
    MemConservative,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct General {
    pub port: u16,
    pub socks_port: u16,
    pub mixed_port: u16,
    pub redir_port: u16,
    pub tproxy_port: u16,
    pub allow_lan: bool,
    pub authentication: Vec<Credential>,
    pub skip_auth_prefixes: Vec<IpCidr>,
    pub mode: TunnelMode,
    pub log_level: LogLevel,
    pub ipv6: bool,
    pub tcp_concurrent: bool,
    pub unified_delay: bool,
    pub find_process_mode: FindProcessMode,
    pub interface_name: String,
    pub routing_mark: u32,
    pub keep_alive_idle: u32,
    pub keep_alive_interval: u32,
    pub disable_keep_alive: bool,
    pub global_ua: String,
    pub geo_auto_update: bool,
    pub geo_update_interval: u32,
    pub geodata_loader: GeodataLoader,
    pub external_controller: String,
    pub secret: String,
}

impl Default for General {
    fn default() -> Self {
        General {
            port: 0,
            socks_port: 0,
            mixed_port: 0,
            redir_port: 0,
            tproxy_port: 0,
            allow_lan: false,
            authentication: Vec::new(),
            skip_auth_prefixes: Vec::new(),
            mode: TunnelMode::Rule,
            log_level: LogLevel::Info,
            ipv6: true,
            tcp_concurrent: false,
            unified_delay: false,
            find_process_mode: FindProcessMode::Strict,
            interface_name: String::new(),
            routing_mark: 0,
            keep_alive_idle: 0,
            keep_alive_interval: 0,
            disable_keep_alive: false,
            global_ua: DEFAULT_GLOBAL_UA.to_string(),
            geo_auto_update: false,
            geo_update_interval: 24,
            geodata_loader: GeodataLoader::MemConservative,
            external_controller: String::new(),
            secret: String::new(),
        }
    }
}

fn choice<T>(text: String, parse: impl Fn(&str) -> Option<T>, what: &str) -> Result<T> {
    parse(&text).ok_or_else(|| ConfigError::new(format!("invalid {what}")))
}

impl General {
    pub fn from_map(map: &Map) -> Result<General> {
        let mut f = Fields::new(map, "", false);
        let mut general = General {
            port: f.u16("port")?,
            socks_port: f.u16("socks-port")?,
            mixed_port: f.u16("mixed-port")?,
            redir_port: f.u16("redir-port")?,
            tproxy_port: f.u16("tproxy-port")?,
            allow_lan: f.boolean("allow-lan")?,
            ..General::default()
        };
        for line in f.strings("authentication")? {
            if let Some((user, pass)) = line.split_once(':') {
                general.authentication.push(Credential {
                    user: user.to_string(),
                    pass: pass.to_string(),
                });
            }
        }
        for text in f.strings("skip-auth-prefixes")? {
            let prefix = IpCidr::parse(text.trim()).ok_or_else(|| {
                ConfigError::new(format!("invalid skip-auth-prefixes entry: {text}"))
            })?;
            general.skip_auth_prefixes.push(prefix);
        }
        if let Some(mode) = f.opt_string("mode")? {
            general.mode = choice(mode, TunnelMode::parse, "mode")?;
        }
        if let Some(level) = f.opt_string("log-level")? {
            general.log_level = choice(level, LogLevel::parse, "log level")?;
        }
        if let Some(mode) = f.opt_string("find-process-mode")? {
            general.find_process_mode = choice(mode, FindProcessMode::parse, "find process mode")?;
        }
        general.ipv6 = f.opt_bool("ipv6")?.unwrap_or(true);
        general.tcp_concurrent = f.boolean("tcp-concurrent")?;
        general.unified_delay = f.boolean("unified-delay")?;
        general.interface_name = f.string("interface-name")?;
        general.routing_mark = f.mark("routing-mark")?;
        general.keep_alive_idle = f.u32("keep-alive-idle")?;
        general.keep_alive_interval = f.u32("keep-alive-interval")?;
        general.disable_keep_alive = f.boolean("disable-keep-alive")?;
        if let Some(ua) = f.opt_string("global-ua")? {
            general.global_ua = ua;
        }
        general.geo_auto_update = f.boolean("geo-auto-update")?;
        if f.has("geo-update-interval") {
            general.geo_update_interval = f.u32("geo-update-interval")?;
        }
        general.geodata_loader = match f.string("geodata-loader")?.to_ascii_lowercase().as_str() {
            "standard" => GeodataLoader::Standard,
            _ => GeodataLoader::MemConservative,
        };
        general.external_controller = f.string("external-controller")?;
        general.secret = f.string("secret")?;
        f.finish()?;
        Ok(general)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::general_defaults;
    use serde_json::json;

    #[test]
    fn defaults_round_trip_through_the_typed_form() {
        assert_eq!(
            General::from_map(&general_defaults()).unwrap(),
            General::default()
        );
    }

    #[test]
    fn scalars_are_read_weakly() {
        let mut map = general_defaults();
        map.insert("mixed-port".into(), json!("7890"));
        map.insert("allow-lan".into(), json!("true"));
        map.insert("mode".into(), json!("Global"));
        map.insert("authentication".into(), json!(["a:b:c", "nocolon"]));
        let general = General::from_map(&map).unwrap();
        assert_eq!(general.mixed_port, 7890);
        assert!(general.allow_lan);
        assert_eq!(general.mode, TunnelMode::Global);
        assert_eq!(
            general.authentication,
            vec![Credential {
                user: "a".into(),
                pass: "b:c".into()
            }]
        );
    }

    #[test]
    fn skip_auth_prefixes_must_be_prefixes_as_in_mihomo() {
        let mut map = Map::new();
        map.insert(
            "skip-auth-prefixes".into(),
            json!(["127.0.0.1/8", "::1/128"]),
        );
        let general = General::from_map(&map).unwrap();
        assert_eq!(general.skip_auth_prefixes.len(), 2);
        map.insert("skip-auth-prefixes".into(), json!(["127.0.0.1"]));
        assert!(General::from_map(&map).is_err());
    }
}
