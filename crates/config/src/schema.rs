use serde_json::{Value, json};

use crate::keys;
use crate::proxy::{T0_PROXY_TYPES, T1_PROXY_TYPES, T2_PROXY_TYPES};
use crate::rule::{T0_RULE_TYPES, T1_RULE_TYPES};

fn tiers(t0: &[&str], t1: &[&str], t2: &[&str]) -> Value {
    json!({"t0": t0, "t1": t1, "t2": t2})
}

pub fn config_schema() -> Value {
    json!({
        "version": 1,
        "keys": tiers(keys::TOP_T0, keys::TOP_T1, keys::TOP_T2),
        "dns": tiers(keys::DNS_T0, keys::DNS_T1, &[]),
        "dns.fallback-filter": tiers(keys::FALLBACK_FILTER, &[], &[]),
        "tun": tiers(keys::TUN_T0, keys::TUN_T1, keys::TUN_T2),
        "sniffer": tiers(keys::SNIFFER_T0, keys::SNIFFER_T1, keys::SNIFFER_T2),
        "ntp": tiers(keys::NTP_KEYS, &[], &[]),
        "geox-url": tiers(keys::GEOX_KEYS, &[], keys::GEOX_T2),
        "profile": tiers(keys::PROFILE_KEYS, &[], &[]),
        "rule-types": tiers(T0_RULE_TYPES, T1_RULE_TYPES, &[]),
        "proxy-types": tiers(T0_PROXY_TYPES, T1_PROXY_TYPES, T2_PROXY_TYPES),
        "group-types": ["select", "url-test", "fallback", "load-balance"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_lists_every_tier() {
        let schema = config_schema();
        assert_eq!(
            schema["keys"]["t0"].as_array().map(Vec::len),
            Some(keys::TOP_T0.len())
        );
        assert_eq!(
            keys::TOP_T0.len() + keys::TOP_T1.len() + keys::TOP_T2.len(),
            66,
            "the 66 top-level profile keys"
        );
        assert_eq!(
            schema["rule-types"]["t0"].as_array().map(Vec::len),
            Some(30)
        );
        assert!(
            schema["proxy-types"]["t2"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "tailscale"))
        );
    }
}
