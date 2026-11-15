use serde_json::Value;

use crate::Map;

/// The `tls` keys the core reads; the inbound server settings there are only warned about.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsConfig {
    pub custom_certificates: Vec<String>,
}

impl TlsConfig {
    /// mihomo reads the misspelt `custom-certifactes`; the correct spelling is taken too.
    pub fn from_map(map: &Map) -> TlsConfig {
        let custom_certificates = ["custom-certifactes", "custom-certificates"]
            .into_iter()
            .filter_map(|key| map.get(key))
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        TlsConfig {
            custom_certificates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificates(text: &str) -> Vec<String> {
        match serde_json::from_str(text) {
            Ok(Value::Object(map)) => TlsConfig::from_map(&map).custom_certificates,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn both_spellings_of_custom_certificates_are_read() {
        assert_eq!(certificates(r#"{"custom-certifactes": ["a"]}"#), ["a"]);
        assert_eq!(certificates(r#"{"custom-certificates": ["b"]}"#), ["b"]);
        assert_eq!(
            certificates(r#"{"custom-certifactes": ["a"], "custom-certificates": ["b"]}"#),
            ["a", "b"]
        );
        assert!(certificates(r#"{"custom-certifactes": null}"#).is_empty());
    }
}
