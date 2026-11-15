use crate::Map;
use crate::error::Result;
use crate::lenient::Fields;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtpConfig {
    pub enable: bool,
    pub server: String,
    pub port: u16,
    pub interval: u32,
    pub dialer_proxy: String,
    pub write_to_system: bool,
}

impl NtpConfig {
    pub fn from_map(map: &Map) -> Result<NtpConfig> {
        let mut f = Fields::new(map, "ntp", false);
        Ok(NtpConfig {
            enable: f.boolean("enable")?,
            server: f.string("server")?,
            port: f.u16("port")?,
            interval: f.u32("interval")?,
            dialer_proxy: f.string("dialer-proxy")?,
            write_to_system: f.boolean("write-to-system")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ntp_defaults;

    #[test]
    fn defaults() {
        let ntp = NtpConfig::from_map(&ntp_defaults()).unwrap();
        assert_eq!(
            (ntp.server.as_str(), ntp.port, ntp.interval),
            ("time.apple.com", 123, 30)
        );
        assert!(!ntp.enable && !ntp.write_to_system);
    }
}
