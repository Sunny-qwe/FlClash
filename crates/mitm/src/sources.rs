//! Surge's `client-source-address`: the clients whose connections are decrypted.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

#[derive(Debug, thiserror::Error)]
#[error("invalid address or CIDR {0:?}")]
pub(crate) struct InvalidSource(String);

/// Every client while it names none, as Surge leaves MITM on for all clients without the key;
/// an entry with `-` leaves its clients out whatever else names them.
#[derive(Debug, Default)]
pub(crate) struct SourceList {
    include: Vec<IpNetwork>,
    exclude: Vec<IpNetwork>,
}

impl SourceList {
    /// Reads a line of comma-separated addresses and CIDRs, as Surge writes the key.
    pub(crate) fn add_line(&mut self, line: &str) -> Result<(), InvalidSource> {
        for entry in line
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (list, text) = match entry.strip_prefix('-') {
                Some(text) => (&mut self.exclude, text.trim()),
                None => (&mut self.include, entry),
            };
            list.push(text.parse().map_err(|_| InvalidSource(entry.to_string()))?);
        }
        Ok(())
    }

    pub(crate) fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        !self.exclude.iter().any(|net| net.contains(ip))
            && (self.include.is_empty() || self.include.iter().any(|net| net.contains(ip)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(lines: &[&str]) -> SourceList {
        let mut list = SourceList::default();
        for line in lines {
            list.add_line(line).unwrap();
        }
        list
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn follows_surge_semantics() {
        assert!(list(&[]).allows(ip("10.0.0.1")));
        let surge = list(&["-192.168.1.2, 0.0.0.0/0"]);
        assert!(surge.allows(ip("192.168.1.3")));
        assert!(!surge.allows(ip("192.168.1.2")));
        assert!(!surge.allows(ip("::ffff:192.168.1.2")));
        assert!(!surge.allows(ip("2001:db8::1")), "only IPv4 is named");
        let skipped = list(&["-192.168.4.50", "-192.168.4.51"]);
        assert!(skipped.allows(ip("192.168.4.52")));
        assert!(!skipped.allows(ip("192.168.4.51")));
        let mut bad = SourceList::default();
        assert!(bad.add_line("192.168.1.0/24, lan").is_err());
    }
}
