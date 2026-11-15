pub(crate) use concord_common::sync::lock;
use std::io;

use crate::ctx::BuildError;

pub(crate) fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

/// Bytes per second from `100`, `100 Mbps` or `10 MBps`: a bare number is Mbps,
/// a lower-case `b` is bits and an upper-case one bytes.
pub(crate) fn parse_bps(text: &str) -> u64 {
    let text = text.trim();
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    let Ok(value) = number.parse::<u64>() else {
        return 0;
    };
    let unit = unit.trim();
    if unit.is_empty() {
        return value.saturating_mul(1_000_000) / 8;
    }
    let Some(unit) = unit.strip_suffix("ps") else {
        return 0;
    };
    let (scale, bytes) = match unit.as_bytes() {
        [b'B'] => (1, true),
        [b'b'] => (1, false),
        [prefix, kind @ (b'B' | b'b')] => {
            let scale = match prefix {
                b'K' => 1_000,
                b'M' => 1_000_000,
                b'G' => 1_000_000_000,
                b'T' => 1_000_000_000_000,
                _ => return 0,
            };
            (scale, *kind == b'B')
        }
        _ => return 0,
    };
    let total = value.saturating_mul(scale);
    if bytes { total } else { total / 8 }
}

pub(crate) fn parse_ports(text: &str) -> Result<Vec<u16>, BuildError> {
    let mut ports = Vec::new();
    for part in text
        .split([',', '/'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        let (low, high) = match part.split_once('-') {
            Some((low, high)) => (low.trim(), high.trim()),
            None => (part, part),
        };
        let parse = |text: &str| {
            text.parse::<u16>()
                .map_err(|_| BuildError::invalid(format!("invalid port range: {part}")))
        };
        let (low, high) = (parse(low)?, parse(high)?);
        let (low, high) = if low <= high {
            (low, high)
        } else {
            (high, low)
        };
        ports.extend(low..=high);
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_accept_lists_and_ranges() {
        assert_eq!(parse_ports("443").unwrap(), [443]);
        assert_eq!(
            parse_ports("1000-1002,2000/3000").unwrap(),
            [1000, 1001, 1002, 2000, 3000]
        );
        assert!(parse_ports("").unwrap().is_empty());
        assert!(parse_ports("70000").is_err());
    }

    #[test]
    fn rates_follow_mihomo() {
        assert_eq!(parse_bps("100"), 12_500_000);
        assert_eq!(parse_bps("100 Mbps"), 12_500_000);
        assert_eq!(parse_bps("1 Gbps"), 125_000_000);
        assert_eq!(parse_bps("10 MBps"), 10_000_000);
        assert_eq!(parse_bps("fast"), 0);
        assert_eq!(parse_bps(""), 0);
    }
}
