use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MIB_TCP_STATE_ESTAB: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    Tcp4,
    Udp4,
    Tcp6,
    Udp6,
}

impl Table {
    fn layout(self) -> Layout {
        match self {
            Table::Tcp4 => Layout {
                row: 24,
                ip_at: 4,
                port: 8,
                pid: 20,
                state: Some(0),
                v6: false,
            },
            Table::Udp4 => Layout {
                row: 12,
                ip_at: 0,
                port: 4,
                pid: 8,
                state: None,
                v6: false,
            },
            Table::Tcp6 => Layout {
                row: 56,
                ip_at: 0,
                port: 20,
                pid: 52,
                state: Some(48),
                v6: true,
            },
            Table::Udp6 => Layout {
                row: 28,
                ip_at: 0,
                port: 20,
                pid: 24,
                state: None,
                v6: true,
            },
        }
    }

    fn is_tcp(self) -> bool {
        matches!(self, Table::Tcp4 | Table::Tcp6)
    }
}

struct Layout {
    row: usize,
    ip_at: usize,
    port: usize,
    pid: usize,
    state: Option<usize>,
    v6: bool,
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Walks a `MIB_*TABLE_OWNER_PID` buffer. Only established TCP rows count, and an
/// unbound UDP socket shows as the wildcard address, which matches any source.
pub fn find_pid(table: Table, buf: &[u8], ip: IpAddr, port: u16) -> Option<u32> {
    let layout = table.layout();
    let count = word(buf, 0)? as usize;
    for index in 0..count {
        let start = 4 + index.checked_mul(layout.row)?;
        let row = buf.get(start..start + layout.row)?;
        if let Some(state_at) = layout.state
            && word(row, state_at)? != MIB_TCP_STATE_ESTAB
        {
            continue;
        }
        let port_bytes: [u8; 2] = row.get(layout.port..layout.port + 2)?.try_into().ok()?;
        if u16::from_be_bytes(port_bytes) != port {
            continue;
        }
        let addr = if layout.v6 {
            let octets: [u8; 16] = row.get(layout.ip_at..layout.ip_at + 16)?.try_into().ok()?;
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            let octets: [u8; 4] = row.get(layout.ip_at..layout.ip_at + 4)?.try_into().ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        };
        if addr == ip || (!table.is_tcp() && addr.is_unspecified()) {
            return word(row, layout.pid);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = (rows.len() as u32).to_ne_bytes().to_vec();
        for row in rows {
            bytes.extend_from_slice(row);
        }
        bytes
    }

    fn tcp4(state: u32, ip: [u8; 4], port: u16, pid: u32) -> Vec<u8> {
        let mut row = vec![0u8; 24];
        row[..4].copy_from_slice(&state.to_ne_bytes());
        row[4..8].copy_from_slice(&ip);
        row[8..10].copy_from_slice(&port.to_be_bytes());
        row[20..24].copy_from_slice(&pid.to_ne_bytes());
        row
    }

    fn udp4(ip: [u8; 4], port: u16, pid: u32) -> Vec<u8> {
        let mut row = vec![0u8; 12];
        row[..4].copy_from_slice(&ip);
        row[4..6].copy_from_slice(&port.to_be_bytes());
        row[8..12].copy_from_slice(&pid.to_ne_bytes());
        row
    }

    #[test]
    fn tcp_rows_must_be_established_and_match_the_address() {
        let buf = table(&[
            tcp4(2, [10, 0, 0, 1], 5000, 1),
            tcp4(5, [10, 0, 0, 2], 5000, 2),
            tcp4(5, [10, 0, 0, 1], 5000, 3),
        ]);
        let ip = "10.0.0.1".parse().unwrap();
        assert_eq!(find_pid(Table::Tcp4, &buf, ip, 5000), Some(3));
        assert_eq!(find_pid(Table::Tcp4, &buf, ip, 5001), None);
    }

    #[test]
    fn udp_matches_the_wildcard_address() {
        let buf = table(&[udp4([0, 0, 0, 0], 5353, 77)]);
        let ip = "192.168.0.9".parse().unwrap();
        assert_eq!(find_pid(Table::Udp4, &buf, ip, 5353), Some(77));
    }

    #[test]
    fn ipv6_rows_use_their_own_offsets() {
        let mut row = vec![0u8; 28];
        row[..16].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        row[20..22].copy_from_slice(&443u16.to_be_bytes());
        row[24..28].copy_from_slice(&9u32.to_ne_bytes());
        let buf = table(&[row]);
        assert_eq!(
            find_pid(Table::Udp6, &buf, IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            Some(9)
        );
    }

    #[test]
    fn a_short_buffer_is_not_a_match() {
        let mut buf = table(&[udp4([0; 4], 1, 1)]);
        buf.truncate(10);
        assert_eq!(
            find_pid(Table::Udp4, &buf, "1.1.1.1".parse().unwrap(), 1),
            None
        );
        assert_eq!(
            find_pid(Table::Udp4, &[], "1.1.1.1".parse().unwrap(), 1),
            None
        );
    }
}
