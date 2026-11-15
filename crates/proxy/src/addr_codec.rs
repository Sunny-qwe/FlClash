use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use concord_common::Address;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::util::invalid_data;

#[derive(Clone, Copy, Debug)]
pub(crate) struct AddrFormat {
    v4: u8,
    v6: u8,
    domain: Option<u8>,
    port_first: bool,
}

pub(crate) const SOCKS: AddrFormat = AddrFormat {
    v4: 1,
    v6: 4,
    domain: Some(3),
    port_first: false,
};

/// VMess and VLESS write the port before the address type.
pub(crate) const VMESS: AddrFormat = AddrFormat {
    v4: 1,
    v6: 3,
    domain: Some(2),
    port_first: true,
};

pub(crate) const PACKET_ADDR: AddrFormat = AddrFormat {
    v4: 1,
    v6: 2,
    domain: None,
    port_first: false,
};

/// The frame address of sing's UDP-over-TCP.
pub(crate) const UOT: AddrFormat = AddrFormat {
    v4: 0,
    v6: 1,
    domain: Some(2),
    port_first: false,
};

pub(crate) const MAX_ADDR_LEN: usize = 1 + 1 + 255 + 2;

impl AddrFormat {
    pub(crate) fn len(self, addr: &Address) -> usize {
        match addr {
            Address::Socket(SocketAddr::V4(_)) => 1 + 4 + 2,
            Address::Socket(SocketAddr::V6(_)) => 1 + 16 + 2,
            Address::Domain(host, _) => 1 + 1 + host.len() + 2,
        }
    }

    pub(crate) fn write(self, addr: &Address, out: &mut Vec<u8>) -> io::Result<()> {
        let start = out.len();
        out.resize(start + self.len(addr), 0);
        let target = out.get_mut(start..).ok_or_else(|| invalid_data("buffer"))?;
        self.write_into(addr, target)?;
        Ok(())
    }

    pub(crate) fn write_into(self, addr: &Address, out: &mut [u8]) -> io::Result<usize> {
        let total = self.len(addr);
        let out = out
            .get_mut(..total)
            .ok_or_else(|| invalid_data("address buffer too small"))?;
        let (port_slot, rest) = if self.port_first {
            let (port, rest) = out.split_at_mut(2);
            (port, rest)
        } else {
            let (rest, port) = out.split_at_mut(total - 2);
            (port, rest)
        };
        port_slot.copy_from_slice(&addr.port().to_be_bytes());
        let (atyp, body) = rest
            .split_first_mut()
            .ok_or_else(|| invalid_data("address buffer too small"))?;
        match addr {
            Address::Socket(SocketAddr::V4(v4)) => {
                *atyp = self.v4;
                body.copy_from_slice(&v4.ip().octets());
            }
            Address::Socket(SocketAddr::V6(v6)) => {
                *atyp = self.v6;
                body.copy_from_slice(&v6.ip().octets());
            }
            Address::Domain(host, _) => {
                let code = self
                    .domain
                    .ok_or_else(|| invalid_data("domain destinations are not supported here"))?;
                let len =
                    u8::try_from(host.len()).map_err(|_| invalid_data("domain longer than 255"))?;
                *atyp = code;
                let (len_slot, name) = body
                    .split_first_mut()
                    .ok_or_else(|| invalid_data("address buffer too small"))?;
                *len_slot = len;
                name.copy_from_slice(host.as_bytes());
            }
        }
        Ok(total)
    }

    /// `Ok(None)` means the buffer ends inside the address.
    pub(crate) fn parse(self, buf: &[u8]) -> io::Result<Option<(Address, usize)>> {
        let atyp_at = if self.port_first { 2 } else { 0 };
        let Some(&atyp) = buf.get(atyp_at) else {
            return Ok(None);
        };
        let body = atyp_at + 1;
        let (addr_len, name_len) = if atyp == self.v4 {
            (4, None)
        } else if atyp == self.v6 {
            (16, None)
        } else if Some(atyp) == self.domain {
            let Some(&len) = buf.get(body) else {
                return Ok(None);
            };
            (usize::from(len), Some(1))
        } else {
            return Err(invalid_data("unknown address type"));
        };
        let skip = name_len.unwrap_or(0);
        let end = body + skip + addr_len;
        let total = if self.port_first { end } else { end + 2 };
        if buf.len() < total {
            return Ok(None);
        }
        let raw = buf
            .get(body + skip..end)
            .ok_or_else(|| invalid_data("address truncated"))?;
        let port_at = if self.port_first { 0 } else { end };
        let port = buf
            .get(port_at..port_at + 2)
            .and_then(|p| <[u8; 2]>::try_from(p).ok())
            .map(u16::from_be_bytes)
            .ok_or_else(|| invalid_data("address truncated"))?;
        let addr = if atyp == self.v4 {
            let octets: [u8; 4] = raw.try_into().map_err(|_| invalid_data("bad ipv4"))?;
            Address::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        } else if atyp == self.v6 {
            let octets: [u8; 16] = raw.try_into().map_err(|_| invalid_data("bad ipv6"))?;
            Address::from(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        } else {
            let name = std::str::from_utf8(raw).map_err(|_| invalid_data("domain is not utf-8"))?;
            Address::Domain(name.into(), port)
        };
        Ok(Some((addr, total)))
    }

    pub(crate) async fn read<R: AsyncRead + Unpin>(self, reader: &mut R) -> io::Result<Address> {
        let mut buf = [0u8; MAX_ADDR_LEN];
        let mut have = 0;
        loop {
            if let Some((addr, used)) = self.parse(buf.get(..have).unwrap_or_default())? {
                debug_assert_eq!(used, have);
                return Ok(addr);
            }
            let slot = buf
                .get_mut(have..have + 1)
                .ok_or_else(|| invalid_data("address too long"))?;
            reader.read_exact(slot).await?;
            have += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(format: AddrFormat, addr: Address) {
        let mut out = Vec::new();
        format.write(&addr, &mut out).unwrap();
        assert_eq!(out.len(), format.len(&addr));
        let (parsed, used) = format.parse(&out).unwrap().unwrap();
        assert_eq!(used, out.len());
        assert_eq!(parsed, addr);
        for cut in 0..out.len() {
            assert!(format.parse(&out[..cut]).unwrap().is_none(), "cut {cut}");
        }
    }

    #[test]
    fn every_layout_round_trips() {
        for format in [SOCKS, VMESS] {
            roundtrip(format, Address::new("1.2.3.4", 80));
            roundtrip(format, Address::new("2001:db8::1", 443));
            roundtrip(format, Address::new("example.com", 8443));
        }
        roundtrip(PACKET_ADDR, Address::new("1.2.3.4", 80));
        roundtrip(PACKET_ADDR, Address::new("::1", 53));
    }

    #[test]
    fn packet_addr_rejects_domains() {
        let mut out = Vec::new();
        assert!(
            PACKET_ADDR
                .write(&Address::new("example.com", 1), &mut out)
                .is_err()
        );
    }

    #[test]
    fn socks_layout_matches_rfc1928() {
        let mut out = Vec::new();
        SOCKS.write(&Address::new("a.b", 0x1234), &mut out).unwrap();
        assert_eq!(out, [3, 3, b'a', b'.', b'b', 0x12, 0x34]);
    }

    #[tokio::test]
    async fn read_stops_at_the_end_of_the_address() {
        let mut data: &[u8] = &[1, 1, 2, 3, 4, 0, 80, 0xff, 0xff];
        let addr = SOCKS.read(&mut data).await.unwrap();
        assert_eq!(addr, Address::new("1.2.3.4", 80));
        assert_eq!(data, [0xff, 0xff]);
    }
}
