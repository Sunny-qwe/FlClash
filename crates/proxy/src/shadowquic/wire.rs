use std::io;

use concord_common::Address;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::addr_codec::SOCKS;

pub(super) const CONNECT: u8 = 0x01;
pub(super) const ASSOCIATE_DATAGRAM: u8 = 0x03;
pub(super) const ASSOCIATE_STREAM: u8 = 0x04;
const EXTENSION: u8 = 0xff;
const OPCODE_BRUTAL: u64 = 0x6d69_686f_6d6f_0001;
const BRUTAL_VERSION: u8 = 1;
const BRUTAL_RX_AUTO: u8 = 1;
const BRUTAL_MIN_PAYLOAD: usize = 8;
const BRUTAL_MAX_PAYLOAD: usize = 64;

pub(super) fn request(command: u8, target: &Address) -> io::Result<Vec<u8>> {
    let mut out = vec![command];
    SOCKS.write(target, &mut out)?;
    Ok(out)
}

pub(super) fn unspecified() -> Address {
    Address::new("0.0.0.0", 0)
}

pub(super) fn control_entry(addr: &Address, id: u16) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    SOCKS.write(addr, &mut out)?;
    out.extend_from_slice(&id.to_be_bytes());
    Ok(out)
}

pub(super) async fn read_control_entry<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(Address, u16)> {
    let addr = SOCKS.read(reader).await?;
    Ok((addr, reader.read_u16().await?))
}

pub(super) fn datagram(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(super) fn split_datagram(message: &[u8]) -> Option<(u16, &[u8])> {
    let (id, payload) = message.split_first_chunk::<2>()?;
    Some((u16::from_be_bytes(*id), payload))
}

pub(super) fn brutal_request(rx: u64) -> Vec<u8> {
    let mut out = vec![EXTENSION];
    out.extend_from_slice(&OPCODE_BRUTAL.to_be_bytes());
    out.extend_from_slice(&brutal_frame(0, rx));
    out
}

fn brutal_frame(flags: u8, rx: u64) -> Vec<u8> {
    let mut out = vec![BRUTAL_VERSION, flags];
    out.extend_from_slice(&(BRUTAL_MIN_PAYLOAD as u16).to_be_bytes());
    out.extend_from_slice(&rx.to_be_bytes());
    out
}

/// The server's grant: its receive rate and whether it asked the client to
/// keep a congestion-controlled sender.
pub(super) async fn read_brutal_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<(u64, bool)> {
    let bad = |message: &str| io::Error::new(io::ErrorKind::InvalidData, message.to_string());
    let mut head = [0u8; 4];
    reader.read_exact(&mut head).await?;
    let [version, flags, hi, lo] = head;
    if version != BRUTAL_VERSION {
        return Err(bad("unsupported brutal negotiation version"));
    }
    let len = usize::from(u16::from_be_bytes([hi, lo]));
    if !(BRUTAL_MIN_PAYLOAD..=BRUTAL_MAX_PAYLOAD).contains(&len) {
        return Err(bad("invalid brutal negotiation"));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    let rx = payload
        .first_chunk::<8>()
        .map(|bytes| u64::from_be_bytes(*bytes))
        .ok_or_else(|| bad("invalid brutal negotiation"))?;
    Ok((rx, flags & BRUTAL_RX_AUTO != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_follow_the_socks_layout() {
        assert_eq!(
            request(CONNECT, &Address::new("a.b", 80)).unwrap(),
            [1, 3, 3, b'a', b'.', b'b', 0, 80]
        );
        assert_eq!(
            request(ASSOCIATE_DATAGRAM, &unspecified()).unwrap(),
            [3, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn control_entries_round_trip() {
        for addr in ["1.2.3.4:53", "[2001:db8::1]:443", "example.com:80"] {
            let addr = Address::parse(addr).unwrap();
            let wire = control_entry(&addr, 0xbeef).unwrap();
            let (parsed, id) = read_control_entry(&mut &wire[..]).await.unwrap();
            assert_eq!((parsed, id), (addr, 0xbeef));
        }
        assert!(read_control_entry(&mut &[1u8, 1, 2][..]).await.is_err());
    }

    #[test]
    fn datagrams_carry_the_association_id_first() {
        let wire = datagram(0x0102, b"hi");
        assert_eq!(wire, [1, 2, b'h', b'i']);
        assert_eq!(split_datagram(&wire), Some((0x0102, &b"hi"[..])));
        assert_eq!(split_datagram(&[1]), None);
    }

    #[tokio::test]
    async fn the_brutal_exchange_matches_the_mihomo_frame() {
        let request = brutal_request(7);
        assert_eq!(
            request,
            [
                0xff, 0x6d, 0x69, 0x68, 0x6f, 0x6d, 0x6f, 0, 1, 1, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 7
            ]
        );
        let reply = brutal_frame(1, 99);
        let (rx, auto) = read_brutal_response(&mut &reply[..]).await.unwrap();
        assert_eq!((rx, auto), (99, true));
        let mut wrong = reply.clone();
        wrong[0] = 2;
        assert!(read_brutal_response(&mut &wrong[..]).await.is_err());
        let mut short = reply;
        short[3] = 4;
        assert!(read_brutal_response(&mut &short[..]).await.is_err());
    }
}
