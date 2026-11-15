use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::util::invalid_data;

pub(super) const VERSION: u8 = 3;
pub(super) const HELLO_LEN: usize = 1 + 8 + 8 + 2;
pub(super) const RESPONSE_LEN: usize = 1 + 4 + 2;
const UDP_FIXED: usize = 4 + 2 + 2 + 2 + 1 + 1 + 2;

pub(super) fn client_hello(send_bps: u64, recv_bps: u64, auth: &[u8]) -> io::Result<Vec<u8>> {
    let auth_len = u16::try_from(auth.len()).map_err(|_| invalid_data("auth too long"))?;
    let mut out = Vec::with_capacity(HELLO_LEN + auth.len());
    out.push(VERSION);
    out.extend_from_slice(&send_bps.to_be_bytes());
    out.extend_from_slice(&recv_bps.to_be_bytes());
    out.extend_from_slice(&auth_len.to_be_bytes());
    out.extend_from_slice(auth);
    Ok(out)
}

pub(super) struct ServerHello {
    pub(super) ok: bool,
    pub(super) recv_bps: u64,
    pub(super) message: String,
}

pub(super) fn parse_server_hello(head: &[u8; HELLO_LEN]) -> (ServerHello, usize) {
    let [
        ok,
        _s0,
        _s1,
        _s2,
        _s3,
        _s4,
        _s5,
        _s6,
        _s7,
        r0,
        r1,
        r2,
        r3,
        r4,
        r5,
        r6,
        r7,
        m0,
        m1,
    ] = *head;
    (
        ServerHello {
            ok: ok == 1,
            recv_bps: u64::from_be_bytes([r0, r1, r2, r3, r4, r5, r6, r7]),
            message: String::new(),
        },
        usize::from(u16::from_be_bytes([m0, m1])),
    )
}

pub(super) async fn read_server_hello<R: AsyncRead + Unpin>(io: &mut R) -> io::Result<ServerHello> {
    let mut head = [0u8; HELLO_LEN];
    io.read_exact(&mut head).await?;
    let (mut hello, message_len) = parse_server_hello(&head);
    if message_len > 0 {
        let mut message = vec![0u8; message_len];
        io.read_exact(&mut message).await?;
        hello.message = String::from_utf8_lossy(&message).into_owned();
    }
    Ok(hello)
}

pub(super) fn client_request(udp: bool, host: &str, port: u16) -> io::Result<Vec<u8>> {
    let host_len = u16::try_from(host.len()).map_err(|_| invalid_data("host too long"))?;
    let mut out = Vec::with_capacity(5 + host.len());
    out.push(u8::from(udp));
    out.extend_from_slice(&host_len.to_be_bytes());
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

pub(super) struct ServerResponse {
    pub(super) ok: bool,
    pub(super) session: u32,
    pub(super) message: String,
}

pub(super) fn parse_response_head(head: &[u8; RESPONSE_LEN]) -> (ServerResponse, usize) {
    let [ok, s0, s1, s2, s3, m0, m1] = *head;
    (
        ServerResponse {
            ok: ok == 1,
            session: u32::from_be_bytes([s0, s1, s2, s3]),
            message: String::new(),
        },
        usize::from(u16::from_be_bytes([m0, m1])),
    )
}

pub(super) async fn read_server_response<R: AsyncRead + Unpin>(
    io: &mut R,
) -> io::Result<ServerResponse> {
    let mut head = [0u8; RESPONSE_LEN];
    io.read_exact(&mut head).await?;
    let (mut response, message_len) = parse_response_head(&head);
    if message_len > 0 {
        let mut message = vec![0u8; message_len];
        io.read_exact(&mut message).await?;
        response.message = String::from_utf8_lossy(&message).into_owned();
    }
    Ok(response)
}

pub(super) struct UdpHeader<'a> {
    pub(super) session: u32,
    pub(super) host: &'a str,
    pub(super) port: u16,
    pub(super) message: u16,
    pub(super) fragment: u8,
    pub(super) fragments: u8,
    pub(super) data_len: u16,
}

pub(super) fn udp_header_len(host: &str) -> usize {
    UDP_FIXED + host.len()
}

pub(super) fn put_udp_header(out: &mut Vec<u8>, header: &UdpHeader<'_>) {
    out.extend_from_slice(&header.session.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(header.host.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    out.extend_from_slice(header.host.as_bytes());
    out.extend_from_slice(&header.port.to_be_bytes());
    out.extend_from_slice(&header.message.to_be_bytes());
    out.push(header.fragment);
    out.push(header.fragments);
    out.extend_from_slice(&header.data_len.to_be_bytes());
}

pub(super) struct UdpMessage<'a> {
    pub(super) session: u32,
    pub(super) host: &'a str,
    pub(super) port: u16,
    pub(super) message: u16,
    pub(super) fragment: u8,
    pub(super) fragments: u8,
    pub(super) data: &'a [u8],
}

pub(super) fn parse_udp(datagram: &[u8]) -> io::Result<UdpMessage<'_>> {
    let short = || invalid_data("short udp message");
    let session = datagram
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or_else(short)?;
    let host_len = datagram
        .get(4..6)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(short)?;
    let host_end = 6 + host_len;
    let host = datagram.get(6..host_end).ok_or_else(short)?;
    let host = std::str::from_utf8(host).map_err(|_| invalid_data("invalid host"))?;
    let tail = datagram.get(host_end..host_end + 8).ok_or_else(short)?;
    let [p0, p1, i0, i1, fragment, fragments, l0, l1] = *tail else {
        return Err(short());
    };
    let data = datagram.get(host_end + 8..).ok_or_else(short)?;
    if data.len() != usize::from(u16::from_be_bytes([l0, l1])) {
        return Err(invalid_data("invalid data length"));
    }
    Ok(UdpMessage {
        session,
        host,
        port: u16::from_be_bytes([p0, p1]),
        message: u16::from_be_bytes([i0, i1]),
        fragment,
        fragments,
        data,
    })
}

/// Puts the pieces of one datagram back together. Like the reference
/// client it follows one fragmented datagram at a time per connection.
#[derive(Default)]
pub(super) struct Defrag {
    message: u16,
    pieces: Vec<Option<Vec<u8>>>,
    count: usize,
}

impl Defrag {
    /// The whole payload once `message` is complete; a datagram that was never
    /// split comes back as it is.
    pub(super) fn feed(&mut self, message: &UdpMessage<'_>) -> Option<Vec<u8>> {
        if message.fragments <= 1 {
            return Some(message.data.to_vec());
        }
        if message.fragment >= message.fragments {
            return None;
        }
        let index = usize::from(message.fragment);
        if message.message != self.message || self.pieces.len() != usize::from(message.fragments) {
            self.message = message.message;
            self.pieces = vec![None; usize::from(message.fragments)];
            self.count = 0;
        }
        let slot = self.pieces.get_mut(index)?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(message.data.to_vec());
        self.count += 1;
        if self.count < self.pieces.len() {
            return None;
        }
        let whole = std::mem::take(&mut self.pieces)
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        self.count = 0;
        Some(whole)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(header: &UdpHeader<'_>, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_udp_header(&mut out, header);
        out.extend_from_slice(data);
        out
    }

    fn header<'a>(
        host: &'a str,
        message: u16,
        fragment: u8,
        fragments: u8,
        len: usize,
    ) -> UdpHeader<'a> {
        UdpHeader {
            session: 7,
            host,
            port: 53,
            message,
            fragment,
            fragments,
            data_len: len as u16,
        }
    }

    #[test]
    fn hello_and_request_have_the_reference_layout() {
        let hello = client_hello(1, 2, b"ab").unwrap();
        assert_eq!(
            hello,
            [
                3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, b'a', b'b'
            ]
        );
        assert_eq!(
            client_request(false, "h.io", 443).unwrap(),
            [0, 0, 4, b'h', b'.', b'i', b'o', 1, 0xbb]
        );
        assert_eq!(client_request(true, "", 0).unwrap(), [1, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn a_server_hello_with_a_message_is_read_whole() {
        let mut wire = vec![
            0u8, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 9, 0, 2, b'n', b'o',
        ];
        wire.extend_from_slice(b"rest");
        let mut reader = &wire[..];
        let hello = read_server_hello(&mut reader).await.unwrap();
        assert!(!hello.ok);
        assert_eq!(hello.recv_bps, 9);
        assert_eq!(hello.message, "no");
        assert_eq!(reader, b"rest");
    }

    #[tokio::test]
    async fn a_server_response_carries_the_session_id() {
        let wire = [1u8, 0, 0, 1, 2, 0, 0];
        let response = read_server_response(&mut &wire[..]).await.unwrap();
        assert!(response.ok);
        assert_eq!(response.session, 0x0102);
        assert!(response.message.is_empty());
    }

    #[test]
    fn udp_messages_round_trip() {
        let wire = datagram(&header("example.com", 3, 0, 1, 4), b"data");
        assert_eq!(wire.len(), udp_header_len("example.com") + 4);
        let message = parse_udp(&wire).unwrap();
        assert_eq!(message.session, 7);
        assert_eq!(message.host, "example.com");
        assert_eq!(message.port, 53);
        assert_eq!(message.data, b"data");
    }

    #[test]
    fn udp_messages_with_a_wrong_length_are_refused() {
        let mut wire = datagram(&header("h", 1, 0, 1, 4), b"data");
        wire.push(0);
        assert!(parse_udp(&wire).is_err());
        assert!(parse_udp(&wire[..5]).is_err());
        assert!(parse_udp(&[]).is_err());
    }

    #[test]
    fn fragments_join_in_any_order() {
        let mut defrag = Defrag::default();
        let pieces: [&[u8]; 3] = [b"aa", b"bb", b"c"];
        let wires: Vec<Vec<u8>> = pieces
            .iter()
            .enumerate()
            .map(|(i, piece)| datagram(&header("h", 9, i as u8, 3, piece.len()), piece))
            .collect();
        let mut whole = None;
        for index in [2, 0, 1] {
            let message = parse_udp(&wires[index]).unwrap();
            whole = defrag.feed(&message);
            if index != 1 {
                assert!(whole.is_none());
            }
        }
        assert_eq!(whole.unwrap(), b"aabbc");
    }

    #[test]
    fn a_new_message_id_drops_the_unfinished_one() {
        let mut defrag = Defrag::default();
        let first = datagram(&header("h", 1, 0, 2, 1), b"x");
        assert!(defrag.feed(&parse_udp(&first).unwrap()).is_none());
        let other = datagram(&header("h", 2, 1, 2, 1), b"y");
        assert!(defrag.feed(&parse_udp(&other).unwrap()).is_none());
        let rest = datagram(&header("h", 2, 0, 2, 1), b"z");
        assert_eq!(defrag.feed(&parse_udp(&rest).unwrap()).unwrap(), b"zy");
    }

    #[test]
    fn a_fragment_past_the_count_is_ignored() {
        let mut defrag = Defrag::default();
        let wire = datagram(&header("h", 1, 5, 2, 1), b"x");
        assert!(defrag.feed(&parse_udp(&wire).unwrap()).is_none());
    }
}
