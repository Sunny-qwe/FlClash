use std::io;
use std::time::UNIX_EPOCH;

use bytes::{Buf, BytesMut};

use super::protocol::{Hash, hmac, rand_below, rand_bytes};
use super::stream::{BoxLayer, Layer};
use crate::ctx::{BuildError, Clock};
use crate::util::invalid_data;

const HEADER_END: &[u8] = b"\r\n\r\n";
const MAX_HEADER: usize = 32 * 1024;
const MAX_RECORD: usize = 16 * 1024;

const USER_AGENTS: [&str; 6] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 7.0; Moto C Build/NRD90M.059) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Plain,
    HttpSimple,
    HttpPost,
    RandomHead,
    Tls,
}

pub(super) struct ObfsFactory {
    pub(super) kind: Kind,
    host: String,
    port: u16,
    pub(super) key: Vec<u8>,
    iv_size: usize,
    param: String,
    client_id: [u8; 32],
    clock: Clock,
}

impl ObfsFactory {
    /// Returns the factory and how many bytes the layer adds to a frame.
    pub(super) fn pick(
        name: &str,
        host: &str,
        port: u16,
        key: Vec<u8>,
        iv_size: usize,
        param: &str,
        clock: Clock,
    ) -> Result<(Self, usize), BuildError> {
        let (kind, overhead) = match name {
            "plain" => (Kind::Plain, 0),
            "http_simple" => (Kind::HttpSimple, 0),
            "http_post" => (Kind::HttpPost, 0),
            "random_head" => (Kind::RandomHead, 0),
            "tls1.2_ticket_auth" | "tls1.2_ticket_fastauth" => (Kind::Tls, 5),
            other => {
                return Err(BuildError::invalid(format!(
                    "ssr initialize obfs error: Obfs {other} not supported"
                )));
            }
        };
        let mut client_id = [0u8; 32];
        rand::fill(&mut client_id[..]);
        Ok((
            ObfsFactory {
                kind,
                host: host.to_string(),
                port,
                key,
                iv_size,
                param: param.to_string(),
                client_id,
                clock,
            },
            overhead,
        ))
    }

    pub(super) fn layer(&self) -> ObfsLayer {
        match self.kind {
            Kind::Plain => ObfsLayer::Plain,
            Kind::HttpSimple | Kind::HttpPost => ObfsLayer::Http(Http {
                post: self.kind == Kind::HttpPost,
                host: self.host.clone(),
                port: self.port,
                param: self.param.clone(),
                iv_size: self.iv_size,
                sent_header: false,
                recv_header: false,
            }),
            Kind::RandomHead => ObfsLayer::RandomHead(RandomHead {
                sent_header: false,
                recv_raw: false,
                sent_raw: false,
                held: Vec::new(),
            }),
            Kind::Tls => ObfsLayer::Tls(Box::new(Tls {
                key: self.key.clone(),
                client_id: self.client_id,
                host: self.host.clone(),
                param: self.param.clone(),
                clock: self.clock.clone(),
                state: TlsState::Start,
                held: Vec::new(),
            })),
        }
    }
}

#[derive(Clone)]
pub(super) enum ObfsLayer {
    Plain,
    Http(Http),
    RandomHead(RandomHead),
    Tls(Box<Tls>),
}

impl Layer for ObfsLayer {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        match self {
            ObfsLayer::Plain => out.extend_from_slice(data),
            ObfsLayer::Http(layer) => layer.encode(out, data),
            ObfsLayer::RandomHead(layer) => layer.encode(out, data),
            ObfsLayer::Tls(layer) => layer.encode(out, data),
        }
        Ok(())
    }

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        reply: &mut Vec<u8>,
    ) -> io::Result<()> {
        match self {
            ObfsLayer::Plain => {
                decoded.extend_from_slice(input);
                input.clear();
                Ok(())
            }
            ObfsLayer::Http(layer) => layer.decode(input, decoded),
            ObfsLayer::RandomHead(layer) => {
                layer.decode(input, decoded, reply);
                Ok(())
            }
            ObfsLayer::Tls(layer) => layer.decode(input, decoded, reply),
        }
    }

    fn handshaking(&self) -> bool {
        match self {
            ObfsLayer::Plain | ObfsLayer::Http(_) => false,
            ObfsLayer::RandomHead(layer) => !layer.recv_raw,
            ObfsLayer::Tls(layer) => !matches!(layer.state, TlsState::Established),
        }
    }

    fn split(self) -> (BoxLayer, BoxLayer) {
        (Box::new(self.clone()), Box::new(self))
    }
}

fn pick_host(list: &str) -> &str {
    let hosts: Vec<&str> = list.split(',').collect();
    hosts
        .get(rand_below(hosts.len()))
        .copied()
        .unwrap_or_default()
}

#[derive(Clone)]
pub(super) struct Http {
    post: bool,
    host: String,
    port: u16,
    param: String,
    iv_size: usize,
    sent_header: bool,
    recv_header: bool,
}

impl Http {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        if self.sent_header {
            out.extend_from_slice(data);
            return;
        }
        let head_length = self.iv_size + 30;
        let mut head_len = data.len();
        if data.len().saturating_sub(head_length) > 64 {
            head_len = head_length + rand_below(65);
        }
        let (head, rest) = data.split_at(head_len.min(data.len()));

        let mut body = String::new();
        let mut host = self.host.as_str();
        if !self.param.is_empty() {
            if let Some((name, tail)) = self.param.split_once('#') {
                body = tail.replace('\n', "\r\n").replace("\\n", "\r\n");
                host = name;
            } else {
                host = &self.param;
            }
        }
        let host = pick_host(host);

        let mut request = String::new();
        request.push_str(if self.post { "POST /" } else { "GET /" });
        for byte in head {
            request.push_str(&format!("%{byte:02x}"));
        }
        request.push_str(" HTTP/1.1\r\nHost: ");
        request.push_str(host);
        if self.port != 80 {
            request.push_str(&format!(":{}", self.port));
        }
        request.push_str("\r\n");
        if body.is_empty() {
            request.push_str("User-Agent: ");
            request.push_str(
                USER_AGENTS
                    .get(rand_below(USER_AGENTS.len()))
                    .copied()
                    .unwrap_or_default(),
            );
            request.push_str("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n");
            if self.post {
                const SET: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                request.push_str("Content-Type: multipart/form-data; boundary=");
                for _ in 0..32 {
                    request.push(char::from(SET.get(rand_below(62)).copied().unwrap_or(b'A')));
                }
                request.push_str("\r\n");
            }
            request.push_str("DNT: 1\r\nConnection: keep-alive\r\n\r\n");
        } else {
            request.push_str(&body);
            request.push_str("\r\n\r\n");
        }
        out.extend_from_slice(request.as_bytes());
        out.extend_from_slice(rest);
        self.sent_header = true;
    }

    fn decode(&mut self, input: &mut BytesMut, decoded: &mut BytesMut) -> io::Result<()> {
        if !self.recv_header {
            let Some(end) = input
                .windows(HEADER_END.len())
                .position(|w| w == HEADER_END)
            else {
                if input.len() > MAX_HEADER {
                    return Err(invalid_data("http obfs header too long"));
                }
                return Ok(());
            };
            input.advance(end + HEADER_END.len());
            self.recv_header = true;
        }
        decoded.extend_from_slice(input);
        input.clear();
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct RandomHead {
    sent_header: bool,
    recv_raw: bool,
    sent_raw: bool,
    held: Vec<u8>,
}

impl RandomHead {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        if self.sent_raw {
            out.extend_from_slice(data);
            return;
        }
        self.held.extend_from_slice(data);
        if !self.sent_header {
            self.sent_header = true;
            let len = rand_below(96) + 4;
            let start = out.len();
            rand_bytes(out, len);
            let crc = crc32fast::hash(out.get(start..).unwrap_or_default());
            out.extend_from_slice(&(0xffff_ffff - crc).to_le_bytes());
        } else if self.recv_raw {
            out.append(&mut self.held);
            self.sent_raw = true;
        }
    }

    fn decode(&mut self, input: &mut BytesMut, decoded: &mut BytesMut, reply: &mut Vec<u8>) {
        if !self.recv_raw {
            input.clear();
            self.recv_raw = true;
            reply.append(&mut self.held);
            self.sent_raw = true;
            return;
        }
        decoded.extend_from_slice(input);
        input.clear();
    }
}

#[derive(Clone)]
enum TlsState {
    Start,
    WaitServer,
    Established,
}

#[derive(Clone)]
pub(super) struct Tls {
    key: Vec<u8>,
    client_id: [u8; 32],
    host: String,
    param: String,
    clock: Clock,
    state: TlsState,
    held: Vec<u8>,
}

fn pack_record(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&[0x17, 3, 3]);
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(data);
}

impl Tls {
    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut key = self.key.clone();
        key.extend_from_slice(&self.client_id);
        hmac(Hash::Sha1, &key, data).into_iter().take(10).collect()
    }

    fn sni(&self) -> String {
        let mut host = if self.param.is_empty() {
            self.host.as_str()
        } else {
            self.param.as_str()
        };
        if host
            .chars()
            .last()
            .is_some_and(|last| last.is_ascii_digit())
        {
            host = "";
        }
        pick_host(host).to_string()
    }

    fn hello(&self) -> Vec<u8> {
        let now = (self.clock)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
            });
        let mut data = vec![3, 3];
        let auth_start = data.len();
        data.extend_from_slice(&now.to_be_bytes());
        rand_bytes(&mut data, 18);
        let mac = self.mac(data.get(auth_start..).unwrap_or_default());
        data.extend_from_slice(&mac);
        data.push(0x20);
        data.extend_from_slice(&self.client_id);
        data.extend_from_slice(&[
            0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
            0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f,
            0x00, 0x0a,
        ]);
        data.extend_from_slice(&[0x01, 0x00]);

        let host = self.sni();
        let mut ext = vec![0xff, 0x01, 0x00, 0x01, 0x00];
        let host_len = u16::try_from(host.len()).unwrap_or(u16::MAX);
        ext.extend_from_slice(&[0, 0]);
        ext.extend_from_slice(&(host_len + 5).to_be_bytes());
        ext.extend_from_slice(&(host_len + 3).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&host_len.to_be_bytes());
        ext.extend_from_slice(host.as_bytes());
        ext.extend_from_slice(&[0, 0x17, 0, 0]);
        let ticket = 16 * (rand_below(17) + 8);
        ext.extend_from_slice(&[0, 0x23]);
        ext.extend_from_slice(&u16::try_from(ticket).unwrap_or(0).to_be_bytes());
        rand_bytes(&mut ext, ticket);
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03,
            0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03,
        ]);
        ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x12, 0x00, 0x00]);
        ext.extend_from_slice(&[0x75, 0x50, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18]);
        data.extend_from_slice(&u16::try_from(ext.len()).unwrap_or(0).to_be_bytes());
        data.extend_from_slice(&ext);

        let mut record = vec![0x16, 3, 1];
        record.extend_from_slice(&u16::try_from(data.len() + 4).unwrap_or(0).to_be_bytes());
        record.extend_from_slice(&[1, 0]);
        record.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        record.extend_from_slice(&data);
        record
    }

    fn encode(&mut self, out: &mut Vec<u8>, mut data: &[u8]) {
        if matches!(self.state, TlsState::Established) {
            while data.len() > 2048 {
                let size = (rand_below(4096) + 100).min(data.len());
                let (chunk, rest) = data.split_at(size);
                pack_record(out, chunk);
                data = rest;
            }
            if !data.is_empty() {
                pack_record(out, data);
            }
            return;
        }
        for chunk in data.chunks(MAX_RECORD) {
            pack_record(&mut self.held, chunk);
        }
        if matches!(self.state, TlsState::Start) {
            self.state = TlsState::WaitServer;
            out.extend_from_slice(&self.hello());
        }
    }

    fn finish(&mut self, reply: &mut Vec<u8>) {
        let start = reply.len();
        reply.extend_from_slice(&[0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20]);
        rand_bytes(reply, 22);
        let mac = self.mac(reply.get(start..).unwrap_or_default());
        reply.extend_from_slice(&mac);
        reply.append(&mut self.held);
        self.state = TlsState::Established;
    }

    /// The flight ends one record after ChangeCipherSpec; servers put a session
    /// ticket before it on about one handshake in nine. mihomo takes one read of its
    /// relay buffer as the whole flight, so a flight runs no further than that.
    pub(super) fn flight_len(input: &[u8]) -> Option<usize> {
        const MAX_FLIGHT: usize = 32 * 1024;
        const CHANGE_CIPHER_SPEC: u8 = 0x14;
        let mut at = 0;
        let mut last = false;
        while at < MAX_FLIGHT {
            let header = input.get(at..at + 5)?;
            let len = usize::from(u16::from_be_bytes([*header.get(3)?, *header.get(4)?]));
            at += 5 + len;
            if last {
                return (input.len() >= at).then_some(at);
            }
            last = *header.first()? == CHANGE_CIPHER_SPEC;
        }
        Some(input.len())
    }

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        reply: &mut Vec<u8>,
    ) -> io::Result<()> {
        if matches!(self.state, TlsState::WaitServer) {
            let Some(len) = Self::flight_len(input) else {
                return Ok(());
            };
            let flight = input.get(..len).unwrap_or_default();
            if len < 11 + 32 + 1 + 32 {
                return Err(invalid_data("tls1.2_ticket_auth too short data"));
            }
            let random_ok = self.mac(flight.get(11..33).unwrap_or_default())
                == flight.get(33..43).unwrap_or_default();
            let body = flight.get(..len - 10).unwrap_or_default();
            let tail_ok = self.mac(body) == flight.get(len - 10..).unwrap_or_default();
            if !random_ok || !tail_ok {
                return Err(invalid_data("tls1.2_ticket_auth hmac verifying failed"));
            }
            input.advance(len);
            self.finish(reply);
        }
        if matches!(self.state, TlsState::Established) {
            while input.len() > 5 {
                if input.get(..3) != Some(&[0x17, 3, 3][..]) {
                    input.clear();
                    return Err(invalid_data("tls1.2_ticket_auth incorrect magic number"));
                }
                let size = usize::from(u16::from_be_bytes([
                    input.get(3).copied().unwrap_or(0),
                    input.get(4).copied().unwrap_or(0),
                ]));
                if input.len() < 5 + size {
                    break;
                }
                input.advance(5);
                decoded.extend_from_slice(input.get(..size).unwrap_or_default());
                input.advance(size);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Tls;

    fn record(kind: u8, len: u8) -> Vec<u8> {
        let mut out = vec![kind, 3, 3, 0, len];
        out.resize(5 + usize::from(len), 0);
        out
    }

    #[test]
    fn a_flight_ends_one_record_after_change_cipher_spec() {
        let without: Vec<u8> = [record(0x16, 90), record(0x14, 1), record(0x16, 32)].concat();
        let with: Vec<u8> = [
            record(0x16, 90),
            record(0x16, 70),
            record(0x14, 1),
            record(0x16, 40),
        ]
        .concat();
        for flight in [without, with] {
            assert_eq!(Tls::flight_len(&flight), Some(flight.len()));
            assert_eq!(Tls::flight_len(&flight[..flight.len() - 1]), None);
            let mut more = flight.clone();
            more.extend_from_slice(&record(0x17, 5));
            assert_eq!(Tls::flight_len(&more), Some(flight.len()));
        }
    }
}
