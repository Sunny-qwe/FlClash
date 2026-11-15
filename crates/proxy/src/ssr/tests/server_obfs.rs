use std::io;

use bytes::{Buf, BytesMut};

use crate::ssr::obfs::{Kind, ObfsFactory};
use crate::ssr::protocol::{Hash, hmac};
use crate::ssr::stream::{BoxLayer, Layer};

pub(super) enum ServerObfs {
    Plain,
    Http { sent: bool, got: bool },
    RandomHead { got: bool },
    Tls(TlsServer),
}

pub(super) struct TlsServer {
    key: Vec<u8>,
    client_id: Vec<u8>,
    state: u8,
}

pub(super) fn layer(factory: &ObfsFactory) -> ServerObfs {
    match factory.kind {
        Kind::Plain => ServerObfs::Plain,
        Kind::HttpSimple | Kind::HttpPost => ServerObfs::Http {
            sent: false,
            got: false,
        },
        Kind::RandomHead => ServerObfs::RandomHead { got: false },
        Kind::Tls => ServerObfs::Tls(TlsServer {
            key: factory.key.clone(),
            client_id: Vec::new(),
            state: 0,
        }),
    }
}

fn unhex(path: &[u8]) -> Vec<u8> {
    path.split(|b| *b == b'%')
        .skip(1)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

impl TlsServer {
    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut key = self.key.clone();
        key.extend_from_slice(&self.client_id);
        hmac(Hash::Sha1, &key, data)[..10].to_vec()
    }

    fn flight(&self) -> Vec<u8> {
        let mut random = vec![7u8; 22];
        random.extend_from_slice(&self.mac(&random.clone()));
        let mut body = vec![3, 3];
        body.extend_from_slice(&random);
        body.push(0x20);
        body.extend_from_slice(&self.client_id);
        body.extend_from_slice(&[0xc0, 0x2f, 0, 0, 0]);
        let mut out = vec![0x16, 3, 3];
        out.extend_from_slice(&u16::try_from(body.len() + 4).unwrap().to_be_bytes());
        out.extend_from_slice(&[2, 0]);
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&body);
        if self.client_id.first().is_some_and(|byte| byte & 1 == 1) {
            out.extend_from_slice(&[0x16, 3, 3, 0, 8, 4, 0, 0, 4, 1, 2, 3, 4]);
        }
        out.extend_from_slice(&[0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20]);
        out.extend_from_slice(&[9u8; 22]);
        let mac = self.mac(&out);
        out.extend_from_slice(&mac);
        out
    }
}

impl Layer for ServerObfs {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        match self {
            ServerObfs::Plain | ServerObfs::RandomHead { .. } => out.extend_from_slice(data),
            ServerObfs::Http { sent, .. } => {
                if !*sent {
                    out.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    *sent = true;
                }
                out.extend_from_slice(data);
            }
            ServerObfs::Tls(_) => {
                for chunk in data.chunks(8000) {
                    out.extend_from_slice(&[0x17, 3, 3]);
                    out.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
                    out.extend_from_slice(chunk);
                }
            }
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
            ServerObfs::Plain => {
                decoded.extend_from_slice(input);
                input.clear();
            }
            ServerObfs::Http { got, .. } => {
                if !*got {
                    let Some(end) = input.windows(4).position(|w| w == b"\r\n\r\n") else {
                        return Ok(());
                    };
                    let line_end = input.iter().position(|b| *b == b'\r').unwrap();
                    let line = &input[..line_end];
                    let path = &line[line.iter().position(|b| *b == b'/').unwrap()..];
                    let path = &path[..path.iter().position(|b| *b == b' ').unwrap()];
                    decoded.extend_from_slice(&unhex(path));
                    input.advance(end + 4);
                    *got = true;
                }
                decoded.extend_from_slice(input);
                input.clear();
            }
            ServerObfs::RandomHead { got } => {
                if !*got {
                    input.clear();
                    *got = true;
                    reply.extend_from_slice(&[0x55; 40]);
                } else {
                    decoded.extend_from_slice(input);
                    input.clear();
                }
            }
            ServerObfs::Tls(tls) => {
                if tls.state == 0 {
                    if input.len() < 5
                        || input.len() < 5 + usize::from(u16::from_be_bytes([input[3], input[4]]))
                    {
                        return Ok(());
                    }
                    let total = 5 + usize::from(u16::from_be_bytes([input[3], input[4]]));
                    tls.client_id = input[44..76].to_vec();
                    assert_eq!(input[33..43], tls.mac(&input[11..33])[..]);
                    input.advance(total);
                    reply.extend_from_slice(&tls.flight());
                    tls.state = 1;
                }
                if tls.state == 1 {
                    if input.len() < 43 {
                        return Ok(());
                    }
                    input.advance(43);
                    tls.state = 2;
                }
                while input.len() >= 5 {
                    assert_eq!(input[..3], [0x17, 3, 3]);
                    let size = usize::from(u16::from_be_bytes([input[3], input[4]]));
                    if input.len() < 5 + size {
                        break;
                    }
                    decoded.extend_from_slice(&input[5..5 + size]);
                    input.advance(5 + size);
                }
            }
        }
        Ok(())
    }

    fn split(self) -> (BoxLayer, BoxLayer) {
        unreachable!("the test server is never split")
    }
}
