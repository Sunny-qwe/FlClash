use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    body: Vec<u8>,
}

struct Peer {
    io: DuplexStream,
    credit: usize,
    updates: usize,
}

impl Peer {
    async fn start(mut self) -> Self {
        let mut preface = [0; 24];
        self.io.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let settings = self.recv().await;
        assert_eq!((settings.kind, settings.flags), (4, 0));
        self.send(4, 0, 0, &[]).await;
        self.send(4, 1, 0, &[]).await;
        self
    }

    async fn send(&mut self, kind: u8, flags: u8, stream: u32, body: &[u8]) {
        let mut header = [0; 9];
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        header[..3].copy_from_slice(&length[1..]);
        header[3] = kind;
        header[4] = flags;
        header[5..].copy_from_slice(&stream.to_be_bytes());
        self.io.write_all(&header).await.unwrap();
        self.io.write_all(body).await.unwrap();
    }

    async fn recv(&mut self) -> Frame {
        let mut header = [0; 9];
        self.io.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        assert!(length <= 1 << 20);
        let mut body = vec![0; length];
        self.io.read_exact(&mut body).await.unwrap();
        let frame = Frame {
            kind: header[3],
            flags: header[4],
            stream: u32::from_be_bytes(header[5..].try_into().unwrap()) & 0x7fff_ffff,
            body,
        };
        if frame.kind == 8 && frame.stream == 0 {
            self.credit += u32::from_be_bytes(frame.body[..4].try_into().unwrap()) as usize;
            self.updates += 1;
        }
        frame
    }

    async fn headers(&mut self) -> u32 {
        loop {
            let frame = self.recv().await;
            assert_ne!(frame.kind, 7, "GOAWAY before the next request");
            if frame.kind == 1 {
                return frame.stream;
            }
        }
    }

    async fn canceled(&mut self, stream: u32) {
        loop {
            let frame = self.recv().await;
            assert_ne!(frame.kind, 7, "GOAWAY before cancellation");
            if frame.kind == 3 && frame.stream == stream {
                assert_eq!(frame.body, 8u32.to_be_bytes());
                return;
            }
        }
    }

    async fn ping_ack(&mut self, token: &[u8; 8]) {
        loop {
            let frame = self.recv().await;
            assert_ne!(frame.kind, 7, "GOAWAY while consuming delayed DATA");
            if frame.kind == 6 && frame.flags == 1 {
                assert_eq!(frame.body.as_slice(), token);
                return;
            }
        }
    }

    async fn go_away(&mut self) -> (u32, String) {
        loop {
            let frame = self.recv().await;
            if frame.kind == 7 {
                let reason = u32::from_be_bytes(frame.body[4..8].try_into().unwrap());
                return (reason, String::from_utf8(frame.body[8..].to_vec()).unwrap());
            }
        }
    }
}

async fn client() -> (
    h2::client::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), h2::Error>>,
    Peer,
) {
    let (near, far) = duplex(1 << 16);
    // No tombstones makes delayed responses deterministic; keep the error guard enabled.
    let (sender, connection) = h2::client::Builder::new()
        .max_concurrent_reset_streams(0)
        .max_local_error_reset_streams(Some(1))
        .handshake::<_, Bytes>(near)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let peer = Peer {
        io: far,
        credit: 65535,
        updates: 0,
    }
    .start()
    .await;
    (sender, driver, peer)
}

#[tokio::test]
async fn delayed_headers_and_data_preserve_hpack_credit_and_connection_reuse() {
    const INITIAL_HEADERS: &[u8] = b"\x88\x40\x08x-cancel\x011";
    const INDEXED_HEADERS: &[u8] = b"\x88\xbe";
    for early in [false, true] {
        let (mut sender, driver, mut peer) = client().await;
        let (completed, mut received) = tokio::sync::mpsc::channel(1);
        let (saw_request, mut requests) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(async move {
            for index in 0..5 {
                let stream = peer.headers().await;
                let headers = if index == 0 {
                    INITIAL_HEADERS
                } else {
                    INDEXED_HEADERS
                };
                if early {
                    saw_request.send(index).await.unwrap();
                } else {
                    peer.send(1, 4, stream, headers).await;
                }
                peer.canceled(stream).await;
                if early {
                    peer.send(1, 4, stream, headers).await;
                }
                while peer.credit < 16384 {
                    let frame = peer.recv().await;
                    assert_ne!(frame.kind, 7);
                }
                peer.credit -= 16384;
                peer.send(0, 0, stream, &[0x42; 16384]).await;
                peer.send(0, 1, stream, &[]).await;
                let token = [index; 8];
                peer.send(6, 0, 0, &token).await;
                peer.ping_ack(&token).await;
                completed.send(index).await.unwrap();
            }
            assert!(
                peer.updates > 0,
                "delayed DATA must return connection credit"
            );
            let stream = peer.headers().await;
            peer.send(1, 5, stream, INDEXED_HEADERS).await;
        });
        for index in 0..5 {
            sender = sender.ready().await.unwrap();
            let (response, request) = sender.send_request(http::Request::new(()), false).unwrap();
            if early {
                assert_eq!(requests.recv().await, Some(index));
                drop(response);
            } else {
                assert_eq!(response.await.unwrap().headers()["x-cancel"], "1");
            }
            drop(request);
            assert_eq!(received.recv().await, Some(index));
        }
        sender = sender.ready().await.unwrap();
        let (response, _) = sender.send_request(http::Request::new(()), true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.headers()["x-cancel"], "1");
        assert!(response.into_body().data().await.is_none());
        server.await.unwrap();
        driver.abort();
    }
}

#[tokio::test]
async fn headers_or_data_for_a_future_stream_still_fail_the_connection() {
    for kind in [0, 1] {
        let (_sender, driver, mut peer) = client().await;
        let (flags, body): (u8, &[u8]) = if kind == 0 { (1, &[]) } else { (5, &[0x88]) };
        peer.send(kind, flags, 99, body).await;
        let (reason, _) = peer.go_away().await;
        assert_eq!(reason, u32::from(h2::Reason::PROTOCOL_ERROR));
        assert_eq!(
            driver.await.unwrap().unwrap_err().reason(),
            Some(h2::Reason::PROTOCOL_ERROR)
        );
    }
}

#[tokio::test]
async fn ignored_nonfinal_empty_data_still_exhausts_the_framing_guard() {
    let (mut sender, driver, mut peer) = client().await;
    let server = tokio::spawn(async move {
        let stream = peer.headers().await;
        peer.send(1, 4, stream, &[0x88]).await;
        peer.canceled(stream).await;
        for _ in 0..101 {
            peer.send(0, 0, stream, &[]).await;
        }
        peer.go_away().await
    });
    sender = sender.ready().await.unwrap();
    let (response, request) = sender.send_request(http::Request::new(()), false).unwrap();
    drop(response.await.unwrap());
    drop(request);
    let (reason, debug) = server.await.unwrap();
    assert_eq!(reason, u32::from(h2::Reason::ENHANCE_YOUR_CALM));
    assert_eq!(debug, "too_many_data_frames");
    assert_eq!(
        driver.await.unwrap().unwrap_err().reason(),
        Some(h2::Reason::ENHANCE_YOUR_CALM)
    );
}
