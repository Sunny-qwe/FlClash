use std::sync::{Arc, Mutex};
use std::task::Waker;

use concord_common::sync::lock;
use shadowsocks::relay::tcprelay::crypto_io::EncryptedWriter;

use concord_common::stream_buffer::ReadBufferOptions;

use super::*;

struct Transport(Arc<Mutex<State>>);
struct State {
    incoming: Vec<u8>,
    at: usize,
    read_allowance: usize,
    outgoing: Vec<u8>,
    write_allowance: usize,
    read_pointers: Vec<usize>,
    write_pointers: Vec<usize>,
    drops: usize,
}

fn transport(incoming: Vec<u8>) -> (Transport, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State {
        incoming,
        at: 0,
        read_allowance: usize::MAX,
        outgoing: Vec::new(),
        write_allowance: usize::MAX,
        read_pointers: Vec::new(),
        write_pointers: Vec::new(),
        drops: 0,
    }));
    (Transport(state.clone()), state)
}

impl Drop for Transport {
    fn drop(&mut self) {
        lock(&self.0).drops += 1;
    }
}
impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = lock(&self.0);
        if buffer.remaining() == 0 || state.at == state.incoming.len() {
            return Poll::Ready(Ok(()));
        }
        if state.read_allowance == 0 {
            return Poll::Pending;
        }
        let take = buffer
            .remaining()
            .min(state.incoming.len() - state.at)
            .min(state.read_allowance);
        state
            .read_pointers
            .push(buffer.initialize_unfilled().as_ptr() as usize);
        buffer.put_slice(&state.incoming[state.at..state.at + take]);
        state.at += take;
        state.read_allowance -= take;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = lock(&self.0);
        if state.write_allowance == 0 {
            return Poll::Pending;
        }
        let take = data.len().min(state.write_allowance);
        state.outgoing.extend_from_slice(&data[..take]);
        state.write_allowance -= take;
        Poll::Ready(Ok(take))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl Stream for Transport {
    fn write_requirements(&self) -> BufferRequirements {
        BufferRequirements {
            front: 3,
            rear: 5,
            mtu: 0,
        }
    }
    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        assert!(buffer.headroom() >= 3 && buffer.tailroom() >= 5);
        lock(&self.0)
            .write_pointers
            .push(buffer.as_slice().as_ptr() as usize);
        concord_common::stream_buffer::poll_write_buffer(self, cx, buffer)
    }
}

fn options(front: usize, rear: usize) -> ReadBufferOptions {
    ReadBufferOptions::for_copy(
        Default::default(),
        BufferRequirements {
            front,
            rear,
            mtu: 0,
        },
    )
    .unwrap()
}
fn input(data: &[u8], requirements: BufferRequirements) -> StreamBuffer {
    let mut buffer = ReadBufferOptions::for_copy(Default::default(), requirements)
        .unwrap()
        .take_for_read(data.len(), 0)
        .unwrap();
    buffer.spare_mut()[..data.len()].copy_from_slice(data);
    buffer.advance(data.len()).unwrap();
    buffer
}
#[test]
fn classic_aead_owned_sealing_matches_the_existing_writer() {
    for kind in [
        CipherKind::AES_128_GCM,
        CipherKind::AES_256_GCM,
        CipherKind::CHACHA20_POLY1305,
        CipherKind::XCHACHA20_POLY1305,
        CipherKind::AES_128_CCM,
        CipherKind::AES_256_CCM,
        CipherKind::AES_128_GCM_SIV,
        CipherKind::AES_256_GCM_SIV,
    ] {
        let key = SsKey::new(kind, "owned tests").unwrap();
        let salt = vec![0x37; kind.salt_len()];
        let EncryptedWriter::Aead(mut old) =
            EncryptedWriter::new(StreamType::Client, kind, key.key(), &salt)
        else {
            panic!("classic AEAD");
        };
        let EncryptedWriter::Aead(mut owned) =
            EncryptedWriter::new(StreamType::Client, kind, key.key(), &salt)
        else {
            panic!("classic AEAD");
        };
        let (mut sink, state) = transport(Vec::new());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(!owned.can_encrypt_in_place());
        assert!(matches!(
            old.poll_write_encrypted(&mut cx, &mut sink, b"warm"),
            Poll::Ready(Ok(4))
        ));
        let warm = std::mem::take(&mut lock(&state).outgoing);
        assert!(matches!(
            owned.poll_write_encrypted(&mut cx, &mut sink, b"warm"),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(std::mem::take(&mut lock(&state).outgoing), warm);
        assert!(owned.can_encrypt_in_place());
        for size in [1, 127, 0x3FFF] {
            let data = vec![0x53; size];
            assert!(
                matches!(old.poll_write_encrypted(&mut cx, &mut sink, &data), Poll::Ready(Ok(n)) if n == size)
            );
            let expected = std::mem::take(&mut lock(&state).outgoing);
            let mut packet = vec![0; 2 + 2 * kind.tag_len() + size];
            packet[2 + kind.tag_len()..2 + kind.tag_len() + size].copy_from_slice(&data);
            assert!(owned.encrypt_in_place(&mut packet));
            assert_eq!(packet, expected);
        }
        assert!(matches!(
            old.poll_write_encrypted(&mut cx, &mut sink, b"after"),
            Poll::Ready(Ok(5))
        ));
        let after = std::mem::take(&mut lock(&state).outgoing);
        assert!(matches!(
            owned.poll_write_encrypted(&mut cx, &mut sink, b"after"),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(lock(&state).outgoing, after);
    }
}

#[test]
fn owned_writes_keep_the_input_storage_and_tail_holding_policy() {
    check_owned_write(CipherKind::AES_128_GCM, "owned tests");
}

fn check_owned_write(kind: CipherKind, password: &str) {
    let (stream, state) = transport(Vec::new());
    let key = SsKey::new(kind, password).unwrap();
    let mut client = ClientStream::new(
        stream,
        new_context(),
        &key,
        &Address::new("example.test", 443),
    );
    let chunk = chunk_payload(kind);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut client).poll_write(&mut cx, b"warm"),
        Poll::Ready(Ok(4))
    ));
    let mut buffer = input(&vec![0x53; chunk], client.write_requirements());
    let pointer = buffer.as_slice().as_ptr() as usize;
    lock(&state).write_allowance = 0;
    assert!(matches!(
        client.poll_write_buffer(&mut cx, &mut buffer),
        Poll::Ready(Ok(n)) if n == chunk
    ));
    assert!(buffer.is_empty());
    assert_eq!(
        client.owned_write.owed().as_ptr() as usize + client.requirements.front,
        pointer
    );
    let mut next = input(b"tail", client.write_requirements());
    assert!(client.poll_write_buffer(&mut cx, &mut next).is_pending());
    assert_eq!(next.as_slice(), b"tail");
    loop {
        lock(&state).write_allowance = 7;
        if Pin::new(&mut client).poll_flush(&mut cx).is_ready() {
            break;
        }
    }
    // A flush ends the burst; a following full chunk starts the same holding policy again.
    lock(&state).write_allowance = usize::MAX;
    let mut full = input(&vec![0x54; chunk], client.write_requirements());
    assert!(matches!(
        client.poll_write_buffer(&mut cx, &mut full),
        Poll::Ready(Ok(n)) if n == chunk
    ));
    let before = lock(&state).outgoing.len();
    assert!(matches!(
        client.poll_write_buffer(&mut cx, &mut next),
        Poll::Ready(Ok(4))
    ));
    assert_eq!(lock(&state).outgoing.len(), before);
    assert!(!client.owned_write.is_pending());
    assert!(Pin::new(&mut client).poll_flush(&mut cx).is_ready());
    assert_eq!(
        lock(&state).outgoing.len() - before,
        4 + client.requirements.front + client.requirements.rear
    );
    drop(client);
    assert_eq!(lock(&state).drops, 1);
}

#[tokio::test]
async fn startup_missing_headroom_and_oversized_inputs_keep_their_fallback() {
    use shadowsocks::relay::tcprelay::ProxyServerStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (method, password) in [
        ("aes-128-gcm", "secret"),
        ("none", "secret"),
        ("aes-128-ctr", "secret"),
        ("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA=="),
    ] {
        let kind = parse_method(method).unwrap();
        let key = SsKey::new(kind, password).unwrap();
        let (near, far) = tokio::io::duplex(127);
        let mut client = ClientStream::new(
            near,
            new_context(),
            &key,
            &Address::new("example.test", 443),
        );
        let mut server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            far,
            kind,
            key.key(),
        );
        let payload = vec![0x53; 2 * 0xFFFF + 7];
        let sending = async {
            let mut first = input(b"first", Default::default());
            while !first.is_empty() {
                std::future::poll_fn(|cx| client.poll_write_buffer(cx, &mut first))
                    .await
                    .unwrap();
            }
            let mut buffer = input(&payload, client.write_requirements());
            while !buffer.is_empty() {
                let n = std::future::poll_fn(|cx| client.poll_write_buffer(cx, &mut buffer))
                    .await
                    .unwrap();
                assert!(n > 0);
            }
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            loop {
                let buffer =
                    std::future::poll_fn(|cx| client.poll_read_buffer(cx, options(19, 17)))
                        .await
                        .unwrap();
                if buffer.is_empty() {
                    break;
                }
                assert!(buffer.headroom() >= 19 && buffer.tailroom() >= 17);
                response.extend_from_slice(buffer.as_slice());
            }
            response
        };
        let serving = async {
            assert_eq!(
                server.handshake().await.unwrap().to_string(),
                "example.test:443"
            );
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(&request[..5], b"first");
            assert_eq!(&request[5..], payload);
            server.write_all(&request).await.unwrap();
            server.shutdown().await.unwrap();
            request
        };
        let (response, request) = tokio::join!(sending, serving);
        assert_eq!(response, request, "{method}");
    }
}

fn methods_2022() -> [(CipherKind, &'static str); 4] {
    [
        (
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            "AAAAAAAAAAAAAAAAAAAAAA==",
        ),
        (
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        (
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        (
            CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
    ]
}

#[test]
fn established_2022_owned_frames_match_the_existing_writer() {
    let mut cx = Context::from_waker(Waker::noop());
    for (kind, password) in methods_2022() {
        let key = SsKey::new(kind, password).unwrap();
        let salt = vec![0x37; kind.salt_len()];
        let EncryptedWriter::Aead2022(mut old) =
            EncryptedWriter::new(StreamType::Client, kind, key.key(), &salt)
        else {
            panic!("2022 writer");
        };
        let EncryptedWriter::Aead2022(mut owned) =
            EncryptedWriter::new(StreamType::Client, kind, key.key(), &salt)
        else {
            panic!("2022 writer");
        };
        let (mut sink, state) = transport(Vec::new());
        assert!(!owned.can_encrypt_in_place());
        assert!(matches!(
            old.poll_write_encrypted(&mut cx, &mut sink, b"warm"),
            Poll::Ready(Ok(4))
        ));
        lock(&state).outgoing.clear();
        assert!(matches!(
            owned.poll_write_encrypted(&mut cx, &mut sink, b"warm"),
            Poll::Ready(Ok(4))
        ));
        // Startup samples the timestamp; compare the normal records and nonce sequence after it.
        lock(&state).outgoing.clear();
        assert!(owned.can_encrypt_in_place());
        for size in [1, 127, 32734, 65535] {
            let data = vec![0x53; size];
            assert!(
                matches!(old.poll_write_encrypted(&mut cx, &mut sink, &data), Poll::Ready(Ok(n)) if n == size)
            );
            let expected = std::mem::take(&mut lock(&state).outgoing);
            let mut packet = vec![0; size + 2 + 2 * kind.tag_len()];
            packet[2 + kind.tag_len()..2 + kind.tag_len() + size].copy_from_slice(&data);
            assert!(owned.encrypt_in_place(&mut packet));
            assert_eq!(packet, expected, "{kind:?} size {size}");
        }
        assert!(matches!(
            old.poll_write_encrypted(&mut cx, &mut sink, b"after"),
            Poll::Ready(Ok(5))
        ));
        let expected = std::mem::take(&mut lock(&state).outgoing);
        assert!(matches!(
            owned.poll_write_encrypted(&mut cx, &mut sink, b"after"),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(lock(&state).outgoing, expected);
    }
}

#[test]
fn owned_2022_writes_keep_storage_across_partial_writes_and_tail_flush() {
    for (kind, password) in methods_2022() {
        check_owned_write(kind, password);
    }
}

#[tokio::test]
async fn a_split_keeps_accepted_ciphertext_before_later_writes() {
    use shadowsocks::relay::tcprelay::ProxyServerStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for (kind, password) in
        std::iter::once((CipherKind::AES_128_GCM, "split tests")).chain(methods_2022())
    {
        let (stream, state) = transport(Vec::new());
        let key = SsKey::new(kind, password).unwrap();
        let mut client = ClientStream::new(
            stream,
            new_context(),
            &key,
            &Address::new("example.test", 443),
        );
        client.write_all(b"warm").await.unwrap();
        let payload = vec![0x53; chunk_payload(kind)];
        let mut buffer = input(&payload, client.write_requirements());
        lock(&state).write_allowance = 0;
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            matches!(client.poll_write_buffer(&mut cx, &mut buffer), Poll::Ready(Ok(n)) if n == payload.len())
        );
        assert!(client.owned_write.is_pending());
        let (read, mut write) = Box::new(client).into_split();
        assert!(Pin::new(&mut write).poll_flush(&mut cx).is_pending());
        loop {
            lock(&state).write_allowance = 7;
            if let Poll::Ready(result) = Pin::new(&mut write).poll_flush(&mut cx) {
                result.unwrap();
                break;
            }
        }
        lock(&state).write_allowance = usize::MAX;
        write.write_all(b"tail").await.unwrap();
        write.shutdown().await.unwrap();
        drop((read, write));
        let wire = std::mem::take(&mut lock(&state).outgoing);
        let (wire, _) = transport(wire);
        let mut server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            wire,
            kind,
            key.key(),
        );
        assert_eq!(
            server.handshake().await.unwrap().to_string(),
            "example.test:443"
        );
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(&request[..4], b"warm");
        assert_eq!(&request[4..4 + payload.len()], payload);
        assert_eq!(&request[4 + payload.len()..], b"tail");
        assert_eq!(lock(&state).drops, 1);
    }
}

#[tokio::test]
async fn owned_2022_writes_interoperate_with_the_unchanged_server_and_scalar_reader() {
    use shadowsocks::relay::tcprelay::ProxyServerStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for (kind, password) in methods_2022() {
        let key = SsKey::new(kind, password).unwrap();
        let (near, far) = tokio::io::duplex(127);
        let mut client = ClientStream::new(
            near,
            new_context(),
            &key,
            &Address::new("example.test", 443),
        );
        let mut server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            far,
            kind,
            key.key(),
        );
        let payload = vec![0x53; 32734];
        let sending = async {
            let mut first = input(b"first", client.write_requirements());
            while !first.is_empty() {
                std::future::poll_fn(|cx| client.poll_write_buffer(cx, &mut first))
                    .await
                    .unwrap();
            }
            let mut buffer = input(&payload, client.write_requirements());
            let accepted = std::future::poll_fn(|cx| client.poll_write_buffer(cx, &mut buffer))
                .await
                .unwrap();
            assert_eq!(accepted, payload.len());
            assert!(buffer.is_empty());
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            loop {
                let buffer =
                    std::future::poll_fn(|cx| client.poll_read_buffer(cx, options(19, 17)))
                        .await
                        .unwrap();
                if buffer.is_empty() {
                    break;
                }
                assert!(buffer.headroom() >= 19 && buffer.tailroom() >= 17);
                response.extend_from_slice(buffer.as_slice());
            }
            response
        };
        let serving = async {
            assert_eq!(
                server.handshake().await.unwrap().to_string(),
                "example.test:443"
            );
            let mut request = Vec::new();
            server.read_to_end(&mut request).await.unwrap();
            assert_eq!(&request[..5], b"first");
            assert_eq!(&request[5..], payload);
            server.write_all(&request).await.unwrap();
            server.shutdown().await.unwrap();
            request
        };
        let (response, request) = tokio::join!(sending, serving);
        assert_eq!(response, request, "{kind:?}");
    }
}
