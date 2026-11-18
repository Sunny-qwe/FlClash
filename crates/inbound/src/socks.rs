use concord_common::{InboundKind, PeekedStream};
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::ctx::{Client, HANDSHAKE_TIMEOUT, ListenCtx, Peer};
use crate::socks4;
use crate::socks5::{self, Command};
use crate::spec::{Authenticator, HostCredential};

pub(crate) async fn handle_socks4(
    ctx: &ListenCtx,
    mut stream: TcpStream,
    peer: Peer,
    auth: Option<&Authenticator>,
) {
    let Ok(Ok(request)) = timeout(
        HANDSHAKE_TIMEOUT,
        socks4::server_handshake(&mut stream, auth),
    )
    .await
    else {
        return;
    };
    let client = Client {
        user: request.user,
        host: false,
    };
    let meta = ctx.tcp_meta(InboundKind::Socks4, &peer, request.target, client);
    ctx.hand_off(meta, Box::new(stream));
}

/// A UDP ASSOCIATE holds its control connection open and discards what arrives
/// on it; the association lives exactly as long.
pub(crate) async fn handle_socks5(
    ctx: &ListenCtx,
    stream: TcpStream,
    peer: Peer,
    auth: Option<&Authenticator>,
    host: Option<&HostCredential>,
) {
    // The greeting and request arrive in one or two segments; reading them through a buffer takes one `recv`
    // per segment instead of one per field, as mihomo's bufio reader does.
    let mut buffered = BufReader::with_capacity(512, stream);
    let Ok(Ok(request)) = timeout(
        HANDSHAKE_TIMEOUT,
        socks5::server_handshake(&mut buffered, auth, host),
    )
    .await
    else {
        return;
    };
    let ahead = buffered.buffer().to_vec();
    let mut stream = buffered.into_inner();
    match request.command {
        Command::Connect => {
            if socks5::reply_success(&mut stream, peer.local)
                .await
                .is_err()
            {
                return;
            }
            let meta = ctx.tcp_meta(InboundKind::Socks5, &peer, request.target, request.client);
            if ahead.is_empty() {
                ctx.hand_off(meta, Box::new(stream));
            } else {
                ctx.hand_off(meta, Box::new(PeekedStream::new(ahead, stream)));
            }
        }
        Command::UdpAssociate => {
            let _association = ctx.assoc.register(peer.src.ip(), request.client.user);
            if socks5::reply_success(&mut stream, peer.local)
                .await
                .is_err()
            {
                return;
            }
            let mut sink = [0u8; 512];
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
        }
    }
}
