use std::time::Duration;

use super::stream::RealityStream;

/// The peer was the cover site: browse it briefly rather than hang up at once.
pub(crate) fn spawn(stream: RealityStream, host: String, user_agent: &'static str) {
    tokio::spawn(async move {
        let _ = browse(stream, host, user_agent).await;
    });
}

async fn browse(stream: RealityStream, host: String, user_agent: &'static str) -> Option<()> {
    let (sender, connection) = h2::client::handshake(stream).await.ok()?;
    let driver = h2_driver(connection);
    let padding = "0".repeat(rand::random_range(30..62usize));
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{host}/"))
        .header("user-agent", user_agent)
        .header("cookie", format!("padding={padding}"))
        .header("accept-encoding", "gzip")
        .body(())
        .ok()?;
    let mut ready = sender.ready().await.ok()?;
    let (response, _) = ready.send_request(request, true).ok()?;
    let _ = response.await;
    tokio::time::sleep(Duration::from_secs(rand::random_range(5..15u64))).await;
    driver.abort();
    Some(())
}

pub(crate) async fn jls_fallback(
    mut stream: RealityStream,
    host: String,
    user_agent: &'static str,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let padding = "0".repeat(rand::random_range(30..62usize));
    if stream.negotiated_alpn() == Some(b"h2") {
        let Ok((sender, connection)) = h2::client::handshake(stream).await else {
            return;
        };
        let _driver = AbortOnDrop(h2_driver(connection));
        if let Ok(request) = http::Request::builder()
            .uri(format!("https://{host}/"))
            .header("user-agent", user_agent)
            .header("cookie", format!("padding={padding}"))
            .header("accept-encoding", "gzip")
            .body(())
            && let Ok(mut ready) = sender.ready().await
            && let Ok((response, _)) = ready.send_request(request, true)
        {
            let _ = response.await;
        }
    } else {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nCookie: padding={padding}\r\nAccept-Encoding: gzip\r\n\r\n"
        );
        if stream.write_all(request.as_bytes()).await.is_ok() && stream.flush().await.is_ok() {
            let mut tail = [0; 4];
            while let Ok(byte) = stream.read_u8().await {
                tail.rotate_left(1);
                tail[3] = byte;
                if tail == *b"\r\n\r\n" {
                    break;
                }
            }
        }
        let _ = stream.shutdown().await;
    }
}

fn h2_driver(
    connection: h2::client::Connection<RealityStream, bytes::Bytes>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = connection.await;
    })
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn authority(name: &rustls_pki_types::ServerName<'_>) -> String {
    let host = name.to_str();
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.into_owned()
    }
}
