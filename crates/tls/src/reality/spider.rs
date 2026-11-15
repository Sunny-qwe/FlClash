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
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
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
