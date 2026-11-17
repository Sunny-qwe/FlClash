use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_tls::TlsOptions;
use hickory_proto::op::Message;
use quinn::crypto::rustls::QuicClientConfig;

use crate::client::{Client, Params, checked, decode, encode, with_random_id, with_timeout};
use crate::dialer::{Connector, Cx};

const ALPN: &str = "doq";
const MAX_RESPONSE: usize = 65_535;

type Session = (quinn::Endpoint, quinn::Connection);

/// `quic://`: one QUIC connection kept between queries, a stream per query.
pub(crate) struct DoqClient {
    host: String,
    port: u16,
    connector: Arc<Connector>,
    config: quinn::ClientConfig,
    session: Mutex<Option<Session>>,
}

impl DoqClient {
    pub(crate) fn new(
        host: String,
        port: u16,
        connector: Arc<Connector>,
        params: &Params<'_>,
    ) -> io::Result<Self> {
        let options = TlsOptions {
            skip_cert_verify: params.is_true("skip-cert-verify"),
            name_cert_verify: params.get("name-cert-verify").map(str::to_string),
            ..TlsOptions::default()
        };
        let tls = concord_tls::quic_client_config(
            &options,
            Arc::clone(&connector.shared().trust),
            &[ALPN],
        )
        .map_err(io::Error::other)?;
        let crypto = QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
        Ok(DoqClient {
            host,
            port,
            connector,
            config: quinn::ClientConfig::new(Arc::new(crypto)),
            session: Mutex::new(None),
        })
    }

    fn cached(&self) -> Option<quinn::Connection> {
        let slot = lock(&self.session);
        let (_, conn) = slot.as_ref()?;
        conn.close_reason().is_none().then(|| conn.clone())
    }

    async fn dial(&self, cx: Cx) -> io::Result<quinn::Connection> {
        let (socket, peer) = self
            .connector
            .quic_socket(&self.host, self.port, cx)
            .await?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.config.clone());
        let conn = endpoint
            .connect(peer, self.host.trim_matches(['[', ']']))
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        {
            let mut slot = lock(&self.session);
            *slot = Some((endpoint, conn.clone()));
        }
        Ok(conn)
    }

    async fn round_trip(conn: &quinn::Connection, query: &[u8]) -> io::Result<Message> {
        let (mut send, mut recv) = conn.open_bi().await.map_err(io::Error::other)?;
        let len = u16::try_from(query.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns query too large"))?;
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(query);
        send.write_all(&frame).await.map_err(io::Error::other)?;
        send.finish().map_err(io::Error::other)?;
        let body = recv
            .read_to_end(MAX_RESPONSE + 2)
            .await
            .map_err(io::Error::other)?;
        let payload = body
            .get(2..)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short DoQ response"))?;
        decode(payload)
    }
}

#[async_trait]
impl Client for DoqClient {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let original = req.metadata.id;
        let mut query = with_random_id(req);
        query.metadata.id = 0;
        let bytes = encode(&query)?;
        with_timeout(async {
            let mut reused = true;
            loop {
                let conn = match self.cached() {
                    Some(conn) => conn,
                    None => {
                        reused = false;
                        self.dial(cx).await?
                    }
                };
                let answer = Self::round_trip(&conn, &bytes)
                    .await
                    .and_then(|resp| checked(&query, resp));
                match answer {
                    Ok(mut resp) => {
                        resp.metadata.id = original;
                        return Ok(resp);
                    }
                    Err(err) => {
                        self.reset();
                        if !reused {
                            return Err(err);
                        }
                        reused = false;
                    }
                }
            }
        })
        .await
    }

    fn address(&self) -> String {
        format!("quic://{}:{}", self.host, self.port)
    }

    fn reset(&self) {
        let taken = lock(&self.session).take();
        if let Some((_, conn)) = taken {
            conn.close(0u32.into(), b"");
        }
    }
}
