use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::Message;

use crate::client::{
    Client, decode, encode, exchange_framed, is_answer_to, with_random_id, with_timeout,
};
use crate::dialer::{Connector, Cx, UdpLink};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

/// `udp://` and `tcp://`: one socket per exchange, and a truncated UDP answer
/// is asked again over TCP.
pub(crate) struct PlainClient {
    transport: Transport,
    host: String,
    port: u16,
    connector: Arc<Connector>,
}

impl PlainClient {
    pub(crate) fn new(
        transport: Transport,
        host: String,
        port: u16,
        connector: Arc<Connector>,
    ) -> Self {
        PlainClient {
            transport,
            host,
            port,
            connector,
        }
    }

    async fn over_udp(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let link = self.connector.udp(&self.host, self.port, cx).await?;
        exchange_datagram(&link, req).await
    }

    async fn over_tcp(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let mut stream = self.connector.tcp(&self.host, self.port, cx).await?;
        exchange_framed(&mut stream, req).await
    }
}

pub(crate) async fn exchange_datagram(link: &UdpLink, req: &Message) -> io::Result<Message> {
    link.send(&encode(req)?).await?;
    let mut buf = vec![0u8; usize::from(u16::MAX)];
    loop {
        let n = link.recv(&mut buf).await?;
        if let Ok(resp) = decode(buf.get(..n).unwrap_or_default())
            && resp.metadata.id == req.metadata.id
            && is_answer_to(req, &resp)
        {
            return Ok(resp);
        }
    }
}

#[async_trait]
impl Client for PlainClient {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let original = req.metadata.id;
        let req = with_random_id(req);
        let mut resp = with_timeout(async {
            match self.transport {
                Transport::Udp => self.over_udp(&req, cx).await,
                Transport::Tcp => self.over_tcp(&req, cx).await,
            }
        })
        .await?;
        if resp.metadata.truncation && self.transport == Transport::Udp {
            resp = with_timeout(self.over_tcp(&req, cx)).await?;
        }
        resp.metadata.id = original;
        Ok(resp)
    }

    fn address(&self) -> String {
        let scheme = match self.transport {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        };
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{scheme}://{host}:{}", self.port)
    }
}
