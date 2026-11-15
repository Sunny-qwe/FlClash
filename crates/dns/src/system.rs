use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_platform::Platform;
use hickory_proto::op::Message;

use crate::client::{Client, ClientRef};
use crate::dialer::{Connector, Cx, Shared, Via};
use crate::plain::{PlainClient, Transport};
use crate::resolver::batch_exchange;

const REFRESH: Duration = Duration::from_secs(5 * 60);

struct Refreshed {
    at: Instant,
    servers: Vec<SocketAddr>,
}

/// Where `system://` gets its servers: the ones the embedding app handed over
/// when there are some, otherwise what the platform reports. The platform's
/// answer is kept for five minutes, as the Go core keeps the resolv.conf read.
pub(crate) struct SystemServers {
    platform: Arc<dyn Platform>,
    handed_over: Mutex<Option<Vec<SocketAddr>>>,
    refreshed: Mutex<Option<Refreshed>>,
    blacklist: Mutex<Vec<IpAddr>>,
}

impl SystemServers {
    pub(crate) fn new(platform: Arc<dyn Platform>) -> Self {
        SystemServers {
            platform,
            handed_over: Mutex::new(None),
            refreshed: Mutex::new(None),
            blacklist: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn set(&self, servers: Vec<SocketAddr>) {
        {
            let mut slot = lock(&self.handed_over);
            *slot = Some(servers);
        }
        self.flush();
    }

    pub(crate) fn set_blacklist(&self, ips: Vec<IpAddr>) {
        {
            let mut slot = lock(&self.blacklist);
            *slot = ips;
        }
        self.flush();
    }

    pub(crate) fn flush(&self) {
        {
            let mut slot = lock(&self.refreshed);
            *slot = None;
        }
    }

    pub(crate) fn servers(&self) -> Vec<SocketAddr> {
        if let Some(servers) = lock(&self.handed_over).as_ref() {
            return servers.clone();
        }
        let mut cached = lock(&self.refreshed);
        if let Some(fresh) = cached.as_ref()
            && fresh.at.elapsed() < REFRESH
        {
            return fresh.servers.clone();
        }
        let blocked = lock(&self.blacklist).clone();
        let servers: Vec<SocketAddr> = self
            .platform
            .system_dns()
            .into_iter()
            .filter(|addr| !blocked.contains(&addr.ip()))
            .collect();
        if !servers.is_empty() {
            *cached = Some(Refreshed {
                at: Instant::now(),
                servers: servers.clone(),
            });
        }
        servers
    }
}

pub(crate) struct SystemClient {
    servers: Arc<SystemServers>,
    shared: Arc<Shared>,
    default_ns: Vec<SocketAddr>,
    clients: Mutex<HashMap<SocketAddr, ClientRef>>,
}

impl SystemClient {
    pub(crate) fn new(
        servers: Arc<SystemServers>,
        shared: Arc<Shared>,
        default_ns: Vec<SocketAddr>,
    ) -> Self {
        SystemClient {
            servers,
            shared,
            default_ns,
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn current(&self) -> (Vec<ClientRef>, bool) {
        let mut addrs = self.servers.servers();
        let mut fallback = false;
        if addrs.is_empty() && !self.default_ns.is_empty() {
            addrs = self.default_ns.clone();
            fallback = true;
        }
        let mut cache = lock(&self.clients);
        let clients = addrs
            .iter()
            .map(|addr| {
                cache
                    .entry(*addr)
                    .or_insert_with(|| {
                        let connector =
                            Arc::new(Connector::new(Arc::clone(&self.shared), Via::Direct, None));
                        Arc::new(PlainClient::new(
                            Transport::Udp,
                            addr.ip().to_string(),
                            addr.port(),
                            connector,
                        ))
                    })
                    .clone()
            })
            .collect();
        cache.retain(|addr, _| addrs.contains(addr));
        (clients, fallback)
    }
}

#[async_trait]
impl Client for SystemClient {
    async fn exchange(&self, req: &Message, cx: Cx) -> io::Result<Message> {
        let (clients, _) = self.current();
        if clients.is_empty() {
            return Err(io::Error::other("no system DNS servers"));
        }
        batch_exchange(&clients, req, cx)
            .await
            .map(|batch| batch.msg)
    }

    fn address(&self) -> String {
        let (clients, fallback) = self.current();
        let tag = if fallback { "[defaultNS]" } else { "" };
        let list: Vec<String> = clients.iter().map(|client| client.address()).collect();
        format!("system{tag}({})", list.join(","))
    }
}
