use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use concord_common::sync::lock;
use concord_common::{Address, HostResolver, Initiator, IpVersion, PacketBuf, PacketSession};

use super::Shared;
use super::config::WgConfig;
use super::stack::UdpPort;
use super::tunnel::Tunnel;

type Lookup = Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send>>;

struct Resolving {
    host: String,
    lookup: Lookup,
}

/// UDP through the tunnel. A destination given by name is resolved once per name,
/// the way Go resolves it before it hands the packet to the tunnel.
pub(super) struct WgSession {
    port: UdpPort,
    tunnel: Arc<Tunnel>,
    shared: Arc<Shared>,
    resolver: Arc<dyn HostResolver>,
    initiator: Initiator,
    names: Mutex<HashMap<String, IpAddr>>,
    pending: Mutex<Option<Resolving>>,
    closed: AtomicBool,
}

fn lookup(
    tunnel: Arc<Tunnel>,
    shared: Arc<Shared>,
    resolver: Arc<dyn HostResolver>,
    host: String,
    initiator: Initiator,
) -> Lookup {
    Box::pin(async move {
        tunnel
            .resolve(
                &shared.config,
                &*resolver,
                &host,
                shared.egress.version(),
                initiator,
            )
            .await
    })
}

impl WgSession {
    pub(super) fn new(
        tunnel: Arc<Tunnel>,
        shared: Arc<Shared>,
        resolver: Arc<dyn HostResolver>,
        initiator: Initiator,
    ) -> io::Result<Self> {
        Ok(WgSession {
            port: tunnel.udp()?,
            tunnel,
            shared,
            resolver,
            initiator,
            names: Mutex::new(HashMap::new()),
            pending: Mutex::new(None),
            closed: AtomicBool::new(false),
        })
    }

    pub(super) async fn seed(
        &self,
        host: &str,
        resolver: &dyn HostResolver,
        initiator: Initiator,
        config: &WgConfig,
        version: IpVersion,
    ) -> io::Result<()> {
        let ip = self
            .tunnel
            .resolve(config, resolver, host, version, initiator)
            .await?;
        lock(&self.names).insert(host.to_string(), ip);
        Ok(())
    }

    fn poll_target(&self, cx: &mut Context<'_>, dst: &Address) -> Poll<io::Result<SocketAddr>> {
        let (host, port) = match dst {
            Address::Socket(addr) => return Poll::Ready(Ok(*addr)),
            Address::Domain(host, port) => (host.as_str(), *port),
        };
        if let Some(ip) = lock(&self.names).get(host) {
            return Poll::Ready(Ok(SocketAddr::new(*ip, port)));
        }
        let mut pending = lock(&self.pending);
        if pending.as_ref().is_none_or(|current| current.host != host) {
            *pending = Some(Resolving {
                host: host.to_string(),
                lookup: lookup(
                    self.tunnel.clone(),
                    self.shared.clone(),
                    self.resolver.clone(),
                    host.to_string(),
                    self.initiator,
                ),
            });
        }
        let Some(current) = pending.as_mut() else {
            return Poll::Pending;
        };
        let result = ready!(current.lookup.as_mut().poll(cx));
        *pending = None;
        let ip = result?;
        lock(&self.names).insert(host.to_string(), ip);
        Poll::Ready(Ok(SocketAddr::new(ip, port)))
    }
}

impl PacketSession for WgSession {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let target = ready!(self.poll_target(cx, dst))?;
        self.port.poll_send_to(cx, pkt.as_slice(), target)
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let (n, from) = ready!(self.port.poll_recv_from(cx, buf.spare_mut()))?;
        buf.advance(n);
        Poll::Ready(Ok(Address::from(from)))
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}
