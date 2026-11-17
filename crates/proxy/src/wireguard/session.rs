use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use concord_common::{HostResolver, Initiator};

use super::Shared;
use super::stack::{SessionTunnel, StackSession};
use super::tunnel::Tunnel;

pub(super) struct WgUdp {
    tunnel: Arc<Tunnel>,
    shared: Arc<Shared>,
    resolver: Arc<dyn HostResolver>,
    initiator: Initiator,
}

impl SessionTunnel for WgUdp {
    const RELEASE_ON_CLOSE: bool = false;

    fn resolve(&self, host: String) -> impl Future<Output = io::Result<IpAddr>> + Send + 'static {
        let tunnel = self.tunnel.clone();
        let shared = self.shared.clone();
        let resolver = self.resolver.clone();
        let initiator = self.initiator;
        async move {
            tunnel
                .resolve(
                    &shared.config,
                    &*resolver,
                    &host,
                    shared.egress.version(),
                    initiator,
                )
                .await
        }
    }

    fn usable(&self) -> bool {
        true
    }
}

pub(super) fn open(
    tunnel: Arc<Tunnel>,
    shared: Arc<Shared>,
    resolver: Arc<dyn HostResolver>,
    initiator: Initiator,
) -> io::Result<StackSession<WgUdp>> {
    Ok(StackSession::new(
        tunnel.udp()?,
        WgUdp {
            tunnel,
            shared,
            resolver,
            initiator,
        },
    ))
}
