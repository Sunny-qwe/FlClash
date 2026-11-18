use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use concord_common::{FlowHandler, Tasks};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::accept::accept_loop;
use crate::bind::{BindHost, BindKey, bind_tcp, bind_udp, resolve_host};
use crate::ctx::{HANDSHAKE_TIMEOUT, ListenCtx, Peer, Shared, unmap_addr};
use crate::spec::{Keepalive, ListenSpec, Policy};
use crate::transparent::{Transparent, handle_redir, handle_tproxy};
use crate::udp::{Associations, UdpOut};
use crate::{ListenError, ListenerKind};
use crate::{http, socks};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    pub kind: ListenerKind,
    pub addr: SocketAddr,
}

struct Running {
    key: BindKey,
    local: SocketAddr,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    async fn stop(self) {
        self.cancel.cancel();
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// Owns the accept tasks. Connections already accepted outlive their listener,
/// as they do when the Go core closes one, and end when the `Tasks` of the reconcile that
/// started the listener stop.
pub struct Listeners {
    shared: Arc<Shared>,
    transparent: Option<Arc<dyn Transparent>>,
    running: Mutex<HashMap<ListenerKind, Running>>,
}

impl Default for Listeners {
    fn default() -> Self {
        Self::new()
    }
}

impl Listeners {
    pub fn new() -> Self {
        Listeners {
            shared: Arc::new(Shared::new(Policy::from_spec(&ListenSpec::default()))),
            transparent: None,
            running: Mutex::new(HashMap::new()),
        }
    }

    pub fn native() -> Self {
        Self::with_transparent(Arc::new(crate::transparent::PlatformTransparent))
    }

    pub fn with_transparent(transparent: Arc<dyn Transparent>) -> Self {
        Listeners {
            transparent: Some(transparent),
            ..Self::new()
        }
    }

    /// Brings the listeners in line with `spec`. A port whose resolved bind
    /// address is unchanged keeps its socket and its connections; a changed one
    /// is closed first and then bound again; a port that cannot be bound is
    /// reported and leaves the others as they are. Auth, the allow and deny
    /// lists and the handler apply to every listener at once.
    pub async fn reconcile(
        &self,
        spec: &ListenSpec,
        handler: Arc<dyn FlowHandler>,
        tasks: Tasks,
    ) -> Vec<ListenError> {
        let mut running = self.running.lock().await;
        self.shared.update(handler, Policy::from_spec(spec));
        let host = resolve_host(spec.allow_lan, &spec.bind_address);
        let mut errors = Vec::new();
        for kind in ListenerKind::ALL {
            let Some(port) = spec.port(kind) else {
                if let Some(old) = running.remove(&kind) {
                    old.stop().await;
                }
                continue;
            };
            let host = match &host {
                Ok(host) => *host,
                Err(err) => {
                    if let Some(old) = running.remove(&kind) {
                        old.stop().await;
                    }
                    errors.push(ListenError::new(
                        kind,
                        spec.bind_address.clone(),
                        io::Error::new(err.kind(), err.to_string()),
                    ));
                    continue;
                }
            };
            let key = BindKey {
                host,
                port,
                mptcp: spec.mptcp && kind != ListenerKind::TProxy,
            };
            if running.get(&kind).is_some_and(|current| current.key == key) {
                continue;
            }
            if let Some(old) = running.remove(&kind) {
                old.stop().await;
            }
            match self.start(kind, key, &tasks) {
                Ok(started) => {
                    tracing::info!("{} proxy listening at: {}", kind.label(), started.local);
                    running.insert(kind, started);
                }
                Err(err) => {
                    let error = ListenError::new(kind, describe(&key), err);
                    tracing::error!("{error}");
                    errors.push(error);
                }
            }
        }
        errors
    }

    pub async fn stop_all(&self) {
        let stopped: Vec<Running> = self
            .running
            .lock()
            .await
            .drain()
            .map(|(_, run)| run)
            .collect();
        for run in stopped {
            run.stop().await;
        }
    }

    pub async fn bound(&self) -> Vec<Bound> {
        let running = self.running.lock().await;
        ListenerKind::ALL
            .into_iter()
            .filter_map(|kind| {
                running.get(&kind).map(|run| Bound {
                    kind,
                    addr: run.local,
                })
            })
            .collect()
    }

    fn start(&self, kind: ListenerKind, key: BindKey, tasks: &Tasks) -> io::Result<Running> {
        let transparent = match kind {
            ListenerKind::Redir | ListenerKind::TProxy => {
                Some(self.transparent.clone().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::Unsupported, "not supported on this platform")
                })?)
            }
            _ => None,
        };
        let tproxy = (kind == ListenerKind::TProxy)
            .then_some(transparent.as_deref())
            .flatten();
        let tcp = bind_tcp(&key, tproxy)?;
        let local = tcp.local_addr()?;
        let udp = kind
            .has_udp()
            .then(|| bind_udp(local, None))
            .transpose()?
            .map(|socket| UdpOut::new(Arc::new(socket), tasks.clone()));

        let ctx = Arc::new(ListenCtx {
            shared: self.shared.clone(),
            name: Arc::from(kind.inbound_name()),
            assoc: Arc::new(Associations::default()),
        });
        let cancel = CancellationToken::new();
        let mut running = Vec::new();
        if let Some(out) = udp {
            // mihomo serves a mixed port's UDP with its SOCKS listener, which names it
            // DEFAULT-SOCKS; the associations stay shared with the TCP side.
            let udp_ctx = Arc::new(ListenCtx {
                shared: self.shared.clone(),
                name: Arc::from(ListenerKind::Socks.inbound_name()),
                assoc: ctx.assoc.clone(),
            });
            running.push(tasks.spawn(crate::udp::run(udp_ctx, out, cancel.clone())));
        }
        if let Some(transparent) = transparent.clone().filter(|_| kind.has_transparent_udp()) {
            match bind_udp(local, Some(transparent.as_ref())) {
                Ok(socket) => {
                    let udp_ctx = Arc::new(ListenCtx {
                        shared: self.shared.clone(),
                        name: Arc::from(ListenerKind::TProxy.inbound_name()),
                        assoc: Arc::new(Associations::default()),
                    });
                    running.push(tasks.spawn(crate::tproxy_udp::run(
                        udp_ctx,
                        socket,
                        transparent,
                        cancel.clone(),
                        tasks.clone(),
                    )));
                }
                Err(err) => tracing::warn!("Failed to start {} UDP Listener: {err}", kind.label()),
            }
        }
        let accept_ctx = ctx;
        let connections = tasks.clone();
        running.push(
            tasks.spawn(accept_loop(tcp, cancel.clone(), move |stream, from| {
                connections.spawn(serve_conn(
                    kind,
                    accept_ctx.clone(),
                    stream,
                    from,
                    transparent.clone(),
                    local,
                ));
            })),
        );
        Ok(Running {
            key,
            local,
            cancel,
            tasks: running,
        })
    }
}

fn describe(key: &BindKey) -> String {
    match key.host {
        BindHost::Wildcard => format!(":{}", key.port),
        BindHost::Ip(ip) => SocketAddr::new(ip, key.port).to_string(),
    }
}

fn configure(stream: &TcpStream, keepalive: Option<Keepalive>) {
    let _ = stream.set_nodelay(true);
    if let Some(Keepalive { idle, interval }) = keepalive {
        let probe = TcpKeepalive::new().with_time(idle).with_interval(interval);
        let _ = SockRef::from(stream).set_tcp_keepalive(&probe);
    }
}

async fn first_byte(stream: &TcpStream) -> Option<u8> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) => Some(first[0]),
        _ => None,
    }
}

async fn serve_conn(
    kind: ListenerKind,
    ctx: Arc<ListenCtx>,
    stream: TcpStream,
    from: SocketAddr,
    transparent: Option<Arc<dyn Transparent>>,
    listener: SocketAddr,
) {
    let Ok(local) = stream.local_addr() else {
        return;
    };
    let peer = Peer {
        src: unmap_addr(from),
        local: unmap_addr(local),
    };
    let policy = ctx.shared.policy();
    let filtered = matches!(
        kind,
        ListenerKind::Mixed | ListenerKind::Http | ListenerKind::Socks
    );
    if filtered && !policy.admits(peer.src.ip()) {
        return;
    }
    configure(&stream, policy.keepalive);
    let auth = policy.authenticator(peer.src.ip());

    match kind {
        ListenerKind::Mixed => match first_byte(&stream).await {
            Some(4) => socks::handle_socks4(&ctx, stream, peer, auth).await,
            Some(5) => socks::handle_socks5(&ctx, stream, peer, auth).await,
            Some(_) => http::serve(ctx.clone(), stream, peer, auth).await,
            None => {}
        },
        ListenerKind::Http => http::serve(ctx.clone(), stream, peer, auth).await,
        ListenerKind::Socks => match first_byte(&stream).await {
            Some(4) => socks::handle_socks4(&ctx, stream, peer, auth).await,
            Some(5) => socks::handle_socks5(&ctx, stream, peer, auth).await,
            _ => {}
        },
        ListenerKind::Redir => {
            if let Some(transparent) = transparent {
                handle_redir(&ctx, stream, peer, transparent.as_ref()).await;
            }
        }
        ListenerKind::TProxy => handle_tproxy(&ctx, stream, peer, listener),
    }
}
