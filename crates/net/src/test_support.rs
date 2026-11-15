#![allow(
    clippy::disallowed_methods,
    reason = "tests talk to loopback listeners and sockets directly"
)]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, DialCx, DialEnv, HostResolver, Initiator, IpVersion, LookupIps, NodeDialer,
    NullSink, PacketSession, RawSocket, SockOpts, SocketFactory, io_error,
};
use concord_common::{FlowKey, ProcessInfo};
use concord_platform::{InterfaceInfo, Platform, SocketIdentity};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Default)]
pub struct FakePlatform {
    pub protected: Mutex<Vec<RawSocket>>,
    pub pressure: AtomicBool,
    pub default_if: Mutex<Option<InterfaceInfo>>,
    pub protect_delay_ms: AtomicU64,
    /// Refuses `protect`, as Android does while no VPN is established.
    pub refuse: AtomicBool,
    /// The inode of each socket protected, read during the call.
    pub protected_inodes: Mutex<Vec<Option<u64>>>,
}

#[async_trait]
impl Platform for FakePlatform {
    fn protect(&self, socket: RawSocket) -> bool {
        let delay = self.protect_delay_ms.load(Ordering::Relaxed);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
        if self.refuse.load(Ordering::SeqCst) {
            return false;
        }
        lock(&self.protected_inodes).push(SocketIdentity::Inode.of(socket));
        lock(&self.protected).push(socket);
        true
    }

    async fn find_owner(&self, _flow: &FlowKey) -> Option<ProcessInfo> {
        None
    }

    fn default_interface(&self) -> Option<InterfaceInfo> {
        lock(&self.default_if).clone()
    }

    fn system_dns(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    fn fd_pressure(&self) -> bool {
        self.pressure.load(Ordering::Relaxed)
    }
}

pub async fn connect(addr: SocketAddr) -> TcpStream {
    TcpStream::connect(addr).await.unwrap()
}

pub async fn loopback_listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

pub async fn loopback_pair() -> (TcpStream, TcpStream) {
    let (listener, addr) = loopback_listener().await;
    let (client, accepted) = tokio::join!(connect(addr), listener.accept());
    (client, accepted.unwrap().0)
}

pub async fn loopback_udp() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

#[derive(Default)]
pub struct MapResolver {
    pub hosts: Mutex<HashMap<String, LookupIps>>,
    pub lookups: AtomicU64,
}

impl MapResolver {
    pub fn with(host: &str, v4: &[&str], v6: &[&str]) -> Arc<Self> {
        let resolver = Arc::new(MapResolver::default());
        lock(&resolver.hosts).insert(
            host.to_string(),
            LookupIps {
                v4: v4.iter().map(|ip| ip.parse().unwrap()).collect(),
                v6: v6.iter().map(|ip| ip.parse().unwrap()).collect(),
            },
        );
        resolver
    }
}

#[async_trait]
impl HostResolver for MapResolver {
    async fn lookup(
        &self,
        host: &str,
        _version: IpVersion,
        _initiator: Initiator,
    ) -> io::Result<LookupIps> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        lock(&self.hosts)
            .get(host)
            .cloned()
            .ok_or_else(|| io_error(format!("no such host {host}")))
    }
}

struct NoNodes;

#[async_trait]
impl NodeDialer for NoNodes {
    async fn dial_via(
        &self,
        name: &str,
        _cx: &DialCx<'_>,
        _dst: &Address,
    ) -> io::Result<BoxStream> {
        Err(io_error(format!("no node {name}")))
    }

    async fn associate_via(
        &self,
        name: &str,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Err(io_error(format!("no node {name}")))
    }
}

pub fn env(
    sockets: Arc<dyn SocketFactory>,
    resolver: Arc<dyn HostResolver>,
    tcp_concurrent: bool,
    ipv6: bool,
) -> DialEnv {
    DialEnv {
        sockets,
        resolver,
        nodes: Arc::new(NoNodes),
        events: Arc::new(NullSink),
        sock_opts: SockOpts::default(),
        tcp_concurrent,
        ipv6,
    }
}

/// Answers each target from a script of delay and outcome, so races are decided by
/// the clock rather than by the network. A scripted success hands out a pre-made
/// loopback connection whose far end the test keeps.
pub struct ScriptedSockets {
    script: Mutex<HashMap<IpAddr, (Duration, Option<TcpStream>)>>,
    pub attempts: Mutex<Vec<IpAddr>>,
}

impl ScriptedSockets {
    pub fn new() -> Self {
        ScriptedSockets {
            script: Mutex::new(HashMap::new()),
            attempts: Mutex::new(Vec::new()),
        }
    }

    pub fn succeed(&self, ip: &str, after: Duration) -> TcpStream {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.set_nonblocking(true).unwrap();
        server.set_nonblocking(true).unwrap();
        lock(&self.script).insert(
            ip.parse().unwrap(),
            (after, Some(TcpStream::from_std(client).unwrap())),
        );
        TcpStream::from_std(server).unwrap()
    }

    pub fn fail(&self, ip: &str, after: Duration) {
        lock(&self.script).insert(ip.parse().unwrap(), (after, None));
    }
}

#[async_trait]
impl SocketFactory for ScriptedSockets {
    async fn connect_tcp(&self, target: SocketAddr, _opts: &SockOpts) -> io::Result<TcpStream> {
        lock(&self.attempts).push(target.ip());
        let (delay, stream) = {
            let mut script = lock(&self.script);
            match script.get_mut(&target.ip()) {
                Some((delay, stream)) => (*delay, stream.take()),
                None => (Duration::ZERO, None),
            }
        };
        tokio::time::sleep(delay).await;
        stream.ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))
    }

    fn bind_udp(&self, _peer: IpAddr, _opts: &SockOpts) -> io::Result<UdpSocket> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}
