use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use crate::{Address, BoxStream, FlowMeta, Host, InboundKind};
use async_trait::async_trait;

#[derive(Clone, Debug)]
pub struct InterceptFlow {
    pub meta: FlowMeta,
    pub host: Option<Host>,
    pub sniffed: bool,
    pub dst_ip: Option<IpAddr>,
    pub port: u16,
}

impl InterceptFlow {
    pub fn is_inner(&self) -> bool {
        self.meta.inbound.kind == InboundKind::Inner
    }

    /// The core's own requests and the host's, which are never intercepted.
    pub fn is_own(&self) -> bool {
        self.is_inner() || self.meta.inbound.host
    }

    pub fn retarget(&self, host: &str, port: u16) -> Self {
        let target = Address::new(host, port);
        let (host, dst_ip) = match &target {
            Address::Socket(addr) => (None, Some(addr.ip())),
            Address::Domain(name, _) => (Some(name.clone()), None),
        };
        let mut meta = self.meta.clone();
        meta.dst = target;
        InterceptFlow {
            meta,
            host,
            sniffed: false,
            dst_ip,
            port,
        }
    }
}

pub enum Offer {
    Taken,
    /// `head` is every byte read from `stream`, to replay ahead of it.
    Declined {
        stream: BoxStream,
        head: Vec<u8>,
    },
}

#[async_trait]
pub trait ConnInterceptor: Send + Sync {
    async fn offer(&self, flow: &InterceptFlow, stream: BoxStream, head: Vec<u8>) -> Offer;

    fn drop_quic(&self, flow: &InterceptFlow) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnMark {
    Plain,
    Decrypted,
    Refused,
}

/// Dropped without a release, it lists as `ConnMark::Plain`.
pub trait HeldConn: Send + Sync {
    fn id(&self) -> &str;
    fn release(&self, mark: ConnMark);
}

pub struct UpstreamRequest {
    pub flow: InterceptFlow,
    /// Keep the connection out of the table until `Upstream::held` is released.
    pub hold: bool,
}

pub struct Upstream {
    pub stream: BoxStream,
    pub id: Option<Arc<str>>,
    pub held: Option<Arc<dyn HeldConn>>,
}

#[derive(Clone, Debug)]
pub struct RuleLabel {
    pub name: Arc<str>,
    pub payload: Arc<str>,
}

#[derive(Debug)]
pub struct DialFailure {
    pub chain: Vec<Arc<str>>,
    pub rule: Option<RuleLabel>,
    pub error: io::Error,
}

impl From<io::Error> for DialFailure {
    fn from(error: io::Error) -> Self {
        DialFailure {
            chain: Vec::new(),
            rule: None,
            error,
        }
    }
}

#[async_trait]
pub trait UpstreamDialer: Send + Sync {
    async fn dial(&self, request: UpstreamRequest) -> Result<Upstream, DialFailure>;

    /// Lists a closed `mitm` connection for a request that went out on none of its own.
    fn record_closed(
        &self,
        flow: &InterceptFlow,
        chain: &[Arc<str>],
        rule: Option<&RuleLabel>,
    ) -> Option<Arc<str>>;
}
