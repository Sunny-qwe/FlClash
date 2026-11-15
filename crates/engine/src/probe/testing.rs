use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{Address, RouteStamp};
use concord_tls::TrustStore;
use futures_util::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{Dialed, ProbeEnv, Prober};

pub struct FakeEnv {
    pub known: Mutex<Vec<String>>,
    pub stamp: Mutex<RouteStamp>,
    pub suspended: AtomicBool,
    pub trust: Mutex<Arc<TrustStore>>,
    pub dials: Mutex<Vec<(String, Option<String>)>>,
    pub hosts: Mutex<HashMap<String, SocketAddr>>,
    pub refuse: AtomicBool,
}

impl FakeEnv {
    pub fn new(known: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            known: Mutex::new(known.iter().map(ToString::to_string).collect()),
            stamp: Mutex::new(RouteStamp::default()),
            suspended: AtomicBool::new(false),
            trust: Mutex::new(TrustStore::from_parts(Vec::new(), b"", Vec::new())),
            dials: Mutex::new(Vec::new()),
            hosts: Mutex::new(HashMap::new()),
            refuse: AtomicBool::new(false),
        })
    }

    pub fn prober(self: &Arc<Self>) -> Prober {
        Prober::new(self.clone())
    }

    pub fn set_stamp(&self, epoch: u64, version: u64) {
        *lock(&self.stamp) = RouteStamp { epoch, version };
    }
}

pub fn exit_name(name: &str) -> String {
    format!("{name:?} Test {name}.example:1")
}

#[async_trait]
impl ProbeEnv for FakeEnv {
    #[allow(clippy::disallowed_methods, reason = "loopback test server")]
    async fn dial(&self, target: &Address, proxy: Option<&str>) -> io::Result<Dialed> {
        lock(&self.dials).push((target.to_string(), proxy.map(str::to_string)));
        if self.refuse.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"));
        }
        let addr = match target {
            Address::Socket(addr) => *addr,
            Address::Domain(..) => *lock(&self.hosts)
                .get(&target.to_string())
                .ok_or_else(|| io::Error::other("unmapped host"))?,
        };
        let stream = TcpStream::connect(addr).await?;
        let chains = match proxy {
            Some(name) if name.starts_with("group-") => {
                vec![format!("node-of-{name}"), name.to_string()]
            }
            Some(name) => vec![name.to_string()],
            None => vec!["DIRECT".to_string()],
        };
        Ok(Dialed {
            stream: Box::new(stream),
            chains,
        })
    }

    fn knows(&self, proxy: &str) -> bool {
        lock(&self.known).iter().any(|known| known == proxy)
    }

    fn exit_through(&self, _target: &str, proxy: Option<&str>) -> Option<String> {
        let name = proxy.unwrap_or("DIRECT");
        if proxy.is_some() && !self.knows(name) {
            return None;
        }
        Some(exit_name(name))
    }

    fn exit_of_chains(&self, chains: &[String]) -> Option<String> {
        let balancer = chains
            .iter()
            .skip(1)
            .rev()
            .find(|name| name.starts_with("lb-"));
        Some(exit_name(balancer.or(chains.first())?))
    }

    fn stamp(&self) -> RouteStamp {
        *lock(&self.stamp)
    }

    fn trust(&self) -> Arc<TrustStore> {
        lock(&self.trust).clone()
    }

    fn suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Debug, Default)]
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay: Duration,
}

impl Resp {
    pub fn ok(body: &str) -> Self {
        Self {
            status: 200,
            body: body.as_bytes().to_vec(),
            ..Self::default()
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

pub type Handler = Arc<dyn Fn(Req) -> BoxFuture<'static, Resp> + Send + Sync>;

pub fn handler<F>(f: F) -> Handler
where
    F: Fn(Req) -> Resp + Send + Sync + 'static,
{
    Arc::new(move |req| {
        let resp = f(req);
        Box::pin(async move {
            tokio::time::sleep(resp.delay).await;
            resp
        })
    })
}

/// A loopback HTTP/1.1 server answering every request on its own connection.
pub struct Server {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<Req>>>,
}

impl Server {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

#[allow(clippy::disallowed_methods, reason = "loopback test server")]
pub async fn serve(handler: Handler) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(answer(stream, handler.clone(), log.clone()));
        }
    });
    Server { addr, requests }
}

pub async fn serve_fn<F>(f: F) -> Server
where
    F: Fn(Req) -> Resp + Send + Sync + 'static,
{
    serve(handler(f)).await
}

async fn answer(mut stream: TcpStream, handler: Handler, log: Arc<Mutex<Vec<Req>>>) {
    let Some(req) = read_request(&mut stream).await else {
        return;
    };
    lock(&log).push(req.clone());
    let resp = handler(req).await;
    let mut out = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", resp.status);
    for (name, value) in &resp.headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", resp.body.len()));
    let _ = stream.write_all(out.as_bytes()).await;
    let _ = stream.write_all(&resp.body).await;
    let _ = stream.shutdown().await;
}

async fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.ok()?;
    Some(Req {
        method,
        path,
        headers,
        body,
    })
}
