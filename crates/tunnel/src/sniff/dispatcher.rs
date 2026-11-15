use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{DnsMode, Host};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout_at};

use super::error::SniffError;
use super::http::HttpSniffer;
use super::quic::QuicSniffer;
use super::skip_list::{FAILURES_BEFORE_SKIP, SkipKey, SkipList};
use super::tls::TlsSniffer;
use super::{DomainMatch, IpMatch};

/// Bounds the per-connection read-ahead: it covers the HTTP/2 preface and
/// several default-sized frames while keeping lengths read from untrusted
/// headers bounded.
const MAX_SNIFF_BUFFER: usize = 64 * 1024;
const READ_CHUNK: usize = 4096;
const FIRST_BYTE_WAIT: Duration = Duration::from_secs(1);
const SNIFF_WAIT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SnifferKind {
    Tls,
    Http,
    Quic,
}

impl SnifferKind {
    fn default_port(self) -> u16 {
        match self {
            SnifferKind::Tls | SnifferKind::Quic => 443,
            SnifferKind::Http => 80,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SnifferEntry {
    pub kind: SnifferKind,
    /// Inclusive ranges; empty means the protocol default.
    pub ports: Vec<(u16, u16)>,
    pub override_dest: bool,
}

#[derive(Default)]
pub struct DispatcherConfig {
    pub enable: bool,
    /// Order-free: the dispatcher tries them as TLS, HTTP, QUIC.
    pub sniffers: Vec<SnifferEntry>,
    pub force_domain: Vec<Arc<dyn DomainMatch>>,
    pub skip_domain: Vec<Arc<dyn DomainMatch>>,
    pub skip_src: Vec<Arc<dyn IpMatch>>,
    pub skip_dst: Vec<Arc<dyn IpMatch>>,
    pub force_dns_mapping: bool,
    pub parse_pure_ip: bool,
}

/// The parts of the connection metadata a sniffer reads and rewrites.
pub struct SniffTarget<'a> {
    pub host: &'a mut Option<Host>,
    pub dst_ip: &'a mut Option<IpAddr>,
    pub src_ip: IpAddr,
    pub dst_port: u16,
    pub dns_mode: &'a mut Option<DnsMode>,
    pub sniff_host: &'a mut Option<Host>,
}

impl SniffTarget<'_> {
    fn host_str(&self) -> &str {
        self.host.as_deref().unwrap_or_default()
    }
}

pub enum UdpSniff {
    Done,
    Quic(Box<QuicSniffer>),
}

pub(super) trait DataSniffer: Send + Sync {
    /// A [`SniffError::NeedAtLeast`] asks for a longer prefix; any other error
    /// rejects the connection for this protocol.
    fn sniff(&self, data: &[u8]) -> Result<String, SniffError>;
}

enum Transport {
    Stream(Box<dyn DataSniffer>),
    Quic,
}

struct Configured {
    ports: Vec<(u16, u16)>,
    override_dest: bool,
    transport: Transport,
}

impl Configured {
    fn supports_port(&self, port: u16) -> bool {
        self.ports
            .iter()
            .any(|&(low, high)| low <= port && port <= high)
    }
}

pub(super) struct Policy {
    force_domain: Vec<Arc<dyn DomainMatch>>,
    skip_domain: Vec<Arc<dyn DomainMatch>>,
    skip_src: Vec<Arc<dyn IpMatch>>,
    skip_dst: Vec<Arc<dyn IpMatch>>,
    force_dns_mapping: bool,
    parse_pure_ip: bool,
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

impl Policy {
    fn should_override(&self, target: &SniffTarget<'_>) -> bool {
        if let Some(ip) = (*target.dst_ip).map(unmap)
            && self.skip_dst.iter().any(|m| m.matches(ip))
        {
            return false;
        }
        let src = unmap(target.src_ip);
        if self.skip_src.iter().any(|m| m.matches(src)) {
            return false;
        }
        if target.host_str().is_empty() && self.parse_pure_ip {
            return true;
        }
        if *target.dns_mode == Some(DnsMode::RedirHost) && self.force_dns_mapping {
            return true;
        }
        self.force_sniff(target)
    }

    fn force_sniff(&self, target: &SniffTarget<'_>) -> bool {
        let host = target.host_str();
        self.force_domain.iter().any(|m| m.matches(host))
    }

    pub(super) fn domain_can_replace(&self, host: &str) -> bool {
        is_valid_sniff_host(host) && !self.skip_domain.iter().any(|m| m.matches(host))
    }

    #[cfg(test)]
    pub(super) fn permissive() -> Arc<Policy> {
        Arc::new(Policy {
            force_domain: Vec::new(),
            skip_domain: Vec::new(),
            skip_src: Vec::new(),
            skip_dst: Vec::new(),
            force_dns_mapping: false,
            parse_pure_ip: true,
        })
    }
}

pub(super) fn replace_domain(target: &mut SniffTarget<'_>, host: &str, override_dest: bool) {
    *target.sniff_host = Some(Host::from(host));
    if override_dest {
        tracing::debug!(
            from = target.host_str(),
            to = host,
            "[Sniffer] sniff success, replace domain"
        );
        *target.host = Some(Host::from(host));
        *target.dst_ip = None;
    }
    *target.dns_mode = Some(DnsMode::Normal);
}

fn is_valid_sniff_host(host: &str) -> bool {
    host != "." && is_domain_name(host)
}

/// Go's `net.isDomainName`.
pub(super) fn is_domain_name(s: &str) -> bool {
    if s == "." {
        return true;
    }
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len == 0 || len > 254 || len == 254 && bytes.last() != Some(&b'.') {
        return false;
    }

    let mut last = b'.';
    let mut non_numeric = false;
    let mut part_len = 0usize;
    for &c in bytes {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part_len += 1;
            }
            b'0'..=b'9' => part_len += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part_len += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || part_len > 63 || part_len == 0 {
                    return false;
                }
                part_len = 0;
            }
            _ => return false,
        }
        last = c;
    }
    last != b'-' && part_len <= 63 && non_numeric
}

struct Candidate<'a> {
    sniffer: &'a dyn DataSniffer,
    override_dest: bool,
    /// The minimum buffer length before the next attempt.
    want: usize,
}

pub struct Dispatcher {
    enable: bool,
    sniffers: Vec<Configured>,
    policy: Arc<Policy>,
    skip_list: Mutex<SkipList>,
}

impl Dispatcher {
    pub fn new(config: DispatcherConfig) -> Self {
        let mut sniffers = Vec::new();
        for kind in [SnifferKind::Tls, SnifferKind::Http, SnifferKind::Quic] {
            let Some(entry) = config.sniffers.iter().rfind(|e| e.kind == kind) else {
                continue;
            };
            let ports = if entry.ports.is_empty() {
                vec![(kind.default_port(), kind.default_port())]
            } else {
                entry
                    .ports
                    .iter()
                    .map(|&(a, b)| (a.min(b), a.max(b)))
                    .collect()
            };
            let transport = match kind {
                SnifferKind::Tls => Transport::Stream(Box::new(TlsSniffer)),
                SnifferKind::Http => Transport::Stream(Box::new(HttpSniffer)),
                SnifferKind::Quic => Transport::Quic,
            };
            sniffers.push(Configured {
                ports,
                override_dest: entry.override_dest,
                transport,
            });
        }

        Dispatcher {
            enable: config.enable,
            sniffers,
            policy: Arc::new(Policy {
                force_domain: config.force_domain,
                skip_domain: config.skip_domain,
                skip_src: config.skip_src,
                skip_dst: config.skip_dst,
                force_dns_mapping: config.force_dns_mapping,
                parse_pure_ip: config.parse_pure_ip,
            }),
            skip_list: Mutex::new(SkipList::default()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enable
    }

    /// Reads ahead from `stream` into `head` (at most 64 KiB) and writes a
    /// sniffed domain to `target`. The caller replays `head` afterwards, also
    /// when this returns false.
    pub async fn sniff_tcp<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        head: &mut Vec<u8>,
        target: &mut SniffTarget<'_>,
    ) -> bool {
        if !self.policy.should_override(target) {
            return false;
        }
        let in_whitelist = self.sniffers.iter().any(|c| {
            matches!(c.transport, Transport::Stream(_)) && c.supports_port(target.dst_port)
        });
        if !in_whitelist {
            return false;
        }

        let force = self.policy.force_sniff(target);
        let dst: SkipKey = (*target.dst_ip, target.dst_port);
        if !force
            && self
                .skip_list()
                .get(&dst)
                .is_some_and(|failures| failures > FAILURES_BEFORE_SKIP)
        {
            tracing::debug!(?dst, "[Sniffer] skip sniffing due to multiple failures");
            return false;
        }

        let (host, override_dest) = match self.sniff_domain(stream, head, target.dst_port).await {
            Ok(found) => found,
            Err(err) => {
                if !force {
                    self.skip_list().record_failure(dst);
                }
                tracing::debug!(?dst, %err, "[Sniffer] all sniffing failed");
                return false;
            }
        };

        if !self.policy.domain_can_replace(&host) {
            tracing::debug!(host, "[Sniffer] skip sni");
            return false;
        }

        self.skip_list().delete(&dst);
        replace_domain(target, &host, override_dest);
        true
    }

    /// Call with the first datagram of a new UDP flow, which is fed to the
    /// sniffer here and must not be fed again. See [`QuicSniffer`] for the
    /// rest of the sequence.
    pub fn sniff_udp(&self, first_packet: &[u8], target: &mut SniffTarget<'_>) -> UdpSniff {
        if !self.policy.should_override(target) {
            return UdpSniff::Done;
        }
        let Some(quic) = self
            .sniffers
            .iter()
            .find(|c| matches!(c.transport, Transport::Quic) && c.supports_port(target.dst_port))
        else {
            return UdpSniff::Done;
        };

        let mut sniffer = QuicSniffer::new(self.policy.clone(), quic.override_dest);
        sniffer.feed(first_packet);
        if sniffer.finished() {
            sniffer.apply(target);
            return UdpSniff::Done;
        }
        UdpSniff::Quic(Box::new(sniffer))
    }

    fn skip_list(&self) -> std::sync::MutexGuard<'_, SkipList> {
        lock(&self.skip_list)
    }

    async fn sniff_domain<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        head: &mut Vec<u8>,
        dst_port: u16,
    ) -> Result<(String, bool), SniffError> {
        let mut candidates: Vec<Candidate<'_>> = self
            .sniffers
            .iter()
            .filter(|c| c.supports_port(dst_port))
            .filter_map(|c| match &c.transport {
                Transport::Stream(sniffer) => Some(Candidate {
                    sniffer: sniffer.as_ref(),
                    override_dest: c.override_dest,
                    want: 1,
                }),
                Transport::Quic => None,
            })
            .collect();
        if candidates.is_empty() {
            return Err(SniffError::AllFailed);
        }

        // Client data may not have arrived yet, so the first byte gets its own
        // window; the candidates and retries then share a fresh one.
        peek(stream, head, 1, Instant::now() + FIRST_BYTE_WAIT).await?;
        let deadline = Instant::now() + SNIFF_WAIT;
        let mut want = head.len();
        while !candidates.is_empty() {
            if want > MAX_SNIFF_BUFFER && want > head.len() {
                return Err(SniffError::BufferFull);
            }
            peek(stream, head, want, deadline).await?;

            let data = head.as_slice();
            let mut found = None;
            let mut next_want = 0;
            candidates.retain_mut(|current| {
                if found.is_some() {
                    return false;
                }
                if current.want <= data.len() {
                    match current.sniffer.sniff(data) {
                        Ok(host) => {
                            if is_valid_sniff_host(&host) {
                                found = Some((host, current.override_dest));
                            }
                            return false;
                        }
                        // Only a request beyond this snapshot can make progress.
                        Err(SniffError::NeedAtLeast(length)) if length > data.len() => {
                            current.want = length;
                        }
                        Err(_) => return false,
                    }
                }
                if next_want == 0 || current.want < next_want {
                    next_want = current.want;
                }
                true
            });
            if let Some(found) = found {
                return Ok(found);
            }
            want = next_want;
        }
        Err(SniffError::AllFailed)
    }
}

/// Reads until `head` holds `want` bytes. Every read may take whatever is
/// available up to the buffer bound, like a buffered reader's fill.
async fn peek<S: AsyncRead + Unpin>(
    stream: &mut S,
    head: &mut Vec<u8>,
    want: usize,
    deadline: Instant,
) -> Result<(), SniffError> {
    while head.len() < want {
        let start = head.len();
        let room = (want - start)
            .max(READ_CHUNK)
            .min(MAX_SNIFF_BUFFER.saturating_sub(start));
        head.resize(start + room, 0);
        let read = timeout_at(
            deadline,
            stream.read(head.get_mut(start..).unwrap_or_default()),
        )
        .await;
        match read {
            Ok(Ok(n)) if n > 0 => head.truncate(start + n),
            _ => {
                head.truncate(start);
                return Err(SniffError::Read);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;
