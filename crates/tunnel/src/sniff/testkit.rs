use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use concord_common::{DnsMode, Host};

use super::{DomainMatch, IpMatch, SniffTarget};

pub fn make_client_hello(host: &str, padding_len: usize) -> Vec<u8> {
    let mut extensions = Vec::new();
    if !host.is_empty() {
        let name = host.as_bytes();
        let list_len = 1 + 2 + name.len();
        let data_len = 2 + list_len;
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&(data_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(list_len as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(name);
    }
    if padding_len > 0 {
        extensions.extend_from_slice(&0x15u16.to_be_bytes());
        extensions.extend_from_slice(&(padding_len as u16).to_be_bytes());
        extensions.extend(std::iter::repeat_n(0u8, padding_len));
    }

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut hello = vec![
        1,
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    hello.extend_from_slice(&body);
    hello
}

pub fn make_tls_records(handshake: &[u8], cuts: &[usize]) -> Vec<u8> {
    let mut records = Vec::new();
    let mut start = 0;
    for &end in cuts.iter().chain(std::iter::once(&handshake.len())) {
        let payload = &handshake[start..end];
        records.extend_from_slice(&[0x16, 0x03, 0x01]);
        records.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        records.extend_from_slice(payload);
        start = end;
    }
    records
}

pub struct MatchFn<F>(pub F);

impl<F: Fn(&str) -> bool + Send + Sync> DomainMatch for MatchFn<F> {
    fn matches(&self, domain: &str) -> bool {
        (self.0)(domain)
    }
}

pub struct IpFn<F>(pub F);

impl<F: Fn(IpAddr) -> bool + Send + Sync> IpMatch for IpFn<F> {
    fn matches(&self, ip: IpAddr) -> bool {
        (self.0)(ip)
    }
}

pub fn always() -> Arc<dyn DomainMatch> {
    Arc::new(MatchFn(|_: &str| true))
}

#[derive(Default)]
pub struct Meta {
    pub host: Option<Host>,
    pub dst_ip: Option<IpAddr>,
    pub src_ip: Option<IpAddr>,
    pub dns_mode: Option<DnsMode>,
    pub sniff_host: Option<Host>,
    pub dst_port: u16,
}

impl Meta {
    pub fn new(dst_port: u16) -> Self {
        Meta {
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            dst_port,
            ..Default::default()
        }
    }

    pub fn target(&mut self) -> SniffTarget<'_> {
        SniffTarget {
            host: &mut self.host,
            dst_ip: &mut self.dst_ip,
            src_ip: self
                .src_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            dst_port: self.dst_port,
            dns_mode: &mut self.dns_mode,
            sniff_host: &mut self.sniff_host,
        }
    }
}

pub type Seen = Arc<Mutex<Vec<usize>>>;
