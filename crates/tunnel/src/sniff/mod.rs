#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::IpAddr;

mod bitmap;
mod dispatcher;
mod error;
mod hpack;
mod hpack_tables;
mod http;
mod quic;
mod quic_crypto;
mod skip_list;
mod tls;

#[cfg(test)]
mod testdata;
#[cfg(test)]
mod testkit;

pub use dispatcher::{
    Dispatcher, DispatcherConfig, SniffTarget, SnifferEntry, SnifferKind, UdpSniff,
};
pub use quic::{QUIC_WAIT, QuicSniffer};

pub trait DomainMatch: Send + Sync {
    fn matches(&self, domain: &str) -> bool;
}

pub trait IpMatch: Send + Sync {
    fn matches(&self, ip: IpAddr) -> bool;
}
