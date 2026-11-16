mod frame;
mod stream;
mod udp;

#[cfg(test)]
mod tests;

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{ProxyDef, SnellOpts};
use concord_transport::{Layer, ObfsMode, ObfsOptions, TransportStack};
use tokio::io::AsyncWriteExt;

use self::frame::{Scheme, Sealer};
use self::stream::SnellStream;
use self::udp::SnellPackets;
use crate::ctx::{BuildCtx, BuildError};
use crate::link::shadow_tls_layer;
use crate::node::{Link, info_for};

const PROTOCOL: u8 = 1;
const CONNECT: u8 = 1;
const CONNECT_V2: u8 = 5;
const UDP: u8 = 6;

struct Snell {
    info: OutboundInfo,
    link: Link,
    psk: Vec<u8>,
    version: u32,
    reuse: bool,
}

impl Snell {
    fn scheme(&self) -> Scheme {
        match self.version {
            1 => Scheme::Chacha,
            2 | 3 => Scheme::Aes,
            _ => Scheme::V4,
        }
    }
}

fn request(dst: &Address, command: u8) -> io::Result<Vec<u8>> {
    let host = match dst {
        Address::Domain(host, _) => host.to_string(),
        Address::Socket(addr) => addr.ip().to_string(),
    };
    let len = u8::try_from(host.len()).map_err(|_| io::Error::other("snell host too long"))?;
    let mut head = vec![PROTOCOL, command, 0, len];
    head.extend_from_slice(host.as_bytes());
    head.extend_from_slice(&dst.port().to_be_bytes());
    Ok(head)
}

#[async_trait]
impl Outbound for Snell {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let raw = self.link.open(cx).await?;
        let mut stream = SnellStream::new(raw, self.scheme(), &self.psk);
        let command = if self.version == 2 || self.reuse {
            CONNECT_V2
        } else {
            stream.without_end_chunk();
            CONNECT
        };
        stream.queue(&request(dst, command)?)?;
        stream.flush().await?;
        Ok(Box::new(stream))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if self.version < 3 {
            return Err(io::Error::other("unsupport UDP version"));
        }
        let mut raw = self.link.open(cx).await?;
        let scheme = self.scheme();
        let mut sealer = Sealer::new(scheme, &self.psk);
        let mut head = Vec::new();
        sealer.seal_chunk(&mut head, &[PROTOCOL, UDP, 0])?;
        raw.write_all(&head).await?;
        raw.flush().await?;
        let session = SnellPackets::new(raw, scheme, &self.psk, sealer);
        if scheme == Scheme::V4 {
            session.read_reply().await?;
        }
        Ok(Arc::new(session))
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &SnellOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let version = match opts.version {
        0 => 1,
        5 => 4,
        other => other,
    };
    match version {
        1 | 2 => {
            if def.common.udp {
                return Err(BuildError::invalid(format!(
                    "snell version {version} not support UDP"
                )));
            }
        }
        3 | 4 => {}
        6 => {
            return Err(BuildError::unsupported(
                "snell version 6 is not implemented by this core",
            ));
        }
        other => {
            return Err(BuildError::invalid(format!("snell version error: {other}")));
        }
    }
    let mut transport_host = opts.server.clone();
    let layers = match opts.obfs_mode.as_str() {
        "" => Vec::new(),
        mode @ ("tls" | "http") => vec![Layer::SimpleObfs(ObfsOptions {
            mode: if mode == "tls" {
                ObfsMode::Tls
            } else {
                ObfsMode::Http
            },
            host: if opts.obfs_host.is_empty() {
                "bing.com".to_string()
            } else {
                opts.obfs_host.clone()
            },
            port: opts.port.to_string(),
            clock: ctx.clock.clone(),
        })],
        "shadow-tls" => {
            let plugin = opts
                .shadow_tls
                .as_ref()
                .ok_or_else(|| BuildError::invalid("snell shadow-tls options are missing"))?;
            transport_host = plugin.host.clone();
            vec![shadow_tls_layer(plugin, &opts.client_fingerprint, ctx)?]
        }
        "restls" | "jls" => {
            return Err(BuildError::unsupported(format!(
                "snell obfs mode {} is not implemented yet",
                opts.obfs_mode
            )));
        }
        other => {
            return Err(BuildError::invalid(format!(
                "snell obfs mode error: {other}"
            )));
        }
    };
    let link = Link {
        stack: TransportStack::new(layers),
        transport_host,
        ..Link::plain(def, &opts.server, opts.port)
    };
    Ok(Arc::new(Snell {
        info: info_for(
            def,
            OutboundKind::Snell,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        link,
        psk: opts.psk.as_bytes().to_vec(),
        version,
        reuse: version == 2 || (version == 4 && opts.reuse),
    }))
}
