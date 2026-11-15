use std::io;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use concord_common::{Address, DialCx, DialEnv, Initiator};
use concord_config::proxy::{
    GrpcOpts, H2Opts, HttpOpts, ProxyDef, ShadowTlsOpts, TlsOpts, Transport, WsOpts, XhttpOpts,
    XhttpReuse,
};
use concord_tls::TlsConnector;
use concord_transport::{
    DialFn, GrpcOptions, GunClient, H2Options, HttpOptions, Layer, ShadowTlsClient,
    ShadowTlsOptions, TransportStack, WsOptions, XhttpClient, XhttpDownload, XhttpOptions,
    tls_dial,
};

use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, Link};
use crate::tlsmap::{TlsSpec, connector, looks_up_ech, tls_options};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    Vmess,
    Vless,
    Trojan,
}

pub(crate) struct LinkSpec<'a> {
    pub(crate) def: &'a ProxyDef,
    pub(crate) server: &'a str,
    pub(crate) port: u16,
    pub(crate) tls: &'a TlsOpts,
    pub(crate) transport: &'a Transport,
    pub(crate) flavor: Flavor,
}

tokio::task_local! {
    /// The nodes whose pools this task is dialing for. A pool dial starts a fresh
    /// `DialCx`, so a `dialer-proxy` loop back through the node shows here instead. This
    /// holds only while pool dials run on the calling task; a pool that spawns its dial
    /// must carry the chain into the task.
    static POOL_DIALS: Vec<Arc<str>>;
}

/// Whether this task is inside a pool dial for `node`: a pool that holds a lock across
/// its dial is entered again only by a loop.
pub(crate) fn pool_dialing(node: &str) -> bool {
    POOL_DIALS
        .try_with(|dialing| dialing.iter().any(|name| &**name == node))
        .unwrap_or(false)
}

/// A gRPC connection is dialed from inside the client's pool, which has no
/// `DialCx` of its own, so each `open` leaves the environment here first.
pub(crate) type EnvSlot = Arc<ArcSwapOption<DialEnv>>;

fn http_obfs_options(opts: &HttpOpts) -> HttpOptions {
    HttpOptions {
        method: opts.method.clone(),
        paths: opts.path.clone(),
        headers: opts
            .headers
            .iter()
            .map(|(key, values)| (key.clone(), values.clone()))
            .collect(),
    }
}

fn ws_options(opts: &WsOpts) -> WsOptions {
    WsOptions {
        path: opts.path.clone(),
        headers: opts
            .headers
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        max_early_data: usize::try_from(opts.max_early_data).unwrap_or(0),
        early_data_header_name: opts.early_data_header_name.clone(),
        v2ray_http_upgrade: opts.v2ray_http_upgrade,
        v2ray_http_upgrade_fast_open: opts.v2ray_http_upgrade_fast_open,
        random_host: false,
    }
}

fn host_header(opts: &WsOpts) -> Option<&str> {
    opts.headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.is_empty())
}

fn grpc_options(opts: &GrpcOpts, authority: String) -> GrpcOptions {
    GrpcOptions {
        service_name: opts.service_name.clone(),
        user_agent: opts.user_agent.clone(),
        authority,
        ping_interval: opts.ping_interval,
        max_connections: opts.max_connections as usize,
        min_streams: opts.min_streams as usize,
        max_streams: opts.max_streams as usize,
    }
}

fn h2_options(opts: &H2Opts) -> H2Options {
    let hosts = if opts.host.is_empty() {
        vec!["www.example.com".to_string()]
    } else {
        opts.host.clone()
    };
    H2Options {
        hosts,
        path: opts.path.clone(),
    }
}

fn user_alpn(tls: &TlsOpts) -> Vec<String> {
    tls.alpn.clone()
}

/// The ShadowTLS layer of `shadow-tls` plugin options; the node's `client-fingerprint` shapes
/// its handshake as it does a plain TLS node's.
pub(crate) fn shadow_tls_layer(
    opts: &ShadowTlsOpts,
    client_fingerprint: &str,
    ctx: &BuildCtx,
) -> Result<Layer, BuildError> {
    let node_tls = TlsOpts {
        enabled: true,
        server_name: opts.host.clone(),
        skip_cert_verify: opts.skip_cert_verify,
        fingerprint: opts.fingerprint.clone(),
        certificate: opts.certificate.clone(),
        private_key: opts.private_key.clone(),
        name_cert_verify: opts.name_cert_verify.clone(),
        client_fingerprint: client_fingerprint.to_string(),
        ..TlsOpts::default()
    };
    let spec = TlsSpec {
        sni: opts.host.clone(),
        alpn: opts.alpn.clone(),
    };
    let client = ShadowTlsClient::new(
        ShadowTlsOptions {
            password: opts.password.clone(),
            version: opts.version,
            tls: tls_options(&node_tls, spec, ctx, None)?,
        },
        ctx.trust.clone(),
    )
    .map_err(|err| BuildError::invalid(err.to_string()))?;
    Ok(Layer::ShadowTls(Arc::new(client)))
}

pub(crate) fn build_link(spec: LinkSpec<'_>, ctx: &BuildCtx) -> Result<Link, BuildError> {
    let LinkSpec {
        def,
        server,
        port,
        tls,
        transport,
        flavor,
    } = spec;
    let trojan = flavor == Flavor::Trojan;
    let tls_on = tls.enabled || trojan;
    let egress = Egress::new(&def.name, &def.common);
    let server_addr = Address::new(server, port);

    let reality = tls
        .reality
        .as_ref()
        .is_some_and(|r| !r.public_key.is_empty());
    if reality && !tls_on {
        return Err(BuildError::invalid("REALITY requires TLS"));
    }
    if reality
        && !matches!(
            transport,
            Transport::Tcp
                | Transport::Grpc(_)
                | Transport::H2(_)
                | Transport::Http(_)
                | Transport::Xhttp(_)
        )
    {
        return Err(BuildError::invalid(format!(
            "REALITY is not supported over the {} network",
            transport.name()
        )));
    }

    let alpn_given = tls.alpn_set || !tls.alpn.is_empty();
    let plain_sni = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let (sni, alpn, transport_host) = match transport {
        Transport::Ws(ws) => {
            let sni = if !tls.server_name.is_empty() || trojan {
                plain_sni.clone()
            } else {
                host_header(ws).map_or_else(|| server.to_string(), str::to_string)
            };
            let alpn = if trojan && alpn_given {
                tls.alpn.clone()
            } else {
                vec!["http/1.1".to_string()]
            };
            let host = if trojan {
                plain_sni.clone()
            } else {
                server.to_string()
            };
            (sni, alpn, host)
        }
        Transport::Grpc(_) | Transport::H2(_) => (
            plain_sni.clone(),
            vec!["h2".to_string()],
            server.to_string(),
        ),
        _ => {
            let alpn = if trojan && !alpn_given {
                vec!["h2".to_string(), "http/1.1".to_string()]
            } else {
                user_alpn(tls)
            };
            (plain_sni.clone(), alpn, server.to_string())
        }
    };

    let env_slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let connector_for =
        |alpn: Vec<String>, sni: &str| -> Result<Option<TlsConnector>, BuildError> {
            if !tls_on {
                return Ok(None);
            }
            let spec = TlsSpec {
                sni: sni.to_string(),
                alpn,
            };
            let mut tls = tls.clone();
            tls.enabled = true;
            connector(&tls, spec, ctx, Some(&env_slot)).map(Some)
        };

    let mut slot = None;
    let stack = match transport {
        Transport::Tcp => TransportStack::default(),
        Transport::Ws(ws) => TransportStack::new(vec![Layer::Ws(WsOptions {
            random_host: flavor == Flavor::Vless && !tls_on,
            ..ws_options(ws)
        })]),
        Transport::Http(http) => TransportStack::new(vec![Layer::Http(http_obfs_options(http))]),
        Transport::H2(h2) => {
            if !tls_on {
                return Err(BuildError::invalid("the h2 network requires tls"));
            }
            TransportStack::new(vec![Layer::H2(h2_options(h2))])
        }
        Transport::Grpc(grpc) => {
            let authority = if tls.server_name.is_empty() && !trojan {
                format!("{server}:{port}")
            } else {
                plain_sni.clone()
            };
            let dial = grpc_dial(
                egress.clone(),
                server_addr.clone(),
                connector_for(alpn.clone(), &sni)?.map(Arc::new),
                sni.clone(),
                env_slot.clone(),
                (!reality).then_some("h2"),
            );
            slot = Some(env_slot.clone());
            TransportStack::new(vec![Layer::Grpc(GunClient::new(
                grpc_options(grpc, authority),
                dial,
            ))])
        }
        Transport::Xhttp(xhttp) => {
            let layer = xhttp_layer(xhttp, tls, &egress, (server, port), &env_slot, ctx)?;
            slot = Some(env_slot.clone());
            TransportStack::new(vec![layer])
        }
    };

    let ech_lookup = tls_on && looks_up_ech(tls);
    let tls = if matches!(transport, Transport::Grpc(_) | Transport::Xhttp(_)) {
        None
    } else {
        connector_for(alpn, &sni)?
    };
    if slot.is_none() && ech_lookup {
        slot = Some(env_slot);
    }
    let link = Link {
        egress,
        server: server_addr,
        tls,
        sni_fallback: sni,
        stack,
        transport_host,
        env_slot: slot,
    };
    Ok(link)
}

pub(crate) fn simple_link(
    def: &ProxyDef,
    server: &str,
    port: u16,
    tls: &TlsOpts,
    ctx: &BuildCtx,
) -> Result<Link, BuildError> {
    let sni = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let env_slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let secured = if tls.enabled {
        let spec = TlsSpec {
            sni: sni.clone(),
            alpn: tls.alpn.clone(),
        };
        Some(connector(tls, spec, ctx, Some(&env_slot))?)
    } else {
        None
    };
    Ok(Link {
        tls: secured,
        sni_fallback: sni,
        env_slot: (tls.enabled && looks_up_ech(tls)).then_some(env_slot),
        ..Link::plain(def, server, port)
    })
}

fn grpc_dial(
    egress: Egress,
    server: Address,
    tls: Option<Arc<TlsConnector>>,
    sni: String,
    slot: EnvSlot,
    required_alpn: Option<&'static str>,
) -> DialFn {
    let raw = dial_server(egress, server, slot);
    match tls {
        Some(tls) => tls_dial(raw, tls, sni, required_alpn),
        None => raw,
    }
}

/// A fresh connection to `server` for a client that dials from inside its own pool.
fn dial_server(egress: Egress, server: Address, slot: EnvSlot) -> DialFn {
    Arc::new(move || {
        let (egress, server, slot) = (egress.clone(), server.clone(), slot.clone());
        Box::pin(async move {
            let mut dialing = POOL_DIALS.try_with(Clone::clone).unwrap_or_default();
            if dialing.contains(egress.name()) {
                return Err(
                    concord_common::CoreError::DialerLoop(egress.name().to_string()).into(),
                );
            }
            dialing.push(egress.name().clone());
            let env = slot
                .load_full()
                .ok_or_else(|| io::Error::other("grpc dial without an environment"))?;
            POOL_DIALS
                .scope(dialing, async {
                    let cx = DialCx::new(&env, Initiator::Proxy, None);
                    egress.dial(&cx, &server).await
                })
                .await
        })
    })
}

fn request_host(explicit: &str, server_name: &str, server: &str) -> String {
    if !explicit.is_empty() {
        return explicit.to_string();
    }
    let host = if server_name.is_empty() {
        server
    } else {
        server_name
    };
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn xhttp_reuse(reuse: &XhttpReuse) -> concord_transport::XhttpReuse {
    concord_transport::XhttpReuse {
        max_concurrency: reuse.max_concurrency.clone(),
        max_connections: reuse.max_connections.clone(),
        c_max_reuse_times: reuse.c_max_reuse_times.clone(),
        h_max_request_times: reuse.h_max_request_times.clone(),
        h_max_reusable_secs: reuse.h_max_reusable_secs.clone(),
    }
}

fn headers(map: &indexmap::IndexMap<String, String>) -> Vec<(String, String)> {
    map.iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// A dial function for one side of an xhttp client and whether it speaks HTTP/1.1.
fn xhttp_dial(
    egress: &Egress,
    tls: &TlsOpts,
    (server, port): (&str, u16),
    slot: &EnvSlot,
    ctx: &BuildCtx,
) -> Result<(DialFn, bool), BuildError> {
    if tls.alpn.len() == 1 && tls.alpn.first().is_some_and(|alpn| alpn == "h3") {
        return Err(BuildError::unsupported(
            "xhttp over HTTP/3 (alpn: [h3]) is not implemented",
        ));
    }
    let http1 = tls.alpn.len() == 1 && tls.alpn.first().is_some_and(|alpn| alpn == "http/1.1");
    let raw = dial_server(egress.clone(), Address::new(server, port), slot.clone());
    if !tls.enabled {
        return Ok((raw, http1));
    }
    let sni = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let wire = if http1 { "http/1.1" } else { "h2" };
    let spec = TlsSpec {
        sni: sni.clone(),
        alpn: vec![wire.to_string()],
    };
    let connector = Arc::new(connector(tls, spec, ctx, Some(slot))?);
    let reality = tls
        .reality
        .as_ref()
        .is_some_and(|r| !r.public_key.is_empty());
    Ok((
        tls_dial(raw, connector, sni, (!http1 && !reality).then_some("h2")),
        http1,
    ))
}

fn xhttp_layer(
    opts: &XhttpOpts,
    tls: &TlsOpts,
    egress: &Egress,
    (server, port): (&str, u16),
    slot: &EnvSlot,
    ctx: &BuildCtx,
) -> Result<Layer, BuildError> {
    let (dial, http1) = xhttp_dial(egress, tls, (server, port), slot, ctx)?;
    let has_reality = tls
        .reality
        .as_ref()
        .is_some_and(|reality| !reality.public_key.is_empty());
    let keep_alive = |reuse: &Option<XhttpReuse>| {
        reuse
            .as_ref()
            .map_or(0, |reuse| i64::from(reuse.h_keep_alive_period))
    };
    let download = opts
        .download
        .as_deref()
        .map(|ds| {
            let mut side = tls.clone();
            if let Some(enabled) = ds.tls {
                side.enabled = enabled;
            }
            if let Some(alpn) = &ds.alpn {
                side.alpn = alpn.clone();
            }
            if let Some(value) = ds.skip_cert_verify {
                side.skip_cert_verify = value;
            }
            if let Some(value) = &ds.name_cert_verify {
                side.name_cert_verify = value.clone();
            }
            if let Some(value) = &ds.fingerprint {
                side.fingerprint = value.clone();
            }
            if let Some(value) = &ds.certificate {
                side.certificate = value.clone();
            }
            if let Some(value) = &ds.private_key {
                side.private_key = value.clone();
            }
            if let Some(value) = &ds.server_name {
                side.server_name = value.clone();
            }
            if let Some(value) = &ds.client_fingerprint {
                side.client_fingerprint = value.clone();
            }
            if let Some(reality) = &ds.reality {
                side.reality = Some(reality.clone());
            }
            if let Some(ech) = &ds.ech {
                side.ech = Some(ech.clone());
            }
            let host = ds.server.as_deref().unwrap_or(server);
            let (dial, http1) =
                xhttp_dial(egress, &side, (host, ds.port.unwrap_or(port)), slot, ctx)?;
            let explicit = ds.host.as_deref().unwrap_or(&opts.host);
            let reuse = ds.reuse.clone().or_else(|| opts.reuse.clone());
            Ok::<_, BuildError>(XhttpDownload {
                host: request_host(explicit, &side.server_name, host),
                path: ds.path.clone().unwrap_or_else(|| opts.path.clone()),
                headers: headers(ds.headers.as_ref().unwrap_or(&opts.headers)),
                keep_alive_period: keep_alive(&reuse),
                reuse: reuse.as_ref().map(xhttp_reuse),
                http1,
                dial,
            })
        })
        .transpose()?;
    let options = XhttpOptions {
        host: request_host(&opts.host, &tls.server_name, server),
        path: opts.path.clone(),
        mode: opts.mode.clone(),
        headers: headers(&opts.headers),
        no_grpc_header: opts.no_grpc_header,
        x_padding_bytes: opts.x_padding_bytes.clone(),
        x_padding_obfs_mode: opts.x_padding_obfs_mode,
        x_padding_key: opts.x_padding_key.clone(),
        x_padding_header: opts.x_padding_header.clone(),
        x_padding_placement: opts.x_padding_placement.clone(),
        x_padding_method: opts.x_padding_method.clone(),
        uplink_http_method: opts.uplink_http_method.clone(),
        session_placement: opts.session_placement.clone(),
        session_key: opts.session_key.clone(),
        session_table: opts.session_table.clone(),
        session_length: opts.session_length.clone(),
        seq_placement: opts.seq_placement.clone(),
        seq_key: opts.seq_key.clone(),
        uplink_data_placement: opts.uplink_data_placement.clone(),
        uplink_data_key: opts.uplink_data_key.clone(),
        uplink_chunk_size: opts.uplink_chunk_size.clone(),
        sc_max_each_post_bytes: opts.sc_max_each_post_bytes.clone(),
        sc_min_posts_interval_ms: opts.sc_min_posts_interval_ms.clone(),
        reuse: opts.reuse.as_ref().map(xhttp_reuse),
        keep_alive_period: keep_alive(&opts.reuse),
        http1,
        has_reality,
    };
    let client = XhttpClient::new(options, dial, download)
        .map_err(|err| BuildError::invalid(err.to_string()))?;
    Ok(Layer::Xhttp(client))
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use async_trait::async_trait;
    use concord_common::{
        Address, BoxStream, CoreError, DialCx, Initiator, NodeDialer, Outbound, PacketSession,
    };
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use concord_tls::TrustStore;
    use serde_json::{Value, json};
    use tokio::sync::Barrier;

    use crate::testing::test_env_with;
    use crate::{BuildCtx, build_outbound};

    fn build(extra: Value) -> Result<(), String> {
        let mut node = json!({
            "name": "n", "type": "vless", "server": "127.0.0.1", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "reality-opts": {"public-key": "SHbG8EvyDdqrc-BMXJTMtSwVPS7mVZGHN0SjL1yYa1I"}
        });
        if let (Some(node), Some(extra)) = (node.as_object_mut(), extra.as_object()) {
            node.extend(extra.clone());
        }
        let Some(map) = node.as_object() else {
            return Err("not an object".into());
        };
        let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
            return Err("does not parse".into());
        };
        let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
        build_outbound(&def, &ctx)
            .map(drop)
            .map_err(|err| err.to_string())
    }

    #[test]
    fn reality_without_tls_is_refused_as_mihomo_does() {
        let err = build(json!({"tls": false})).unwrap_err();
        assert!(err.contains("REALITY requires TLS"), "{err}");
    }

    #[test]
    fn reality_runs_over_xhttp() {
        build(json!({
            "tls": true, "client-fingerprint": "chrome",
            "network": "xhttp", "xhttp-opts": {"path": "/x"}
        }))
        .unwrap();
    }

    /// The `dialer-proxy` `hop`: it holds `wait` dials until all are in flight and
    /// fails them, or with no `wait` dials back through `back`.
    struct Hop {
        wait: Option<Barrier>,
        back: OnceLock<Arc<dyn Outbound>>,
    }

    #[async_trait]
    impl NodeDialer for Hop {
        async fn dial_via(
            &self,
            _name: &str,
            cx: &DialCx<'_>,
            dst: &Address,
        ) -> io::Result<BoxStream> {
            if let Some(wait) = &self.wait {
                wait.wait().await;
                return Err(io::Error::other("hop down"));
            }
            let back = self.back.get().ok_or_else(|| io::Error::other("no node"))?;
            back.connect(cx, dst).await
        }

        async fn associate_via(
            &self,
            name: &str,
            _cx: &DialCx<'_>,
            _hint: &Address,
        ) -> io::Result<Arc<dyn PacketSession>> {
            Err(CoreError::UnknownNode(name.to_string()).into())
        }
    }

    fn pooled(network: Value) -> Arc<dyn Outbound> {
        let mut node = json!({
            "name": "pooled", "type": "vless", "server": "127.0.0.1", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "dialer-proxy": "hop"
        });
        if let (Some(node), Some(network)) = (node.as_object_mut(), network.as_object()) {
            node.extend(network.clone());
        }
        let map = node.as_object().unwrap();
        let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
            panic!("does not parse");
        };
        build_outbound(&def, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap()
    }

    #[tokio::test]
    async fn pool_dials_through_a_dialer_proxy_run_side_by_side() {
        const DIALS: usize = 32;
        let hop = Arc::new(Hop {
            wait: Some(Barrier::new(DIALS)),
            back: OnceLock::new(),
        });
        let env = test_env_with(hop);
        // XHTTP without reuse dials a connection per logical connection.
        let outbound = pooled(json!({"network": "xhttp", "xhttp-opts": {"path": "/x"}}));
        let dials: Vec<_> = (0..DIALS)
            .map(|_| {
                let (outbound, env) = (outbound.clone(), env.clone());
                tokio::spawn(async move {
                    let cx = DialCx::new(&env, Initiator::Direct, None);
                    outbound
                        .connect(&cx, &Address::new("127.0.0.1", 9))
                        .await
                        .map(drop)
                })
            })
            .collect();
        for dial in dials {
            let err = tokio::time::timeout(Duration::from_secs(5), dial)
                .await
                .expect("dials did not run side by side")
                .unwrap()
                .unwrap_err();
            assert!(err.to_string().contains("hop down"), "{err}");
        }
    }

    /// Gun holds its connection's lock across the dial, so the loop must fail before
    /// it reaches the pool again.
    #[tokio::test]
    async fn a_dialer_proxy_loop_through_the_pool_fails() {
        for network in [
            json!({"network": "xhttp", "xhttp-opts": {"path": "/x"}}),
            json!({"network": "grpc", "grpc-opts": {"grpc-service-name": "x"}}),
        ] {
            let hop = Arc::new(Hop {
                wait: None,
                back: OnceLock::new(),
            });
            let env = test_env_with(hop.clone());
            let outbound = pooled(network.clone());
            let _ = hop.back.set(outbound.clone());
            let cx = DialCx::new(&env, Initiator::Direct, None);
            let err = tokio::time::timeout(
                Duration::from_secs(5),
                outbound.connect(&cx, &Address::new("127.0.0.1", 9)),
            )
            .await
            .unwrap_or_else(|_| panic!("{network}: the loop did not end"))
            .map(drop)
            .unwrap_err();
            assert!(
                matches!(CoreError::of(&err), Some(CoreError::DialerLoop(name)) if name == "pooled"),
                "{network}: {err}"
            );
        }
    }
}
