use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    BoxStream, FlowHandler, FlowMeta, IcmpAnswer, Initiator, SockOpts, UdpFlow, UdpPayload,
    UdpReply,
};
use concord_config::net::IpCidr;
use concord_config::tun::TunConfig;
use concord_net::Sockets;
use concord_platform::Platform;
use concord_tun::{
    Congestion, DeviceSource, DnsHijack, HandlerSink, IdRange, Prefix, SelfExclusion, StartError,
    TunDeps, TunOptions, TunRunner,
};
use concord_tunnel::Tunnel;

const DEFAULT_MTU: u32 = 9000;
const DEFAULT_INET4: &str = "198.18.0.1/30";
const DEFAULT_INET6: &str = "fdfe:dcba:9876::1/126";

/// What the TUN device asks of DNS, against whichever config is in force.
struct TunnelDns(Tunnel);

/// mihomo's order: the core's dials bind past the device before its routes go in, and follow
/// the routing table again only once the routes are gone. Sessions and resolver connections
/// dialled before the device existed are unbound, so its routes would take them in; they are
/// dropped for bound ones.
pub(crate) struct KeepOffDevice {
    pub platform: Arc<dyn Platform>,
    pub sockets: Arc<Sockets>,
    pub tunnel: Tunnel,
    pub auto_detect: bool,
}

impl SelfExclusion for KeepOffDevice {
    fn exclude(&self, device: &str) {
        self.platform
            .set_excluded_interfaces(vec![device.to_string()]);
        self.sockets.set_auto_detect_interface(self.auto_detect);
        if self.auto_detect
            && let Some(runtime) = self.tunnel.runtime()
        {
            runtime.outbounds.reset_sessions();
            runtime.dns.reset_connections();
        }
    }

    fn release(&self) {
        self.sockets.set_auto_detect_interface(false);
        self.platform.set_excluded_interfaces(Vec::new());
    }
}

#[async_trait]
impl DnsHijack for TunnelDns {
    async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let runtime = self.0.runtime()?;
        runtime.dns.handle_query_udp(query, Initiator::Other).await
    }

    async fn answer_stream(&self, query: &[u8]) -> Option<Vec<u8>> {
        let runtime = self.0.runtime()?;
        runtime.dns.handle_query(query, Initiator::Other).await
    }
}

const PING_WAIT: Duration = Duration::from_secs(10);

/// The tunnel's flows, and the echo requests it cannot see: a request goes to its
/// destination directly and is answered when the destination answers. One for a fake-ip
/// or an address of the device itself is answered by the stack, as mihomo does.
struct TunFlows {
    tunnel: Tunnel,
    sockets: Arc<Sockets>,
    device: Vec<Prefix>,
}

impl FlowHandler for TunFlows {
    fn handle_tcp(&self, meta: FlowMeta, stream: BoxStream) {
        self.tunnel.handle_tcp(meta, stream);
    }

    fn handle_udp(&self, flow: UdpFlow<'_>, payload: UdpPayload<'_>, reply: &Arc<dyn UdpReply>) {
        self.tunnel.handle_udp(flow, payload, reply);
    }

    fn udp_round(&self, round: &mut dyn FnMut()) {
        self.tunnel.udp_round(round);
    }

    #[cfg(any(unix, windows))]
    fn handle_icmp(&self, dst: IpAddr, message: &[u8], answer: IcmpAnswer) -> bool {
        let fake = self
            .tunnel
            .runtime()
            .is_none_or(|runtime| runtime.dns.is_fake_ip(dst));
        if fake || self.device.iter().any(|prefix| prefix.contains(dst)) {
            return false;
        }
        let sockets = Arc::clone(&self.sockets);
        let message = message.to_vec();
        tokio::spawn(async move {
            match sockets
                .ping(dst, &message, &SockOpts::default(), PING_WAIT)
                .await
            {
                Ok(()) => answer(),
                Err(err) => tracing::debug!("[ICMP] {dst} did not answer: {err}"),
            }
        });
        true
    }

    #[cfg(not(any(unix, windows)))]
    fn handle_icmp(&self, _dst: IpAddr, _message: &[u8], _answer: IcmpAnswer) -> bool {
        false
    }
}

fn prefixes(cidrs: &[IpCidr]) -> Vec<Prefix> {
    cidrs
        .iter()
        .filter_map(|cidr| Prefix::new(cidr.addr, cidr.prefix))
        .collect()
}

fn ids<T: Copy + Into<u32>>(ids: &[T]) -> Vec<IdRange> {
    ids.iter().map(|id| IdRange::single((*id).into())).collect()
}

/// `parseTun`: the device takes the first address of the fake-ip range.
pub(crate) fn inet4_of(fake_ip_range: Option<IpCidr>) -> Option<Prefix> {
    match fake_ip_range {
        Some(range) => Prefix::new(range.addr, 30),
        None => Prefix::parse(DEFAULT_INET4),
    }
}

pub(crate) fn options_of(config: &TunConfig, inet4: Option<Prefix>, ipv6: bool) -> TunOptions {
    TunOptions {
        device: Some(config.device.clone()).filter(|device| !device.is_empty()),
        mtu: if config.mtu == 0 {
            DEFAULT_MTU
        } else {
            config.mtu
        },
        inet4_address: inet4.into_iter().collect(),
        inet6_address: Prefix::parse(DEFAULT_INET6)
            .filter(|_| ipv6)
            .into_iter()
            .collect(),
        auto_route: config.auto_route,
        strict_route: config.strict_route,
        route_address: prefixes(&config.route_address),
        route_exclude_address: prefixes(&config.route_exclude_address),
        include_interface: config.include_interface.clone(),
        exclude_interface: config.exclude_interface.clone(),
        include_uid: ids(&config.include_uid),
        exclude_uid: ids(&config.exclude_uid),
        exclude_src_port: ids(&config.exclude_src_port),
        exclude_dst_port: ids(&config.exclude_dst_port),
        dns_hijack: config.dns_hijack.clone(),
        udp_timeout: u64::try_from(config.udp_timeout)
            .ok()
            .filter(|seconds| *seconds > 0)
            .map_or_else(|| TunOptions::default().udp_timeout, Duration::from_secs),
        disable_icmp_forwarding: config.disable_icmp_forwarding,
        ..TunOptions::default()
    }
}

/// What Android hands over with the `VpnService` descriptor.
#[cfg(unix)]
#[derive(Clone, Debug, Default)]
pub struct VpnTunRequest {
    pub stack: String,
    pub address: String,
    pub dns: String,
    pub options: String,
}

#[cfg(unix)]
#[derive(serde::Deserialize, Default)]
struct VpnTunSettings {
    #[serde(default)]
    mtu: u32,
    #[serde(default, rename = "congestion-controller")]
    congestion_controller: String,
}

/// `tun.Start`: the options the Android service sends, read the same way.
#[cfg(unix)]
pub(crate) fn vpn_options(request: &VpnTunRequest) -> Result<(TunOptions, Congestion), String> {
    let settings: VpnTunSettings =
        serde_json::from_str(&request.options).map_err(|err| err.to_string())?;
    let mut options = TunOptions {
        device: Some(concord_common::PRODUCT_NAME.to_owned()),
        mtu: if settings.mtu == 0 {
            DEFAULT_MTU
        } else {
            settings.mtu
        },
        auto_route: false,
        ..TunOptions::default()
    };
    for address in request.address.split(',').map(str::trim) {
        if address.is_empty() {
            continue;
        }
        let prefix =
            Prefix::parse(address).ok_or_else(|| format!("invalid tun address {address}"))?;
        if prefix.addr().is_ipv4() {
            options.inet4_address.push(prefix);
        } else {
            options.inet6_address.push(prefix);
        }
    }
    for server in request.dns.split(',').map(str::trim) {
        if server.is_empty() {
            continue;
        }
        let ip: std::net::IpAddr = server
            .parse()
            .map_err(|_| format!("invalid tun dns {server}"))?;
        options
            .dns_hijack
            .push(std::net::SocketAddr::new(ip, 53).to_string());
    }
    Ok((options, congestion_of(&settings.congestion_controller)))
}

pub(crate) fn congestion_of(name: &str) -> Congestion {
    let (congestion, exact) = Congestion::parse(name);
    if !exact {
        tracing::warn!("[TUN] congestion controller {name} is not available, using CUBIC");
    }
    congestion
}

/// `listener.ReCreateTun` and the Android start share everything but the descriptor.
pub(crate) async fn start_runner(
    tunnel: &Tunnel,
    sockets: &Arc<Sockets>,
    options: &TunOptions,
    source: DeviceSource,
    congestion: Congestion,
    exclusion: Option<Arc<dyn SelfExclusion>>,
) -> Result<TunRunner, StartError> {
    let handler: Arc<dyn FlowHandler> = Arc::new(TunFlows {
        tunnel: tunnel.clone(),
        sockets: Arc::clone(sockets),
        device: options
            .inet4_address
            .iter()
            .chain(&options.inet6_address)
            .copied()
            .collect(),
    });
    let runner = TunRunner::start(
        options,
        source,
        TunDeps {
            sink: Arc::new(HandlerSink::new(handler, &options.inbound_name)),
            dns: Some(Arc::new(TunnelDns(tunnel.clone()))),
            congestion,
            exclusion,
        },
    )
    .await?;
    for note in runner.notes() {
        tracing::info!("[TUN] {note}");
    }
    tracing::info!("[TUN] Tun adapter listening at: {}", runner.device_name());
    Ok(runner)
}

pub(crate) async fn stop_runner(runner: TunRunner) {
    let report = runner.stop().await;
    for failure in report.route_failures {
        tracing::error!("[TUN] restore routes: {failure}");
    }
    if let Err(err) = report.stack {
        tracing::warn!("[TUN] stack stopped: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> IpCidr {
        let (addr, prefix) = text.split_once('/').unwrap();
        IpCidr {
            addr: addr.parse().unwrap(),
            prefix: prefix.parse().unwrap(),
        }
    }

    #[test]
    fn the_device_address_comes_from_the_fake_ip_range() {
        assert_eq!(
            inet4_of(Some(cidr("198.18.0.1/16"))),
            Prefix::parse("198.18.0.1/30")
        );
        assert_eq!(
            inet4_of(Some(cidr("28.0.0.1/8"))),
            Prefix::parse("28.0.0.1/30")
        );
        assert_eq!(inet4_of(None), Prefix::parse("198.18.0.1/30"));
    }

    #[test]
    fn the_v6_address_follows_the_ipv6_switch() {
        let config = TunConfig::default();
        assert_eq!(
            options_of(&config, None, true).inet6_address,
            Prefix::parse(DEFAULT_INET6).into_iter().collect::<Vec<_>>()
        );
        assert!(options_of(&config, None, false).inet6_address.is_empty());
    }

    #[test]
    fn an_unset_mtu_and_timeout_keep_the_defaults() {
        let options = options_of(&TunConfig::default(), None, true);
        assert_eq!(options.mtu, DEFAULT_MTU);
        assert_eq!(options.udp_timeout, TunOptions::default().udp_timeout);
        assert_eq!(options.device, None);
    }

    #[cfg(unix)]
    #[test]
    fn vpn_options_read_what_the_service_sends() {
        let request = VpnTunRequest {
            stack: "mixed".into(),
            address: "172.19.0.1/30, fdfe:dcba:9876::1/126".into(),
            dns: "172.19.0.2".into(),
            options: r#"{"mtu":1480,"congestion-controller":"bbr"}"#.into(),
        };
        let (options, _) = vpn_options(&request).unwrap();
        assert_eq!(options.mtu, 1480);
        assert_eq!(
            options.inet4_address,
            Prefix::parse("172.19.0.1/30")
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(options.inet6_address.len(), 1);
        assert_eq!(options.dns_hijack, vec!["172.19.0.2:53".to_string()]);
        assert!(!options.auto_route);
    }

    #[cfg(unix)]
    #[test]
    fn a_bad_vpn_request_is_refused() {
        let bad = |address: &str, dns: &str, options: &str| {
            vpn_options(&VpnTunRequest {
                stack: String::new(),
                address: address.into(),
                dns: dns.into(),
                options: options.into(),
            })
            .is_err()
        };
        assert!(bad("172.19.0.1/30", "", "not json"));
        assert!(bad("nonsense", "", "{}"));
        assert!(bad("172.19.0.1/30", "nonsense", "{}"));
        assert!(!bad("172.19.0.1/30", "172.19.0.2", "{}"));
    }
}
