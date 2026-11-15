#![allow(dead_code, reason = "each test binary uses a different part")]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use concord_common::{BoxStream, FlowKey, PacketBuf, UdpReply};
use concord_tun::FlowSink;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr,
    TcpSeqNumber, UdpPacket, UdpRepr,
};
use tokio::sync::mpsc;

pub struct ChannelSink {
    pub tcp: mpsc::UnboundedSender<(FlowKey, BoxStream)>,
    pub udp: mpsc::UnboundedSender<(FlowKey, PacketBuf, Arc<dyn UdpReply>)>,
}

pub type TcpRx = mpsc::UnboundedReceiver<(FlowKey, BoxStream)>;
pub type UdpRx = mpsc::UnboundedReceiver<(FlowKey, PacketBuf, Arc<dyn UdpReply>)>;

pub fn channel_sink() -> (Arc<ChannelSink>, TcpRx, UdpRx) {
    let (tcp, tcp_rx) = mpsc::unbounded_channel();
    let (udp, udp_rx) = mpsc::unbounded_channel();
    (Arc::new(ChannelSink { tcp, udp }), tcp_rx, udp_rx)
}

impl FlowSink for ChannelSink {
    fn tcp(&self, flow: FlowKey, stream: BoxStream) {
        let _ = self.tcp.send((flow, stream));
    }

    fn udp(&self, flow: FlowKey, payload: &[u8], reply: &Arc<dyn UdpReply>) {
        let _ = self
            .udp
            .send((flow, PacketBuf::from_slice(payload), Arc::clone(reply)));
    }
}

pub fn wrap_ip(src: IpAddr, dst: IpAddr, proto: IpProtocol, l4: &[u8]) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let repr = Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: proto,
                payload_len: l4.len(),
                hop_limit: 64,
            };
            let mut raw = vec![0u8; 20 + l4.len()];
            let mut packet = Ipv4Packet::new_unchecked(&mut raw[..]);
            repr.emit(&mut packet, &caps);
            packet.payload_mut().copy_from_slice(l4);
            raw
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let repr = Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: proto,
                payload_len: l4.len(),
                hop_limit: 64,
            };
            let mut raw = vec![0u8; 40 + l4.len()];
            let mut packet = Ipv6Packet::new_unchecked(&mut raw[..]);
            repr.emit(&mut packet);
            packet.payload_mut().copy_from_slice(l4);
            raw
        }
        _ => panic!("mixed families"),
    }
}

pub fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let repr = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let mut l4 = vec![0u8; 8 + payload.len()];
    let mut udp = UdpPacket::new_unchecked(&mut l4[..]);
    repr.emit(
        &mut udp,
        &src.ip().into(),
        &dst.ip().into(),
        payload.len(),
        |body| body.copy_from_slice(payload),
        &caps,
    );
    wrap_ip(src.ip(), dst.ip(), IpProtocol::Udp, &l4)
}

pub struct Udp {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

pub fn parse_udp(raw: &[u8]) -> Option<Udp> {
    let (src, dst, l4) = split_ip(raw)?;
    let udp = UdpPacket::new_checked(l4).ok()?;
    if !udp.verify_checksum(&src.into(), &dst.into()) {
        return None;
    }
    Some(Udp {
        src: SocketAddr::new(src, udp.src_port()),
        dst: SocketAddr::new(dst, udp.dst_port()),
        payload: udp.payload().to_vec(),
    })
}

pub fn split_ip(raw: &[u8]) -> Option<(IpAddr, IpAddr, &[u8])> {
    match raw.first()? >> 4 {
        4 => {
            let packet = Ipv4Packet::new_checked(raw).ok()?;
            Some((
                IpAddr::V4(packet.src_addr()),
                IpAddr::V4(packet.dst_addr()),
                packet.payload(),
            ))
        }
        6 => {
            let packet = Ipv6Packet::new_checked(raw).ok()?;
            Some((
                IpAddr::V6(packet.src_addr()),
                IpAddr::V6(packet.dst_addr()),
                packet.payload(),
            ))
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct Seg {
    pub seq: u32,
    pub ack: Option<u32>,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
    pub window: u16,
    pub payload: Vec<u8>,
}

impl Seg {
    pub fn next_seq(&self) -> u32 {
        self.seq
            .wrapping_add(self.payload.len() as u32)
            .wrapping_add(u32::from(self.syn))
            .wrapping_add(u32::from(self.fin))
    }
}

pub struct TcpPeer {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub seq: u32,
    pub ack: u32,
}

impl TcpPeer {
    pub fn new(client: &str, server: &str) -> Self {
        TcpPeer {
            client: client.parse().unwrap(),
            server: server.parse().unwrap(),
            seq: 1000,
            ack: 0,
        }
    }

    fn build(&mut self, control: TcpControl, ack: bool, payload: &[u8]) -> Vec<u8> {
        let caps = ChecksumCapabilities::default();
        let repr = TcpRepr {
            src_port: self.client.port(),
            dst_port: self.server.port(),
            control,
            seq_number: TcpSeqNumber(self.seq as i32),
            ack_number: ack.then_some(TcpSeqNumber(self.ack as i32)),
            window_len: 65_535,
            window_scale: None,
            max_seg_size: (control == TcpControl::Syn).then_some(1400),
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let mut l4 = vec![0u8; repr.buffer_len()];
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut l4[..]),
            &self.client.ip().into(),
            &self.server.ip().into(),
            &caps,
        );
        self.seq = self
            .seq
            .wrapping_add(payload.len() as u32)
            .wrapping_add(u32::from(matches!(
                control,
                TcpControl::Syn | TcpControl::Fin
            )));
        wrap_ip(self.client.ip(), self.server.ip(), IpProtocol::Tcp, &l4)
    }

    pub fn syn(&mut self) -> Vec<u8> {
        self.build(TcpControl::Syn, false, &[])
    }

    pub fn ack(&mut self) -> Vec<u8> {
        self.build(TcpControl::None, true, &[])
    }

    pub fn data(&mut self, payload: &[u8]) -> Vec<u8> {
        self.build(TcpControl::Psh, true, payload)
    }

    pub fn fin(&mut self) -> Vec<u8> {
        self.build(TcpControl::Fin, true, &[])
    }

    pub fn rst(&mut self) -> Vec<u8> {
        self.build(TcpControl::Rst, true, &[])
    }

    pub fn parse(&self, raw: &[u8]) -> Option<Seg> {
        let (src, dst, l4) = split_ip(raw)?;
        if src != self.server.ip() || dst != self.client.ip() {
            return None;
        }
        let tcp = TcpPacket::new_checked(l4).ok()?;
        if !tcp.verify_checksum(&src.into(), &dst.into()) {
            return None;
        }
        if tcp.dst_port() != self.client.port() || tcp.src_port() != self.server.port() {
            return None;
        }
        Some(Seg {
            seq: tcp.seq_number().0 as u32,
            ack: tcp.ack().then(|| tcp.ack_number().0 as u32),
            syn: tcp.syn(),
            fin: tcp.fin(),
            rst: tcp.rst(),
            window: tcp.window_len(),
            payload: tcp.payload().to_vec(),
        })
    }

    pub fn absorb(&mut self, seg: &Seg) {
        if seg.next_seq().wrapping_sub(self.ack) as i32 > 0 || seg.syn {
            self.ack = seg.next_seq();
        }
    }
}

pub fn tcp_payload_len(raw: &[u8]) -> usize {
    split_ip(raw)
        .and_then(|(_, _, l4)| {
            TcpPacket::new_checked(l4)
                .ok()
                .map(|tcp| tcp.payload().len())
        })
        .unwrap_or(0)
}
