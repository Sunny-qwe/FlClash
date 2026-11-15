use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const IPV4_HEADER: usize = 20;
pub const IPV6_HEADER: usize = 40;
pub const UDP_HEADER: usize = 8;
pub const TCP_HEADER: usize = 20;
pub const HOP_LIMIT: u8 = 64;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_IPV6_FRAG: u8 = 44;
pub const PROTO_ICMPV6: u8 = 58;

/// Why a packet read from the device is not handed on. Counted, never logged per packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    Malformed,
    Fragment,
    Checksum,
    Unsupported,
    Martian,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4Kind {
    Tcp,
    Udp,
    Icmp,
}

pub(crate) fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let pair = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([*pair.first()?, *pair.get(1)?]))
}

pub(crate) fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let quad: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(quad))
}

fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> Option<()> {
    out.get_mut(at..at + bytes.len())?.copy_from_slice(bytes);
    Some(())
}

pub(crate) fn put16(out: &mut [u8], at: usize, value: u16) -> Option<()> {
    put(out, at, &value.to_be_bytes())
}

pub(crate) fn put32(out: &mut [u8], at: usize, value: u32) -> Option<()> {
    put(out, at, &value.to_be_bytes())
}

/// The one's-complement sum of `data` added to `sum`, not yet folded.
pub fn sum_bytes(mut sum: u64, data: &[u8]) -> u64 {
    let (chunks, rest) = data.as_chunks::<8>();
    for chunk in chunks {
        let (added, carry) = sum.overflowing_add(u64::from_be_bytes(*chunk));
        sum = added + u64::from(carry);
    }
    let mut tail = [0u8; 8];
    if let Some(head) = tail.get_mut(..rest.len()) {
        head.copy_from_slice(rest);
    }
    let (added, carry) = sum.overflowing_add(u64::from_be_bytes(tail));
    added + u64::from(carry)
}

pub fn fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

pub fn finish(sum: u64) -> u16 {
    !fold(sum)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum L4Checksum {
    #[default]
    Full,
    /// Only the pseudo-header sum, which a device with checksum offload completes.
    Pseudo,
}

fn l4_checksum(mode: L4Checksum, pseudo: u64, l4: &[u8]) -> u16 {
    match mode {
        L4Checksum::Full => finish(sum_bytes(pseudo, l4)),
        L4Checksum::Pseudo => fold(pseudo),
    }
}

pub fn pseudo_header(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> u64 {
    let mut sum = 0;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            sum = sum_bytes(sum, &s.octets());
            sum = sum_bytes(sum, &d.octets());
        }
        (s, d) => {
            sum = sum_bytes(sum, &v6(s).octets());
            sum = sum_bytes(sum, &v6(d).octets());
        }
    }
    sum + u64::from(proto) + len as u64
}

fn v6(addr: IpAddr) -> Ipv6Addr {
    match addr {
        IpAddr::V6(addr) => addr,
        IpAddr::V4(addr) => addr.to_ipv6_mapped(),
    }
}

/// A received IP packet with fixed-size headers resolved.
#[derive(Clone, Copy, Debug)]
pub struct IpView<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub kind: L4Kind,
    /// Transport header and payload, cut to the IP length.
    pub l4: &'a [u8],
    pub packet: &'a [u8],
}

/// The fields a fragment carries, for reassembly.
#[derive(Clone, Copy, Debug)]
pub struct FragmentView<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
    pub proto: u8,
    pub offset: usize,
    pub more: bool,
    /// Header bytes of the first fragment, including any IPv6 extension headers before the
    /// fragment header, with the fragment header itself removed.
    pub header: &'a [u8],
    pub payload: &'a [u8],
}

pub enum Parsed<'a> {
    Packet(IpView<'a>),
    Fragment(FragmentView<'a>),
}

fn martian_v4(src: Ipv4Addr, dst: Ipv4Addr) -> bool {
    src.is_unspecified()
        || src.is_multicast()
        || dst.is_unspecified()
        || dst.is_multicast()
        || dst == Ipv4Addr::BROADCAST
        || dst.is_loopback()
        || dst.is_link_local()
}

fn martian_v6(src: Ipv6Addr, dst: Ipv6Addr) -> bool {
    src.is_unspecified()
        || src.is_multicast()
        || dst.is_unspecified()
        || dst.is_multicast()
        || dst.is_loopback()
        || dst.is_unicast_link_local()
        || src.to_ipv4_mapped().is_some()
        || dst.to_ipv4_mapped().is_some()
}

fn kind_of(proto: u8) -> Result<L4Kind, DropReason> {
    match proto {
        PROTO_TCP => Ok(L4Kind::Tcp),
        PROTO_UDP => Ok(L4Kind::Udp),
        PROTO_ICMP | PROTO_ICMPV6 => Ok(L4Kind::Icmp),
        _ => Err(DropReason::Unsupported),
    }
}

/// Parses an IP packet, returning fragments separately so the caller can reassemble them.
pub fn parse_packet(packet: &[u8]) -> Result<Parsed<'_>, DropReason> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => parse_v4(packet),
        Some(6) => parse_v6(packet),
        _ => Err(DropReason::Malformed),
    }
}

/// Like `parse_packet` but treats every fragment as a drop.
pub fn parse_ip(packet: &[u8]) -> Result<IpView<'_>, DropReason> {
    match parse_packet(packet)? {
        Parsed::Packet(view) => Ok(view),
        Parsed::Fragment(_) => Err(DropReason::Fragment),
    }
}

fn parse_v4(packet: &[u8]) -> Result<Parsed<'_>, DropReason> {
    let first = *packet.first().ok_or(DropReason::Malformed)?;
    let ihl = usize::from(first & 0x0f) * 4;
    let total = usize::from(be16(packet, 2).ok_or(DropReason::Malformed)?);
    if ihl < IPV4_HEADER || total < ihl || total > packet.len() {
        return Err(DropReason::Malformed);
    }
    let header = packet.get(..ihl).ok_or(DropReason::Malformed)?;
    if fold(sum_bytes(0, header)) != 0xffff {
        return Err(DropReason::Checksum);
    }
    let src = Ipv4Addr::from(be32(packet, 12).ok_or(DropReason::Malformed)?);
    let dst = Ipv4Addr::from(be32(packet, 16).ok_or(DropReason::Malformed)?);
    if martian_v4(src, dst) {
        return Err(DropReason::Martian);
    }
    let proto = *packet.get(9).ok_or(DropReason::Malformed)?;
    let flags_frag = be16(packet, 6).ok_or(DropReason::Malformed)?;
    let packet = packet.get(..total).ok_or(DropReason::Malformed)?;
    let payload = packet.get(ihl..).ok_or(DropReason::Malformed)?;
    let more = flags_frag & 0x2000 != 0;
    let offset = usize::from(flags_frag & 0x1fff) * 8;
    if more || offset != 0 {
        return Ok(Parsed::Fragment(FragmentView {
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
            id: u32::from(be16(packet, 4).ok_or(DropReason::Malformed)?),
            proto,
            offset,
            more,
            header,
            payload,
        }));
    }
    Ok(Parsed::Packet(IpView {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        kind: kind_of(proto)?,
        l4: payload,
        packet,
    }))
}

fn parse_v6(packet: &[u8]) -> Result<Parsed<'_>, DropReason> {
    let payload_len = usize::from(be16(packet, 4).ok_or(DropReason::Malformed)?);
    let total = IPV6_HEADER + payload_len;
    if total > packet.len() {
        return Err(DropReason::Malformed);
    }
    let packet = packet.get(..total).ok_or(DropReason::Malformed)?;
    let src: [u8; 16] = packet
        .get(8..24)
        .and_then(|b| b.try_into().ok())
        .ok_or(DropReason::Malformed)?;
    let dst: [u8; 16] = packet
        .get(24..40)
        .and_then(|b| b.try_into().ok())
        .ok_or(DropReason::Malformed)?;
    let (src, dst) = (Ipv6Addr::from(src), Ipv6Addr::from(dst));
    if martian_v6(src, dst) {
        return Err(DropReason::Martian);
    }
    let next = *packet.get(6).ok_or(DropReason::Malformed)?;
    if next == PROTO_IPV6_FRAG {
        let frag = packet.get(IPV6_HEADER..).ok_or(DropReason::Malformed)?;
        let inner = *frag.first().ok_or(DropReason::Malformed)?;
        let field = be16(frag, 2).ok_or(DropReason::Malformed)?;
        let id = be32(frag, 4).ok_or(DropReason::Malformed)?;
        let payload = frag.get(8..).ok_or(DropReason::Malformed)?;
        return Ok(Parsed::Fragment(FragmentView {
            src: IpAddr::V6(src),
            dst: IpAddr::V6(dst),
            id,
            proto: inner,
            offset: usize::from(field & 0xfff8),
            more: field & 1 != 0,
            header: packet.get(..IPV6_HEADER).ok_or(DropReason::Malformed)?,
            payload,
        }));
    }
    Ok(Parsed::Packet(IpView {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        kind: kind_of(next)?,
        l4: packet.get(IPV6_HEADER..).ok_or(DropReason::Malformed)?,
        packet,
    }))
}

/// Writes an IP header for `l4_len` bytes of `proto` and returns its length.
pub fn emit_ip(
    out: &mut [u8],
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    l4_len: usize,
) -> Option<usize> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = u16::try_from(IPV4_HEADER + l4_len).ok()?;
            let header = out.get_mut(..IPV4_HEADER)?;
            put(header, 0, &[0x45, 0])?;
            put16(header, 2, total)?;
            put(header, 4, &[0, 0, 0x40, 0, HOP_LIMIT, proto, 0, 0])?;
            put(header, 12, &s.octets())?;
            put(header, 16, &d.octets())?;
            let sum = finish(sum_bytes(0, header));
            put16(header, 10, sum)?;
            Some(IPV4_HEADER)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len = u16::try_from(l4_len).ok()?;
            let header = out.get_mut(..IPV6_HEADER)?;
            put(header, 0, &[0x60, 0, 0, 0])?;
            put16(header, 4, len)?;
            put(header, 6, &[proto, HOP_LIMIT])?;
            put(header, 8, &s.octets())?;
            put(header, 24, &d.octets())?;
            Some(IPV6_HEADER)
        }
        _ => None,
    }
}

pub fn ip_header_len(addr: IpAddr) -> usize {
    match addr {
        IpAddr::V4(_) => IPV4_HEADER,
        IpAddr::V6(_) => IPV6_HEADER,
    }
}

pub struct UdpView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp<'a>(view: &IpView<'a>) -> Result<UdpView<'a>, DropReason> {
    parse_udp_with(view, true)
}

pub fn parse_udp_unverified<'a>(view: &IpView<'a>) -> Result<UdpView<'a>, DropReason> {
    parse_udp_with(view, false)
}

fn parse_udp_with<'a>(view: &IpView<'a>, verify: bool) -> Result<UdpView<'a>, DropReason> {
    let l4 = view.l4;
    let len = usize::from(be16(l4, 4).ok_or(DropReason::Malformed)?);
    if len < UDP_HEADER || len > l4.len() {
        return Err(DropReason::Malformed);
    }
    let datagram = l4.get(..len).ok_or(DropReason::Malformed)?;
    let checksum = be16(l4, 6).ok_or(DropReason::Malformed)?;
    let unchecked_v4 = view.src.is_ipv4() && checksum == 0;
    if verify && !unchecked_v4 {
        let sum = sum_bytes(pseudo_header(view.src, view.dst, PROTO_UDP, len), datagram);
        if fold(sum) != 0xffff {
            return Err(DropReason::Checksum);
        }
    }
    Ok(UdpView {
        src_port: be16(l4, 0).ok_or(DropReason::Malformed)?,
        dst_port: be16(l4, 2).ok_or(DropReason::Malformed)?,
        payload: datagram.get(UDP_HEADER..).ok_or(DropReason::Malformed)?,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    TooLarge,
    Family,
}

/// Writes an IP packet carrying one UDP datagram from `src` to `dst`.
pub fn build_udp(
    out: &mut [u8],
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    checksum: L4Checksum,
) -> Result<usize, BuildError> {
    if src.is_ipv4() != dst.is_ipv4() {
        return Err(BuildError::Family);
    }
    let l4_len = UDP_HEADER + payload.len();
    let header = ip_header_len(src.ip());
    let total = header + l4_len;
    if l4_len > usize::from(u16::MAX) || total > out.len() {
        return Err(BuildError::TooLarge);
    }
    emit_ip(out, src.ip(), dst.ip(), PROTO_UDP, l4_len).ok_or(BuildError::TooLarge)?;
    let udp = out.get_mut(header..total).ok_or(BuildError::TooLarge)?;
    let len = l4_len as u16;
    put16(udp, 0, src.port()).ok_or(BuildError::TooLarge)?;
    put16(udp, 2, dst.port()).ok_or(BuildError::TooLarge)?;
    put16(udp, 4, len).ok_or(BuildError::TooLarge)?;
    put16(udp, 6, 0).ok_or(BuildError::TooLarge)?;
    put(udp, UDP_HEADER, payload).ok_or(BuildError::TooLarge)?;
    let pseudo = pseudo_header(src.ip(), dst.ip(), PROTO_UDP, l4_len);
    let mut sum = l4_checksum(checksum, pseudo, udp);
    if sum == 0 && checksum == L4Checksum::Full {
        sum = 0xffff;
    }
    put16(udp, 6, sum).ok_or(BuildError::TooLarge)?;
    Ok(total)
}

const FRAG_MORE: u16 = 0x2000;
const IPV6_FRAG_HEADER: usize = 8;

fn fragment_layout(packet: &[u8], mtu: usize) -> Option<(usize, usize, usize)> {
    let (base, header) = match packet.first()? >> 4 {
        4 => (IPV4_HEADER, IPV4_HEADER),
        6 => (IPV6_HEADER, IPV6_HEADER + IPV6_FRAG_HEADER),
        _ => return None,
    };
    let step = mtu.checked_sub(header)? & !7;
    if step == 0 {
        return None;
    }
    let l4 = packet.len().checked_sub(base)?;
    Some((header, step, l4))
}

/// How many fragments `packet` needs to fit `mtu`, or `None` when it cannot be cut.
pub fn fragment_count(packet: &[u8], mtu: usize) -> Option<usize> {
    let (_, step, l4) = fragment_layout(packet, mtu)?;
    Some(l4.div_ceil(step))
}

/// Writes fragment `index` of a whole IP packet to `out`, as gVisor cuts a datagram that
/// exceeds the route MTU: payload blocks of a multiple of 8 bytes, no DF on IPv4, and a
/// fragment header after the fixed header on IPv6. `ident` is shared by every fragment.
pub fn write_fragment(
    packet: &[u8],
    mtu: usize,
    ident: u32,
    index: usize,
    out: &mut [u8],
) -> Option<usize> {
    let (header, step, l4) = fragment_layout(packet, mtu)?;
    let v4 = header == IPV4_HEADER;
    let base = if v4 { IPV4_HEADER } else { IPV6_HEADER };
    let start = index.checked_mul(step)?;
    let end = (start + step).min(l4);
    let payload = packet.get(base + start..base + end)?;
    let total = header + payload.len();
    let more = end < l4;
    let frame = out.get_mut(..total)?;
    frame.get_mut(..base)?.copy_from_slice(packet.get(..base)?);
    if v4 {
        put16(frame, 2, u16::try_from(total).ok()?)?;
        put16(frame, 4, ident as u16)?;
        let field = u16::try_from(start / 8).ok()? | if more { FRAG_MORE } else { 0 };
        put16(frame, 6, field)?;
        put16(frame, 10, 0)?;
        let sum = finish(sum_bytes(0, frame.get(..IPV4_HEADER)?));
        put16(frame, 10, sum)?;
    } else {
        let proto = *packet.get(6)?;
        put16(
            frame,
            4,
            u16::try_from(IPV6_FRAG_HEADER + payload.len()).ok()?,
        )?;
        *frame.get_mut(6)? = PROTO_IPV6_FRAG;
        *frame.get_mut(IPV6_HEADER)? = proto;
        *frame.get_mut(IPV6_HEADER + 1)? = 0;
        let field = u16::try_from(start).ok()? | u16::from(more);
        put16(frame, IPV6_HEADER + 2, field)?;
        put32(frame, IPV6_HEADER + 4, ident)?;
    }
    frame.get_mut(header..)?.copy_from_slice(payload);
    Some(total)
}

/// Answers an echo request as if the destination host replied.
pub fn build_echo_reply(out: &mut [u8], view: &IpView<'_>) -> Option<usize> {
    match (view.src, view.dst) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            if *view.l4.first()? != 8
                || *view.l4.get(1)? != 0
                || fold(sum_bytes(0, view.l4)) != 0xffff
            {
                return None;
            }
            emit_ip(out, view.dst, view.src, PROTO_ICMP, view.l4.len())?;
            let total = IPV4_HEADER + view.l4.len();
            let icmp = out.get_mut(IPV4_HEADER..total)?;
            icmp.copy_from_slice(view.l4);
            *icmp.first_mut()? = 0;
            put16(icmp, 2, 0)?;
            let sum = finish(sum_bytes(0, icmp));
            put16(icmp, 2, sum)?;
            Some(total)
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            let pseudo = pseudo_header(view.src, view.dst, PROTO_ICMPV6, view.l4.len());
            if *view.l4.first()? != 128
                || *view.l4.get(1)? != 0
                || fold(sum_bytes(pseudo, view.l4)) != 0xffff
            {
                return None;
            }
            emit_ip(out, view.dst, view.src, PROTO_ICMPV6, view.l4.len())?;
            let total = IPV6_HEADER + view.l4.len();
            let icmp = out.get_mut(IPV6_HEADER..total)?;
            icmp.copy_from_slice(view.l4);
            *icmp.first_mut()? = 129;
            put16(icmp, 2, 0)?;
            let pseudo = pseudo_header(view.dst, view.src, PROTO_ICMPV6, icmp.len());
            let sum = finish(sum_bytes(pseudo, icmp));
            put16(icmp, 2, sum)?;
            Some(total)
        }
        _ => None,
    }
}

pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_PSH: u8 = 0x08;
pub const FLAG_ACK: u8 = 0x10;

/// At most four SACK blocks fit in the option space; three when timestamps are on.
pub const MAX_SACK_BLOCKS: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamp: Option<(u32, u32)>,
    pub sack: [(u32, u32); MAX_SACK_BLOCKS],
    pub sack_len: u8,
}

impl TcpOptions {
    pub fn sack_blocks(&self) -> &[(u32, u32)] {
        self.sack
            .get(..usize::from(self.sack_len))
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

impl TcpSegment<'_> {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn is_syn(&self) -> bool {
        self.has(FLAG_SYN) && !self.has(FLAG_ACK)
    }

    /// Sequence space the segment occupies: payload plus one for SYN and one for FIN.
    pub fn seq_len(&self) -> u32 {
        self.payload.len() as u32 + u32::from(self.has(FLAG_SYN)) + u32::from(self.has(FLAG_FIN))
    }
}

/// Parses a TCP header without checking its checksum; the device on the other side of a TUN
/// is the local kernel, which computed it.
pub fn parse_tcp<'a>(l4: &'a [u8]) -> Result<TcpSegment<'a>, DropReason> {
    let offset = usize::from(l4.get(12).ok_or(DropReason::Malformed)? >> 4) * 4;
    if offset < TCP_HEADER || offset > l4.len() {
        return Err(DropReason::Malformed);
    }
    let options = parse_options(l4.get(TCP_HEADER..offset).ok_or(DropReason::Malformed)?);
    Ok(TcpSegment {
        src_port: be16(l4, 0).ok_or(DropReason::Malformed)?,
        dst_port: be16(l4, 2).ok_or(DropReason::Malformed)?,
        seq: be32(l4, 4).ok_or(DropReason::Malformed)?,
        ack: be32(l4, 8).ok_or(DropReason::Malformed)?,
        flags: *l4.get(13).ok_or(DropReason::Malformed)? & 0x3f,
        window: be16(l4, 14).ok_or(DropReason::Malformed)?,
        options,
        payload: l4.get(offset..).ok_or(DropReason::Malformed)?,
    })
}

pub fn tcp_checksum_ok(src: IpAddr, dst: IpAddr, l4: &[u8]) -> bool {
    fold(sum_bytes(pseudo_header(src, dst, PROTO_TCP, l4.len()), l4)) == 0xffff
}

fn parse_options(mut bytes: &[u8]) -> TcpOptions {
    let mut options = TcpOptions::default();
    while let Some(&kind) = bytes.first() {
        match kind {
            0 => break,
            1 => {
                bytes = bytes.get(1..).unwrap_or_default();
                continue;
            }
            _ => {}
        }
        let Some(&len) = bytes.get(1) else {
            break;
        };
        let len = usize::from(len);
        let Some(body) = bytes.get(2..len) else {
            break;
        };
        match (kind, len) {
            (2, 4) => options.mss = be16(body, 0),
            (3, 3) => options.window_scale = body.first().map(|s| (*s).min(14)),
            (4, 2) => options.sack_permitted = true,
            (5, _) => {
                for block in body.as_chunks::<8>().0.iter().take(MAX_SACK_BLOCKS) {
                    if let (Some(left), Some(right)) = (be32(block, 0), be32(block, 4))
                        && let Some(slot) = options.sack.get_mut(usize::from(options.sack_len))
                    {
                        *slot = (left, right);
                        options.sack_len += 1;
                    }
                }
            }
            (8, 10) => options.timestamp = be32(body, 0).zip(be32(body, 4)),
            _ => {}
        }
        bytes = bytes.get(len..).unwrap_or_default();
    }
    options
}

/// Writes the option block for a segment and returns its length, a multiple of four.
fn emit_options(out: &mut [u8], options: &TcpOptions) -> Option<usize> {
    let mut at = 0;
    if let Some(mss) = options.mss {
        put(out, at, &[2, 4])?;
        put16(out, at + 2, mss)?;
        at += 4;
    }
    if options.sack_permitted {
        put(out, at, &[1, 1, 4, 2])?;
        at += 4;
    }
    if let Some((value, echo)) = options.timestamp {
        put(out, at, &[1, 1, 8, 10])?;
        put32(out, at + 4, value)?;
        put32(out, at + 8, echo)?;
        at += 12;
    }
    if let Some(shift) = options.window_scale {
        put(out, at, &[1, 3, 3, shift])?;
        at += 4;
    }
    let blocks = options.sack_blocks();
    if !blocks.is_empty() {
        put(out, at, &[1, 1, 5, 2 + 8 * blocks.len() as u8])?;
        at += 4;
        for (left, right) in blocks {
            put32(out, at, *left)?;
            put32(out, at + 4, *right)?;
            at += 8;
        }
    }
    Some(at)
}

pub fn options_len(options: &TcpOptions) -> usize {
    let mut len = 0;
    if options.mss.is_some() {
        len += 4;
    }
    if options.sack_permitted {
        len += 4;
    }
    if options.timestamp.is_some() {
        len += 12;
    }
    if options.window_scale.is_some() {
        len += 4;
    }
    let blocks = usize::from(options.sack_len);
    if blocks > 0 {
        len += 4 + 8 * blocks;
    }
    len
}

#[derive(Clone, Copy, Debug)]
pub struct TcpHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

/// Writes a full IP packet carrying one TCP segment. `fill` writes `payload_len` bytes of
/// payload into the slice it is given. Returns the packet length.
pub fn emit_tcp(
    out: &mut [u8],
    header: &TcpHeader,
    options: &TcpOptions,
    payload_len: usize,
    checksum: L4Checksum,
    fill: impl FnOnce(&mut [u8]) -> Option<()>,
) -> Option<usize> {
    let (ip_len, head_len) = emit_tcp_headers(out, header, options, payload_len)?;
    let tcp = out.get_mut(ip_len..head_len + payload_len)?;
    fill(tcp.get_mut(head_len - ip_len..)?)?;
    let pseudo = pseudo_header(header.src.ip(), header.dst.ip(), PROTO_TCP, tcp.len());
    let sum = l4_checksum(checksum, pseudo, tcp);
    put16(tcp, 16, sum).map(|()| head_len + payload_len)
}

/// The headers of a segment whose payload follows elsewhere, with the checksum a device with
/// checksum offload completes. Returns their length.
pub fn emit_tcp_head(
    out: &mut [u8],
    header: &TcpHeader,
    options: &TcpOptions,
    payload_len: usize,
) -> Option<usize> {
    let (ip_len, head_len) = emit_tcp_headers(out, header, options, payload_len)?;
    let pseudo = pseudo_header(
        header.src.ip(),
        header.dst.ip(),
        PROTO_TCP,
        head_len - ip_len + payload_len,
    );
    put16(out.get_mut(ip_len..head_len)?, 16, fold(pseudo))?;
    Some(head_len)
}

fn emit_tcp_headers(
    out: &mut [u8],
    header: &TcpHeader,
    options: &TcpOptions,
    payload_len: usize,
) -> Option<(usize, usize)> {
    let ip_len = ip_header_len(header.src.ip());
    let opt_len = options_len(options);
    let head_len = ip_len + TCP_HEADER + opt_len;
    emit_ip(
        out,
        header.src.ip(),
        header.dst.ip(),
        PROTO_TCP,
        TCP_HEADER + opt_len + payload_len,
    )?;
    let tcp = out.get_mut(ip_len..head_len)?;
    put16(tcp, 0, header.src.port())?;
    put16(tcp, 2, header.dst.port())?;
    put32(tcp, 4, header.seq)?;
    put32(tcp, 8, header.ack)?;
    put(
        tcp,
        12,
        &[(((TCP_HEADER + opt_len) / 4) as u8) << 4, header.flags],
    )?;
    put16(tcp, 14, header.window)?;
    put(tcp, 16, &[0, 0, 0, 0])?;
    let written = emit_options(tcp.get_mut(TCP_HEADER..)?, options)?;
    (written == opt_len).then_some((ip_len, head_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 8192];
        let n = build_udp(
            &mut buf,
            src.parse().unwrap(),
            dst.parse().unwrap(),
            payload,
            L4Checksum::Full,
        )
        .unwrap();
        buf.truncate(n);
        buf
    }

    /// What a device does for NEEDS_CSUM: sum from the transport header on and store the result.
    fn complete(packet: &mut [u8], field: usize) {
        let l4_start = ip_header_len(parse_ip(packet).unwrap().src);
        let sum = finish(sum_bytes(0, &packet[l4_start..]));
        packet[l4_start + field..l4_start + field + 2].copy_from_slice(&sum.to_be_bytes());
    }

    #[test]
    fn a_pseudo_checksum_completed_by_the_device_matches_a_full_one() {
        for (src, dst) in [
            ("10.0.0.2:5000", "8.8.8.8:53"),
            ("[fd00::2]:5000", "[2001:db8::1]:53"),
        ] {
            let (src, dst) = (src.parse().unwrap(), dst.parse().unwrap());
            let mut full = vec![0u8; 2048];
            let n = build_udp(&mut full, src, dst, b"payload", L4Checksum::Full).unwrap();
            let mut partial = vec![0u8; 2048];
            let m = build_udp(&mut partial, src, dst, b"payload", L4Checksum::Pseudo).unwrap();
            complete(&mut partial[..m], 6);
            assert_eq!(partial[..m], full[..n]);

            let header = TcpHeader {
                src,
                dst,
                seq: 7,
                ack: 9,
                flags: FLAG_ACK | FLAG_PSH,
                window: 512,
            };
            let options = TcpOptions::default();
            let fill = |body: &mut [u8]| {
                body.copy_from_slice(b"abcde");
                Some(())
            };
            let n = emit_tcp(&mut full, &header, &options, 5, L4Checksum::Full, fill).unwrap();
            let m = emit_tcp(&mut partial, &header, &options, 5, L4Checksum::Pseudo, fill).unwrap();
            complete(&mut partial[..m], 16);
            assert_eq!(partial[..m], full[..n]);
        }
    }

    #[test]
    fn udp_round_trips_for_both_families() {
        for (src, dst) in [
            ("10.0.0.2:5000", "8.8.8.8:53"),
            ("[fd00::2]:5000", "[2001:db8::1]:53"),
        ] {
            let raw = udp_packet(src, dst, b"hello");
            let view = parse_ip(&raw).unwrap();
            assert_eq!(view.kind, L4Kind::Udp);
            let udp = parse_udp(&view).unwrap();
            assert_eq!(udp.payload, b"hello");
            assert_eq!((udp.src_port, udp.dst_port), (5000, 53));
        }
    }

    #[test]
    fn corrupt_checksums_and_fragments_are_reported() {
        let mut raw = udp_packet("10.0.0.2:5000", "8.8.8.8:53", b"hello");
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        let view = parse_ip(&raw).unwrap();
        assert_eq!(parse_udp(&view).err(), Some(DropReason::Checksum));

        let mut frag = udp_packet("10.0.0.2:5000", "8.8.8.8:53", b"hello");
        frag[6] = 0x20;
        frag[10] = 0;
        frag[11] = 0;
        let sum = finish(sum_bytes(0, &frag[..20]));
        frag[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(parse_ip(&frag).err(), Some(DropReason::Fragment));
        assert!(matches!(parse_packet(&frag), Ok(Parsed::Fragment(f)) if f.more && f.offset == 0));
    }

    #[test]
    fn martians_and_garbage_are_dropped() {
        let raw = udp_packet("10.0.0.2:5000", "224.0.0.251:5353", b"x");
        assert_eq!(parse_ip(&raw).err(), Some(DropReason::Martian));
        assert_eq!(parse_ip(&[]).err(), Some(DropReason::Malformed));
        assert_eq!(parse_ip(&[0x45, 0, 0]).err(), Some(DropReason::Malformed));
        assert_eq!(parse_ip(&[0x10; 64]).err(), Some(DropReason::Malformed));
        for dst in ["127.0.0.1:53", "169.254.1.1:53"] {
            let raw = udp_packet("10.0.0.2:5000", dst, b"x");
            assert_eq!(parse_ip(&raw).err(), Some(DropReason::Martian), "{dst}");
        }
        for dst in ["[::1]:53", "[fe80::1]:53"] {
            let raw = udp_packet("[fd00::2]:5000", dst, b"x");
            assert_eq!(parse_ip(&raw).err(), Some(DropReason::Martian), "{dst}");
        }
    }

    #[test]
    fn tcp_segments_round_trip_with_options() {
        let mut options = TcpOptions {
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamp: Some((11, 22)),
            ..TcpOptions::default()
        };
        options.sack[0] = (100, 200);
        options.sack_len = 1;
        let header = TcpHeader {
            src: "10.0.0.1:80".parse().unwrap(),
            dst: "10.0.0.2:5000".parse().unwrap(),
            seq: 7,
            ack: 9,
            flags: FLAG_ACK | FLAG_PSH,
            window: 1234,
        };
        let mut out = [0u8; 256];
        let n = emit_tcp(&mut out, &header, &options, 3, L4Checksum::Full, |body| {
            body.get_mut(..3)?.copy_from_slice(b"abc");
            Some(())
        })
        .unwrap();
        let view = parse_ip(&out[..n]).unwrap();
        assert!(tcp_checksum_ok(view.src, view.dst, view.l4));
        let seg = parse_tcp(view.l4).unwrap();
        assert_eq!(seg.payload, b"abc");
        assert_eq!((seg.seq, seg.ack, seg.window), (7, 9, 1234));
        assert_eq!(seg.options, options);
    }

    #[test]
    fn echo_requests_get_a_swapped_reply() {
        let mut raw = vec![0u8; 32];
        emit_ip(
            &mut raw,
            "10.0.0.2".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            PROTO_ICMP,
            12,
        )
        .unwrap();
        raw[20..32].copy_from_slice(&[8, 0, 0, 0, 0, 7, 0, 9, 1, 2, 3, 4]);
        let sum = finish(sum_bytes(0, &raw[20..32]));
        raw[22..24].copy_from_slice(&sum.to_be_bytes());
        let view = parse_ip(&raw).unwrap();
        let mut out = [0u8; 64];
        let n = build_echo_reply(&mut out, &view).unwrap();
        let reply = parse_ip(&out[..n]).unwrap();
        assert_eq!(reply.src, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(reply.l4[0], 0);
        assert_eq!(fold(sum_bytes(0, reply.l4)), 0xffff);
    }

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn random_and_mutated_bytes_never_panic() {
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        let seed = udp_packet("10.0.0.2:5000", "8.8.8.8:53", b"hello world");
        for round in 0..200_000 {
            let mut packet = if round % 2 == 0 {
                let len = (rng.next() % 200) as usize;
                (0..len).map(|_| rng.next() as u8).collect::<Vec<_>>()
            } else {
                let mut packet = seed.clone();
                let at = (rng.next() as usize) % packet.len();
                packet[at] = rng.next() as u8;
                packet
            };
            if let Some(first) = packet.first_mut() {
                *first = if rng.next().is_multiple_of(2) {
                    0x45
                } else {
                    0x60
                };
            }
            if let Ok(Parsed::Packet(view)) = parse_packet(&packet) {
                let _ = parse_udp(&view);
                let _ = parse_tcp(view.l4);
                let mut out = [0u8; 2048];
                let _ = build_echo_reply(&mut out, &view);
            }
        }
    }

    fn cut(packet: &[u8], mtu: usize, ident: u32) -> Vec<Vec<u8>> {
        (0..fragment_count(packet, mtu).unwrap())
            .map(|index| {
                let mut out = vec![0u8; mtu];
                let n = write_fragment(packet, mtu, ident, index, &mut out).unwrap();
                out.truncate(n);
                out
            })
            .collect()
    }

    fn rebuilt(frags: &[Vec<u8>]) -> Vec<u8> {
        let mut reassembler = crate::frag::Reassembler::default();
        let mut out = Vec::new();
        let mut done = 0;
        for frag in frags {
            let Ok(Parsed::Fragment(view)) = parse_packet(frag) else {
                panic!("expected a fragment");
            };
            if reassembler.push(&view, 0, &mut out) {
                done += 1;
            }
        }
        assert_eq!(done, 1);
        out
    }

    #[test]
    fn an_ipv4_datagram_is_cut_on_eight_byte_blocks() {
        let payload: Vec<u8> = (0..3000).map(|i| i as u8).collect();
        let packet = udp_packet("8.8.8.8:53", "10.0.0.2:5000", &payload);
        let frags = cut(&packet, 1500, 0xbeef);
        assert_eq!(frags.len(), 3);
        let mut offset = 0;
        for (i, frag) in frags.iter().enumerate() {
            let last = i + 1 == frags.len();
            assert!(frag.len() <= 1500);
            assert_eq!(usize::from(be16(frag, 2).unwrap()), frag.len());
            assert_eq!(be16(frag, 4), Some(0xbeef));
            let field = be16(frag, 6).unwrap();
            assert_eq!(field & 0x4000, 0, "DF must be clear");
            assert_eq!(field & FRAG_MORE != 0, !last);
            assert_eq!(usize::from(field & 0x1fff) * 8, offset);
            assert_eq!(finish(sum_bytes(0, &frag[..IPV4_HEADER])), 0);
            offset += frag.len() - IPV4_HEADER;
        }
        assert_eq!(frags[0].len(), 1500);
        assert_eq!((frags[0].len() - IPV4_HEADER) % 8, 0);
        let whole = rebuilt(&frags);
        let Ok(Parsed::Packet(view)) = parse_packet(&whole) else {
            panic!("expected a whole packet");
        };
        assert_eq!(parse_udp(&view).unwrap().payload, &payload[..]);
    }

    #[test]
    fn an_ipv6_datagram_gets_a_fragment_header() {
        let payload: Vec<u8> = (0..4000).map(|i| (i * 7) as u8).collect();
        let packet = udp_packet("[2001:db8::1]:53", "[2001:db8::2]:5000", &payload);
        let frags = cut(&packet, 1280, 0x0102_0304);
        assert_eq!(frags.len(), 4);
        let mut offset = 0;
        for (i, frag) in frags.iter().enumerate() {
            let last = i + 1 == frags.len();
            assert!(frag.len() <= 1280);
            assert_eq!(frag[6], PROTO_IPV6_FRAG);
            assert_eq!(frag[IPV6_HEADER], PROTO_UDP);
            assert_eq!(
                usize::from(be16(frag, 4).unwrap()),
                frag.len() - IPV6_HEADER
            );
            let field = be16(frag, IPV6_HEADER + 2).unwrap();
            assert_eq!(field & 1 != 0, !last);
            assert_eq!(usize::from(field & 0xfff8), offset);
            assert_eq!(be32(frag, IPV6_HEADER + 4), Some(0x0102_0304));
            offset += frag.len() - IPV6_HEADER - IPV6_FRAG_HEADER;
        }
        let whole = rebuilt(&frags);
        let Ok(Parsed::Packet(view)) = parse_packet(&whole) else {
            panic!("expected a whole packet");
        };
        assert_eq!(parse_udp(&view).unwrap().payload, &payload[..]);
    }

    #[test]
    fn a_packet_that_fits_is_one_fragment_and_a_tiny_mtu_is_refused() {
        let packet = udp_packet("8.8.8.8:53", "10.0.0.2:5000", &[1; 100]);
        assert_eq!(fragment_count(&packet, 1500), Some(1));
        assert_eq!(fragment_count(&packet, 24), None);
    }
}
