//! The virtio-net header a Linux TUN opened with `IFF_VNET_HDR` puts before every packet.

use std::io::{self, IoSlice};
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use concord_netstack::wire::{finish, fold, pseudo_header, sum_bytes};

pub const HEADER_LEN: usize = 10;

/// TCP payload per frame for the kernel to segment, leaving room for headers under 64 KiB.
pub const SEGMENT_LIMIT: usize = 61_440;

const F_NEEDS_CSUM: u8 = 1;
const GSO_TCPV4: u8 = 1;
const GSO_TCPV6: u8 = 4;
const GSO_UDP_L4: u8 = 5;
const GSO_ECN: u8 = 0x80;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// Turns off the UDP segmentation tun-rs enables where it can: the stack takes a TCP
/// aggregate as one segment, but a UDP one would have to be split into datagrams first.
pub fn restrict_to_tcp(fd: RawFd) -> io::Result<()> {
    let flags = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
    #[allow(unsafe_code, reason = "TUNSETOFFLOAD has no safe wrapper")]
    // SAFETY: `fd` is an open TUN descriptor and the argument is a plain flag word.
    let result = unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD, libc::c_ulong::from(flags)) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn packet_len(buf: &[u8], read: usize) -> usize {
    let gso_type = buf.get(1).copied().unwrap_or_default() & !GSO_ECN;
    if read <= HEADER_LEN || gso_type == GSO_UDP_L4 {
        return 0;
    }
    read - HEADER_LEN
}

pub fn header_for(packet: &[u8], segment: u16) -> [u8; HEADER_LEN] {
    let version = packet.first().map(|b| b >> 4);
    let (l4_start, proto) = match version {
        Some(4) => (
            usize::from(packet.first().copied().unwrap_or_default() & 0x0f) * 4,
            packet.get(9).copied(),
        ),
        Some(6) => (40, packet.get(6).copied()),
        _ => (0, None),
    };
    if version == Some(4)
        && matches!(packet.get(6..8), Some(&[flags, offset]) if flags & 0x3f != 0 || offset != 0)
    {
        return [0; HEADER_LEN];
    }
    let offset: u16 = match proto {
        Some(PROTO_TCP) => 16,
        Some(PROTO_UDP) => 6,
        _ => return [0; HEADER_LEN],
    };
    let mut header = [0u8; HEADER_LEN];
    header[0] = F_NEEDS_CSUM;
    header[6..8].copy_from_slice(&(l4_start as u16).to_ne_bytes());
    header[8..10].copy_from_slice(&offset.to_ne_bytes());
    if segment > 0 && proto == Some(PROTO_TCP) {
        let tcp_len = usize::from(packet.get(l4_start + 12).copied().unwrap_or_default() >> 4) * 4;
        header[1] = if version == Some(4) {
            GSO_TCPV4
        } else {
            GSO_TCPV6
        };
        header[2..4].copy_from_slice(&((l4_start + tcp_len) as u16).to_ne_bytes());
        header[4..6].copy_from_slice(&segment.to_ne_bytes());
    }
    header
}

/// The most datagrams one merged UDP frame carries; the kernel takes up to 128.
pub const UDP_RUN_LIMIT: usize = 32;

const MERGED_LIMIT: usize = 65_535;
const UDP_HEADER: usize = 8;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;

/// The IP and UDP header length of a datagram the kernel can segment, or `None`.
fn udp_header_len(packet: &[u8]) -> Option<usize> {
    let ip = match packet.first()? {
        0x45 => {
            let total = u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]);
            let fragmented = matches!(
                packet.get(6..8),
                Some(&[flags, offset]) if flags & 0x3f != 0 || offset != 0
            );
            if *packet.get(9)? != PROTO_UDP || fragmented || usize::from(total) != packet.len() {
                return None;
            }
            IPV4_HEADER
        }
        byte if byte >> 4 == 6 => {
            let payload = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]);
            if *packet.get(6)? != PROTO_UDP || usize::from(payload) + IPV6_HEADER != packet.len() {
                return None;
            }
            IPV6_HEADER
        }
        _ => return None,
    };
    (packet.len() > ip + UDP_HEADER).then_some(ip + UDP_HEADER)
}

/// The addresses and ports, which every datagram of one frame shares.
fn flow_bytes(packet: &[u8], headers: usize) -> Option<&[u8]> {
    if headers == IPV4_HEADER + UDP_HEADER {
        packet.get(12..24)
    } else {
        packet.get(8..44)
    }
}

/// How many datagrams at the front of `packets` one frame can carry, 0 when the first cannot be
/// merged. As in sing-tun, they share a flow and the first one's size, and only the last is shorter.
pub fn udp_run(packets: &[&[u8]]) -> usize {
    let Some((first, rest)) = packets.split_first() else {
        return 0;
    };
    let Some(headers) = udp_header_len(first) else {
        return 0;
    };
    let size = first.len() - headers;
    let flow = flow_bytes(first, headers);
    let mut total = first.len();
    let mut run = 1;
    for next in rest.iter().take(UDP_RUN_LIMIT - 1) {
        if udp_header_len(next) != Some(headers) || flow_bytes(next, headers) != flow {
            break;
        }
        let len = next.len() - headers;
        if len > size || total + len > MERGED_LIMIT {
            break;
        }
        total += len;
        run += 1;
        if len < size {
            break;
        }
    }
    run
}

/// The front of one frame that carries a run of datagrams.
pub struct MergedUdp {
    pub vnet: [u8; HEADER_LEN],
    headers: [u8; IPV6_HEADER + UDP_HEADER],
    len: usize,
}

impl MergedUdp {
    pub fn headers(&self) -> &[u8] {
        self.headers.get(..self.len).unwrap_or_default()
    }
}

/// The front of the frame for `run`, which `udp_run` accepted.
pub fn merged_udp(run: &[&[u8]]) -> Option<MergedUdp> {
    let first = run.first()?;
    let headers = udp_header_len(first)?;
    let ip = headers - UDP_HEADER;
    let payload: usize = run.iter().map(|packet| packet.len() - headers).sum();
    let udp_len = u16::try_from(UDP_HEADER + payload).ok()?;
    let mut out = [0u8; IPV6_HEADER + UDP_HEADER];
    out.get_mut(..headers)?
        .copy_from_slice(first.get(..headers)?);
    let (src, dst) = if ip == IPV4_HEADER {
        let total = u16::try_from(headers + payload).ok()?;
        out.get_mut(2..4)?.copy_from_slice(&total.to_be_bytes());
        out.get_mut(10..12)?.copy_from_slice(&[0, 0]);
        let sum = finish(sum_bytes(0, out.get(..IPV4_HEADER)?));
        out.get_mut(10..12)?.copy_from_slice(&sum.to_be_bytes());
        (
            IpAddr::from(<[u8; 4]>::try_from(out.get(12..16)?).ok()?),
            IpAddr::from(<[u8; 4]>::try_from(out.get(16..20)?).ok()?),
        )
    } else {
        out.get_mut(4..6)?.copy_from_slice(&udp_len.to_be_bytes());
        (
            IpAddr::from(<[u8; 16]>::try_from(out.get(8..24)?).ok()?),
            IpAddr::from(<[u8; 16]>::try_from(out.get(24..40)?).ok()?),
        )
    };
    let sum = fold(pseudo_header(src, dst, PROTO_UDP, usize::from(udp_len)));
    out.get_mut(ip + 4..ip + 6)?
        .copy_from_slice(&udp_len.to_be_bytes());
    out.get_mut(ip + 6..ip + 8)?
        .copy_from_slice(&sum.to_be_bytes());
    let segment = u16::try_from(first.len() - headers).ok()?;
    let mut vnet = [0u8; HEADER_LEN];
    vnet[0] = F_NEEDS_CSUM;
    vnet[1] = GSO_UDP_L4;
    vnet[2..4].copy_from_slice(&(headers as u16).to_ne_bytes());
    vnet[4..6].copy_from_slice(&segment.to_ne_bytes());
    vnet[6..8].copy_from_slice(&(ip as u16).to_ne_bytes());
    vnet[8..10].copy_from_slice(&6u16.to_ne_bytes());
    Some(MergedUdp {
        vnet,
        headers: out,
        len: headers,
    })
}

/// Writes packets from the front of `packets` and returns how many it consumed, sent or counted
/// in `failed`; 0 when the first write would block. A UDP run goes out as one frame while
/// `merging` holds. A frame the kernel refuses turns merging off for good, and that run is sent
/// again one datagram at a time; what was written before it stays counted once.
pub fn send_packets(
    packets: &[&[u8]],
    merging: &AtomicBool,
    failed: &mut usize,
    mut write: impl FnMut(&[IoSlice<'_>]) -> io::Result<usize>,
) -> usize {
    let mut done = 0;
    while let Some(rest) = packets.get(done..).filter(|rest| !rest.is_empty()) {
        let run = if merging.load(Ordering::Relaxed) {
            udp_run(rest)
        } else {
            0
        };
        if run > 1
            && let Some(frame) = rest.get(..run)
            && let Some(merged) = merged_udp(frame)
        {
            let mut parts = [IoSlice::new(&[]); UDP_RUN_LIMIT + 2];
            parts[0] = IoSlice::new(&merged.vnet);
            parts[1] = IoSlice::new(merged.headers());
            for (part, packet) in parts.iter_mut().skip(2).zip(frame) {
                *part = IoSlice::new(packet.get(merged.len..).unwrap_or_default());
            }
            match write(parts.get(..run + 2).unwrap_or_default()) {
                Ok(_) => done += run,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return done,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) if refused(&err) => {
                    if merging.swap(false, Ordering::Relaxed) {
                        tracing::warn!("tun refused a merged UDP frame, sending datagrams: {err}");
                    }
                }
                Err(_) => {
                    *failed += run;
                    done += run;
                }
            }
            continue;
        }
        let Some(packet) = rest.first() else {
            break;
        };
        let header = header_for(packet, 0);
        match write(&[IoSlice::new(&header), IoSlice::new(packet)]) {
            Ok(_) => done += 1,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return done,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                *failed += 1;
                done += 1;
            }
        }
    }
    done
}

fn refused(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL | libc::EIO | libc::EOPNOTSUPP)
    )
}

#[cfg(test)]
mod tests {
    use concord_netstack::wire::{
        FLAG_ACK, L4Checksum, TcpHeader, TcpOptions, build_udp, emit_tcp, parse_ip, parse_udp,
    };

    use super::*;

    #[test]
    fn the_header_points_the_kernel_at_the_transport_checksum() {
        let mut packet = [0u8; 128];
        let len = build_udp(
            &mut packet,
            "10.0.0.2:5000".parse().unwrap(),
            "10.0.0.1:53".parse().unwrap(),
            b"query",
            L4Checksum::Pseudo,
        )
        .unwrap();
        let header = header_for(&packet[..len], 0);
        assert_eq!(header[0], F_NEEDS_CSUM);
        let start = usize::from(u16::from_ne_bytes([header[6], header[7]]));
        let offset = usize::from(u16::from_ne_bytes([header[8], header[9]]));
        assert_eq!((start, offset), (20, 6));

        let mut sum: u32 = 0;
        for pair in packet[start..len].chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let field = start + offset;
        packet[field..field + 2].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        let view = parse_ip(&packet[..len]).unwrap();
        assert_eq!(parse_udp(&view).unwrap().payload, b"query");
    }

    #[test]
    fn a_segmented_frame_names_its_headers_and_segment_size() {
        let mut frame = [0u8; 2048];
        let header = TcpHeader {
            src: "[fd00::1]:443".parse().unwrap(),
            dst: "[fd00::2]:40000".parse().unwrap(),
            seq: 1,
            ack: 1,
            flags: FLAG_ACK,
            window: 1024,
        };
        let options = TcpOptions {
            timestamp: Some((1, 2)),
            ..TcpOptions::default()
        };
        let len = emit_tcp(
            &mut frame,
            &header,
            &options,
            1800,
            L4Checksum::Pseudo,
            |_| Some(()),
        )
        .unwrap();
        let vnet = header_for(&frame[..len], 1200);
        assert_eq!(vnet[1], GSO_TCPV6);
        assert_eq!(u16::from_ne_bytes([vnet[2], vnet[3]]), 40 + 32);
        assert_eq!(u16::from_ne_bytes([vnet[4], vnet[5]]), 1200);
        assert_eq!(u16::from_ne_bytes([vnet[6], vnet[7]]), 40);
        assert_eq!(header_for(&frame[..len], 0)[1], 0);
    }

    #[test]
    fn ipv4_fragments_carry_no_offload_request() {
        let mut first = [0u8; 40];
        first[0] = 0x45;
        first[9] = PROTO_UDP;
        first[6] = 0x20;
        assert_eq!(header_for(&first, 0), [0; HEADER_LEN]);
        first[6] = 0;
        first[7] = 185;
        assert_eq!(header_for(&first, 0), [0; HEADER_LEN]);
        first[7] = 0;
        assert_eq!(header_for(&first, 0)[0], F_NEEDS_CSUM);
    }

    #[test]
    fn icmp_goes_out_without_offload_and_udp_aggregates_are_refused() {
        let echo = [0x45u8, 0, 0, 28, 0, 0, 0, 0, 64, 1];
        assert_eq!(header_for(&echo, 1400), [0; HEADER_LEN]);
        let mut read = [0u8; 64];
        read[1] = GSO_UDP_L4;
        assert_eq!(packet_len(&read, 40), 0);
        read[1] = 1;
        assert_eq!(packet_len(&read, 40), 30);
        assert_eq!(packet_len(&read, HEADER_LEN), 0);
    }

    fn udp(src: &str, dst: &str, size: usize) -> Vec<u8> {
        let mut out = vec![0u8; size + 48];
        let payload: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let len = build_udp(
            &mut out,
            src.parse().unwrap(),
            dst.parse().unwrap(),
            &payload,
            L4Checksum::Pseudo,
        )
        .unwrap();
        out.truncate(len);
        out
    }

    const REPLY: (&str, &str) = ("1.1.1.1:443", "10.0.0.2:5000");

    #[test]
    fn a_run_holds_one_flow_and_ends_at_a_shorter_datagram() {
        let a = udp(REPLY.0, REPLY.1, 100);
        let short = udp(REPLY.0, REPLY.1, 60);
        assert_eq!(udp_run(&[&a, &a, &short, &a]), 3);
        assert_eq!(udp_run(&[&a, &a, &a]), 3);
        assert_eq!(udp_run(&[&a]), 1);
        assert_eq!(udp_run(&[]), 0);
    }

    #[test]
    fn a_run_breaks_at_another_flow_or_a_longer_datagram() {
        let a = udp(REPLY.0, REPLY.1, 100);
        let port = udp(REPLY.0, "10.0.0.2:5001", 100);
        let host = udp("1.1.1.2:443", REPLY.1, 100);
        let long = udp(REPLY.0, REPLY.1, 101);
        let v6 = udp("[2001:db8::1]:443", "[fd00::2]:5000", 100);
        assert_eq!(udp_run(&[&a, &port]), 1);
        assert_eq!(udp_run(&[&a, &host]), 1);
        assert_eq!(udp_run(&[&a, &long]), 1);
        assert_eq!(udp_run(&[&a, &v6]), 1);
        assert_eq!(udp_run(&[&v6, &v6, &v6]), 3);
    }

    #[test]
    fn a_run_stops_at_the_frame_and_segment_limits() {
        let big = udp(REPLY.0, REPLY.1, 4000);
        let many = vec![big.as_slice(); 40];
        assert_eq!(udp_run(&many), 16);
        let small = udp(REPLY.0, REPLY.1, 10);
        let many = vec![small.as_slice(); 40];
        assert_eq!(udp_run(&many), UDP_RUN_LIMIT);
    }

    #[test]
    fn fragments_options_and_other_protocols_are_not_merged() {
        let a = udp(REPLY.0, REPLY.1, 100);
        let mut fragment = a.clone();
        fragment[6] = 0x20;
        assert_eq!(udp_run(&[&fragment, &fragment]), 0);
        let mut options = a.clone();
        options[0] = 0x46;
        assert_eq!(udp_run(&[&options, &options]), 0);
        let mut tcp = a.clone();
        tcp[9] = PROTO_TCP;
        assert_eq!(udp_run(&[&tcp, &tcp]), 0);
        let empty = udp(REPLY.0, REPLY.1, 0);
        assert_eq!(udp_run(&[&empty, &empty]), 0);
        assert_eq!(udp_run(&[&a, &fragment]), 1);
    }

    #[test]
    fn a_merged_frame_carries_the_lengths_and_checksums_of_the_whole_run() {
        let a = udp(REPLY.0, REPLY.1, 100);
        let short = udp(REPLY.0, REPLY.1, 30);
        let merged = merged_udp(&[&a, &a, &short]).unwrap();
        let (vnet, headers) = (merged.vnet, merged.headers());
        assert_eq!(headers.len(), 28);
        let ip = &headers[..20];
        assert_eq!(u16::from_be_bytes([ip[2], ip[3]]), 28 + 230);
        assert_eq!(finish(sum_bytes(0, ip)), 0);
        let udp_len = u16::from_be_bytes([headers[24], headers[25]]);
        assert_eq!(udp_len, 8 + 230);
        let pseudo = pseudo_header(
            "1.1.1.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            PROTO_UDP,
            238,
        );
        assert_eq!(u16::from_be_bytes([headers[26], headers[27]]), fold(pseudo));
        assert_eq!(&headers[20..24], &a[20..24]);
        assert_eq!((vnet[0], vnet[1]), (F_NEEDS_CSUM, GSO_UDP_L4));
        assert_eq!(u16::from_ne_bytes([vnet[2], vnet[3]]), 28);
        assert_eq!(u16::from_ne_bytes([vnet[4], vnet[5]]), 100);
        assert_eq!(u16::from_ne_bytes([vnet[6], vnet[7]]), 20);
        assert_eq!(u16::from_ne_bytes([vnet[8], vnet[9]]), 6);

        let v6 = udp("[2001:db8::1]:443", "[fd00::2]:5000", 100);
        let merged = merged_udp(&[&v6, &v6]).unwrap();
        let (vnet, headers) = (merged.vnet, merged.headers());
        assert_eq!(headers.len(), 48);
        assert_eq!(u16::from_be_bytes([headers[4], headers[5]]), 208);
        assert_eq!(u16::from_be_bytes([headers[44], headers[45]]), 208);
        assert_eq!(u16::from_ne_bytes([vnet[6], vnet[7]]), 40);
    }

    struct Writes {
        calls: Vec<Vec<u8>>,
        written: Vec<Vec<u8>>,
        answers: Vec<io::Result<usize>>,
    }

    impl Writes {
        fn new(answers: Vec<io::Result<usize>>) -> Self {
            Writes {
                calls: Vec::new(),
                written: Vec::new(),
                answers,
            }
        }

        fn write(&mut self, parts: &[IoSlice<'_>]) -> io::Result<usize> {
            let bytes: Vec<u8> = parts.iter().flat_map(|part| part.iter().copied()).collect();
            self.calls.push(bytes.clone());
            let answer = if self.answers.is_empty() {
                Ok(bytes.len())
            } else {
                self.answers.remove(0)
            };
            if answer.is_ok() {
                self.written.push(bytes[HEADER_LEN..].to_vec());
            }
            answer
        }
    }

    #[test]
    fn a_run_goes_out_as_one_frame_of_its_payloads() {
        let a = udp(REPLY.0, REPLY.1, 100);
        let merging = AtomicBool::new(true);
        let mut writes = Writes::new(Vec::new());
        let mut failed = 0;
        let sent = send_packets(&[&a, &a, &a], &merging, &mut failed, |parts| {
            writes.write(parts)
        });
        assert_eq!((sent, failed, writes.calls.len()), (3, 0, 1));
        let mut expected = merged_udp(&[&a, &a, &a]).unwrap().headers().to_vec();
        for _ in 0..3 {
            expected.extend_from_slice(&a[28..]);
        }
        assert_eq!(writes.written, vec![expected]);
    }

    #[test]
    fn a_refused_frame_after_earlier_writes_sends_its_run_once_one_by_one() {
        let other = udp(REPLY.0, "10.0.0.3:6000", 50);
        let a = udp(REPLY.0, REPLY.1, 100);
        let b = udp(REPLY.0, REPLY.1, 80);
        let merging = AtomicBool::new(true);
        let mut writes = Writes::new(vec![
            Ok(78),
            Err(io::Error::from_raw_os_error(libc::EINVAL)),
        ]);
        let mut failed = 0;
        let packets: [&[u8]; 4] = [&other, &a, &a, &b];
        let sent = send_packets(&packets, &merging, &mut failed, |parts| writes.write(parts));
        assert_eq!((sent, failed), (4, 0));
        assert!(!merging.load(Ordering::Relaxed));
        assert_eq!(writes.calls.len(), 5);
        let expected: Vec<Vec<u8>> = packets.iter().map(|packet| packet.to_vec()).collect();
        assert_eq!(writes.written, expected);

        let mut writes = Writes::new(Vec::new());
        let sent = send_packets(&[&a, &a], &merging, &mut failed, |parts| {
            writes.write(parts)
        });
        assert_eq!((sent, writes.calls.len()), (2, 2));
    }

    #[test]
    fn a_blocked_write_returns_what_went_out_before_it() {
        let other = udp(REPLY.0, "10.0.0.3:6000", 50);
        let a = udp(REPLY.0, REPLY.1, 100);
        let merging = AtomicBool::new(true);
        let mut writes = Writes::new(vec![Ok(78), Err(io::ErrorKind::WouldBlock.into())]);
        let mut failed = 0;
        let sent = send_packets(&[&other, &a, &a], &merging, &mut failed, |parts| {
            writes.write(parts)
        });
        assert_eq!((sent, failed), (1, 0));
        assert!(merging.load(Ordering::Relaxed));

        let mut writes = Writes::new(vec![
            Err(io::ErrorKind::Interrupted.into()),
            Err(io::Error::from_raw_os_error(libc::ENOBUFS)),
        ]);
        let sent = send_packets(&[&a, &a, &other], &merging, &mut failed, |parts| {
            writes.write(parts)
        });
        assert_eq!((sent, failed, writes.calls.len()), (3, 2, 3));
    }
}
