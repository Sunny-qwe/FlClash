//! TCP counters of the core's own sockets, read with `INET_DIAG` at the two edges of a window.
//!
//! The near leg is the core's accepted connections on its mixed port; the far leg is every other TCP socket the
//! core holds (to the server, or to the origin for `direct`). Only sockets present at both ends of the window
//! count, matched by their kernel cookie.

use std::collections::HashMap;

use crate::load::Metrics;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tcp {
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub segs_in: u32,
    pub segs_out: u32,
    pub data_segs_in: u32,
    pub data_segs_out: u32,
    pub total_retrans: u32,
    pub rcv_rtt_us: u32,
    pub rcv_space: u32,
    pub rcv_wnd: u32,
    pub notsent_bytes: u32,
    pub busy_us: u64,
    pub rwnd_limited_us: u64,
    pub sndbuf_limited_us: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leg {
    Near,
    Far,
}

pub struct Snapshot {
    sockets: HashMap<u64, (Leg, Tcp)>,
}

pub fn snapshot(core: u32, mixed_port: Option<u16>) -> Option<Snapshot> {
    let owned = imp::socket_inodes(core)?;
    let sockets = imp::dump()?
        .into_iter()
        .filter(|row| owned.contains(&row.inode))
        .map(|row| {
            let leg = if Some(row.local_port) == mixed_port {
                Leg::Near
            } else {
                Leg::Far
            };
            (row.cookie, (leg, row.tcp))
        })
        .collect();
    Some(Snapshot { sockets })
}

/// The server's sockets on the link to the core, read inside the server's namespace: those whose peer has another
/// address, which leaves out its connections to the origin beside it.
pub fn snapshot_link(server: u32, netns: &str) -> Option<Snapshot> {
    let owned = imp::socket_inodes(server)?;
    let sockets = crate::isolate::in_netns(netns, imp::dump)??
        .into_iter()
        .filter(|row| owned.contains(&row.inode) && !row.peer_is_self)
        .map(|row| (row.cookie, (Leg::Far, row.tcp)))
        .collect();
    Some(Snapshot { sockets })
}

/// Sockets below this many bytes in the window are control connections, not the workload's flows.
const FLOW_BYTES: u64 = 1_000_000;

fn flows<'a>(
    before: &'a Snapshot,
    after: &'a Snapshot,
) -> impl Iterator<Item = (&'a Tcp, &'a Tcp)> {
    after.sockets.iter().filter_map(|(cookie, (leg, end))| {
        let (_, start) = before.sockets.get(cookie).filter(|_| *leg == Leg::Far)?;
        let moved = (end.bytes_received + end.bytes_sent)
            .saturating_sub(start.bytes_received + start.bytes_sent);
        (moved >= FLOW_BYTES).then_some((start, end))
    })
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    values.sort_by(f64::total_cmp);
    (!values.is_empty()).then(|| crate::stats::quantile(&values, 0.5))
}

/// Receive autotuning of the core's far-leg flows as the window closes, the median over the flows.
pub fn receive_state(before: &Snapshot, after: &Snapshot, m: &mut Metrics) {
    for (key, read) in [
        ("far_rcv_rtt_us", (|t| t.rcv_rtt_us) as fn(&Tcp) -> u32),
        ("far_rcv_space_bytes", |t| t.rcv_space),
        ("far_rcv_wnd_bytes", |t| t.rcv_wnd),
    ] {
        let values = flows(before, after).map(|(_, end)| f64::from(read(end)));
        if let Some(value) = median(values.collect()) {
            m.insert(key.into(), value);
        }
    }
}

/// How the server's flows to the core spent a window of `seconds`: the share of it they had data to send, the
/// shares of that time the core's receive window or their own send buffer held them, how many of them the receive
/// window held for at least half the window, and what was still unsent as it closed.
pub fn link_metrics(before: &Snapshot, after: &Snapshot, seconds: f64, m: &mut Metrics) {
    let (mut count, mut held, mut busy, mut rwnd, mut sndbuf) = (0u64, 0u64, 0u64, 0u64, 0u64);
    for (start, end) in flows(before, after) {
        let flow_rwnd = end.rwnd_limited_us.saturating_sub(start.rwnd_limited_us);
        count += 1;
        held += u64::from(flow_rwnd as f64 >= seconds * 0.5e6);
        busy += end.busy_us.saturating_sub(start.busy_us);
        rwnd += flow_rwnd;
        sndbuf += end
            .sndbuf_limited_us
            .saturating_sub(start.sndbuf_limited_us);
    }
    if count == 0 || seconds <= 0.0 {
        return;
    }
    m.insert("server_link_flows".into(), count as f64);
    m.insert("server_link_rwnd_held_flows".into(), held as f64);
    m.insert(
        "server_link_busy_share".into(),
        busy as f64 / (count as f64 * seconds * 1e6),
    );
    if busy > 0 {
        m.insert(
            "server_link_rwnd_limited_share".into(),
            rwnd as f64 / busy as f64,
        );
        m.insert(
            "server_link_sndbuf_limited_share".into(),
            sndbuf as f64 / busy as f64,
        );
    }
    let unsent = flows(before, after).map(|(_, end)| f64::from(end.notsent_bytes));
    if let Some(value) = median(unsent.collect()) {
        m.insert("server_link_unsent_bytes".into(), value);
    }
}

#[derive(Default)]
struct Sum {
    bytes_received: u64,
    bytes_sent: u64,
    segs_in: u64,
    segs_out: u64,
    data_segs_in: u64,
    data_segs_out: u64,
    retrans: u64,
}

/// Returns the bytes the core received and sent on all its TCP sockets over the window.
pub fn metrics(before: &Snapshot, after: &Snapshot, m: &mut Metrics) -> (u64, u64) {
    let mut total = (0, 0);
    for (leg, prefix) in [(Leg::Near, "near"), (Leg::Far, "far")] {
        let mut sum = Sum::default();
        for (cookie, (l, end)) in &after.sockets {
            let Some((_, start)) = before.sockets.get(cookie).filter(|(l2, _)| l2 == l) else {
                continue;
            };
            if *l != leg {
                continue;
            }
            sum.bytes_received += end.bytes_received.saturating_sub(start.bytes_received);
            sum.bytes_sent += end.bytes_sent.saturating_sub(start.bytes_sent);
            sum.segs_in += u64::from(end.segs_in.wrapping_sub(start.segs_in));
            sum.segs_out += u64::from(end.segs_out.wrapping_sub(start.segs_out));
            sum.data_segs_in += u64::from(end.data_segs_in.wrapping_sub(start.data_segs_in));
            sum.data_segs_out += u64::from(end.data_segs_out.wrapping_sub(start.data_segs_out));
            sum.retrans += u64::from(end.total_retrans.wrapping_sub(start.total_retrans));
        }
        total.0 += sum.bytes_received;
        total.1 += sum.bytes_sent;
        let wire_mb = (sum.bytes_received + sum.bytes_sent) as f64 / 1e6;
        if wire_mb <= 0.0 {
            continue;
        }
        if sum.data_segs_in > 0 {
            m.insert(
                format!("{prefix}_rx_segment_bytes"),
                sum.bytes_received as f64 / sum.data_segs_in as f64,
            );
        }
        if sum.data_segs_out > 0 {
            m.insert(
                format!("{prefix}_tx_segment_bytes"),
                sum.bytes_sent as f64 / sum.data_segs_out as f64,
            );
        }
        m.insert(
            format!("{prefix}_nondata_rx_per_mb"),
            sum.segs_in.saturating_sub(sum.data_segs_in) as f64 / wire_mb,
        );
        m.insert(
            format!("{prefix}_nondata_tx_per_mb"),
            sum.segs_out.saturating_sub(sum.data_segs_out) as f64 / wire_mb,
        );
        m.insert(
            format!("{prefix}_retrans_per_mb"),
            sum.retrans as f64 / wire_mb,
        );
    }
    total
}

struct Row {
    inode: u64,
    cookie: u64,
    local_port: u16,
    peer_is_self: bool,
    tcp: Tcp,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(
    unsafe_code,
    reason = "a NETLINK_SOCK_DIAG socket has no safe wrapper; every buffer passed is a live local"
)]
mod imp {
    use std::collections::HashSet;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{Row, Tcp};

    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_DUMP: u16 = 0x300;
    const INET_DIAG_INFO: u16 = 2;
    /// `struct inet_diag_msg`; the attributes follow it.
    const DIAG_MSG_LEN: usize = 72;
    /// `tcp_info` up to and including `tcpi_bytes_sent` (Linux 4.19).
    const TCP_INFO_MIN: usize = 208;

    pub fn socket_inodes(pid: u32) -> Option<HashSet<u64>> {
        let dir = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        Some(
            dir.filter_map(|entry| {
                let target = std::fs::read_link(entry.ok()?.path()).ok()?;
                target
                    .to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse()
                    .ok()
            })
            .collect(),
        )
    }

    pub fn dump() -> Option<Vec<Row>> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return None;
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut rows = Vec::new();
        for (seq, family) in [(1u32, libc::AF_INET), (2, libc::AF_INET6)] {
            request(&socket, seq, family as u8)?;
            receive(&socket, seq, &mut rows)?;
        }
        Some(rows)
    }

    fn request(socket: &OwnedFd, seq: u32, family: u8) -> Option<()> {
        let mut message = Vec::with_capacity(72);
        message.extend_from_slice(&72u32.to_ne_bytes());
        message.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        message.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        message.extend_from_slice(&seq.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(&[
            family,
            libc::IPPROTO_TCP as u8,
            1 << (INET_DIAG_INFO - 1),
            0,
        ]);
        message.extend_from_slice(&u32::MAX.to_ne_bytes());
        message.resize(72, 0);
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
            )
        };
        (sent == message.len() as isize).then_some(())
    }

    fn receive(socket: &OwnedFd, seq: u32, rows: &mut Vec<Row>) -> Option<()> {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n =
                unsafe { libc::recv(socket.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n <= 0 {
                return None;
            }
            let mut data = &buf[..n as usize];
            while data.len() >= 16 {
                let len = u32::from_ne_bytes(data[0..4].try_into().ok()?) as usize;
                let kind = u16::from_ne_bytes(data[4..6].try_into().ok()?);
                let got_seq = u32::from_ne_bytes(data[8..12].try_into().ok()?);
                if len < 16 || len > data.len() || got_seq != seq {
                    return None;
                }
                match kind {
                    NLMSG_DONE => return Some(()),
                    NLMSG_ERROR => return None,
                    SOCK_DIAG_BY_FAMILY => rows.extend(parse(&data[16..len])),
                    _ => {}
                }
                data = &data[(len + 3) & !3..];
            }
        }
    }

    fn parse(msg: &[u8]) -> Option<Row> {
        if msg.len() < DIAG_MSG_LEN {
            return None;
        }
        let u32_at =
            |b: &[u8], at: usize| Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?));
        let u64_at =
            |b: &[u8], at: usize| Some(u64::from_ne_bytes(b.get(at..at + 8)?.try_into().ok()?));
        let local_port = u16::from_be_bytes(msg[4..6].try_into().ok()?);
        let peer_is_self = msg[8..24] == msg[24..40];
        let cookie = u64::from(u32_at(msg, 44)?) | (u64::from(u32_at(msg, 48)?) << 32);
        let inode = u64::from(u32_at(msg, 68)?);
        let mut attrs = &msg[DIAG_MSG_LEN..];
        while attrs.len() >= 4 {
            let len = usize::from(u16::from_ne_bytes(attrs[0..2].try_into().ok()?));
            let kind = u16::from_ne_bytes(attrs[2..4].try_into().ok()?);
            if len < 4 || len > attrs.len() {
                return None;
            }
            let info = &attrs[4..len];
            if kind == INET_DIAG_INFO && info.len() >= TCP_INFO_MIN {
                // Fields past `TCP_INFO_MIN` are newer (`tcpi_rcv_wnd` is Linux 6.2) and read as zero when absent.
                let tcp = Tcp {
                    rcv_rtt_us: u32_at(info, 92)?,
                    rcv_space: u32_at(info, 96)?,
                    notsent_bytes: u32_at(info, 144)?,
                    busy_us: u64_at(info, 168)?,
                    rwnd_limited_us: u64_at(info, 176)?,
                    sndbuf_limited_us: u64_at(info, 184)?,
                    rcv_wnd: u32_at(info, 232).unwrap_or(0),
                    total_retrans: u32_at(info, 100)?,
                    bytes_received: u64_at(info, 128)?,
                    segs_out: u32_at(info, 136)?,
                    segs_in: u32_at(info, 140)?,
                    data_segs_in: u32_at(info, 152)?,
                    data_segs_out: u32_at(info, 156)?,
                    bytes_sent: u64_at(info, 200)?,
                };
                return Some(Row {
                    inode,
                    cookie,
                    local_port,
                    peer_is_self,
                    tcp,
                });
            }
            attrs = attrs.get((len + 3) & !3..).unwrap_or_default();
        }
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod imp {
    use std::collections::HashSet;

    use super::Row;

    pub fn socket_inodes(_: u32) -> Option<HashSet<u64>> {
        None
    }

    pub fn dump() -> Option<Vec<Row>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(rx: u64, tx: u64, segs_in: u32, data_in: u32, segs_out: u32, data_out: u32) -> Tcp {
        Tcp {
            bytes_received: rx,
            bytes_sent: tx,
            segs_in,
            segs_out,
            data_segs_in: data_in,
            data_segs_out: data_out,
            ..Tcp::default()
        }
    }

    #[test]
    fn link_state_covers_the_flows_and_skips_idle_sockets() {
        let flow = |sent: u64, busy: u64, rwnd: u64, unsent: u32| Tcp {
            bytes_sent: sent,
            busy_us: busy,
            rwnd_limited_us: rwnd,
            notsent_bytes: unsent,
            rcv_space: unsent,
            ..Tcp::default()
        };
        let before = Snapshot {
            sockets: HashMap::from([
                (1, (Leg::Far, flow(0, 100_000, 0, 0))),
                (2, (Leg::Far, flow(0, 0, 0, 0))),
                (3, (Leg::Far, flow(0, 0, 0, 0))),
            ]),
        };
        let after = Snapshot {
            sockets: HashMap::from([
                (1, (Leg::Far, flow(8_000_000, 600_000, 550_000, 3_000_000))),
                (2, (Leg::Far, flow(8_000_000, 500_000, 200_000, 1_000_000))),
                (3, (Leg::Far, flow(900, 900_000, 0, 9))),
            ]),
        };
        let mut m = Metrics::new();
        link_metrics(&before, &after, 1.0, &mut m);
        assert_eq!(m["server_link_flows"], 2.0);
        assert_eq!(m["server_link_rwnd_held_flows"], 1.0);
        assert_eq!(m["server_link_busy_share"], 0.5);
        assert_eq!(m["server_link_rwnd_limited_share"], 0.75);
        assert_eq!(m["server_link_sndbuf_limited_share"], 0.0);
        assert_eq!(m["server_link_unsent_bytes"], 2_000_000.0);
        receive_state(&before, &after, &mut m);
        assert_eq!(m["far_rcv_space_bytes"], 2_000_000.0);
    }

    #[test]
    fn legs_and_sockets_present_at_both_ends() {
        let before = Snapshot {
            sockets: HashMap::from([
                (1, (Leg::Far, tcp(0, 0, 0, 0, 0, 0))),
                (2, (Leg::Near, tcp(0, 0, 0, 0, 0, 0))),
                (3, (Leg::Far, tcp(0, 0, 0, 0, 0, 0))),
            ]),
        };
        let after = Snapshot {
            sockets: HashMap::from([
                (1, (Leg::Far, tcp(16_000_000, 0, 1_100, 1_000, 500, 0))),
                (2, (Leg::Near, tcp(0, 16_000_000, 300, 0, 250, 250))),
                (4, (Leg::Far, tcp(9_000_000, 0, 9, 9, 9, 0))),
            ]),
        };
        let mut m = Metrics::new();
        metrics(&before, &after, &mut m);
        assert_eq!(m["far_rx_segment_bytes"], 16_000.0);
        assert_eq!(m["far_nondata_rx_per_mb"], 100.0 / 16.0);
        assert_eq!(m["far_nondata_tx_per_mb"], 500.0 / 16.0);
        assert!(!m.contains_key("far_tx_segment_bytes"));
        assert_eq!(m["near_tx_segment_bytes"], 64_000.0);
        assert_eq!(m["near_nondata_rx_per_mb"], 300.0 / 16.0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_own_connected_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let port = client.local_addr().unwrap().port();
        let mine = imp::socket_inodes(std::process::id()).unwrap();
        let rows = imp::dump().unwrap();
        assert!(
            rows.iter()
                .any(|r| r.local_port == port && mine.contains(&r.inode))
        );
        drop((client, server));
    }
}
