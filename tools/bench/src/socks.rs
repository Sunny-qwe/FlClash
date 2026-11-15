//! How the load reaches the core: a SOCKS5 mixed port, or plain sockets that the
//! routing table sends into the core's TUN device.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

#[derive(Clone, Copy, Debug)]
pub enum Entry {
    Socks(SocketAddr),
    Tun,
}

pub async fn connect(entry: Entry, target: SocketAddr) -> io::Result<TcpStream> {
    match entry {
        Entry::Socks(proxy) => {
            let mut stream = dial(proxy).await?;
            handshake(&mut stream, 1, target).await?;
            Ok(stream)
        }
        Entry::Tun => dial(target).await,
    }
}

/// Android routes into a VPN by a socket's uid, and never root's: see `--load-uid`.
static LOAD_UID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

pub fn set_load_uid(uid: u32) {
    let _ = LOAD_UID.set(uid);
}

/// A socket takes its owner from the filesystem uid of the thread that creates it,
/// so switching only that, and only for the call, leaves the harness root otherwise.
pub fn owned<T>(create: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(&uid) = LOAD_UID.get() {
        #[allow(
            unsafe_code,
            reason = "setfsuid only changes this thread's filesystem credentials"
        )]
        let previous = unsafe { libc::setfsuid(uid) };
        let created = create();
        #[allow(unsafe_code, reason = "restores the credentials saved above")]
        unsafe {
            libc::setfsuid(previous as libc::uid_t);
        }
        return created;
    }
    create()
}

async fn dial(address: SocketAddr) -> io::Result<TcpStream> {
    let socket = owned(|| {
        if address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
    })?;
    let stream = socket.connect(address).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Closing with a zero linger sends RST, so the harness leaves no TIME_WAIT behind
/// across thousands of short connections.
pub fn abort(stream: TcpStream) {
    let _ = socket2::SockRef::from(&stream).set_linger(Some(std::time::Duration::ZERO));
    drop(stream);
}

async fn handshake(
    stream: &mut TcpStream,
    command: u8,
    target: SocketAddr,
) -> io::Result<SocketAddr> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, 0] {
        return Err(io::Error::other(format!("socks method refused: {reply:?}")));
    }
    let mut request = vec![5, command, 0];
    put_address(&mut request, target);
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(io::Error::other(format!("socks reply {}", head[1])));
    }
    let ip = match head[3] {
        1 => {
            let mut v4 = [0u8; 4];
            stream.read_exact(&mut v4).await?;
            IpAddr::from(v4)
        }
        4 => {
            let mut v6 = [0u8; 16];
            stream.read_exact(&mut v6).await?;
            IpAddr::from(v6)
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            IpAddr::from([127, 0, 0, 1])
        }
        other => return Err(io::Error::other(format!("socks address type {other}"))),
    };
    let port = stream.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

fn put_address(out: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
}

/// A UDP flow to one target. Over SOCKS the control connection is held for the
/// association's lifetime, as RFC 1928 requires.
pub struct Udp {
    socket: UdpSocket,
    header: Vec<u8>,
    _control: Option<TcpStream>,
}

impl Udp {
    pub async fn open(entry: Entry, target: SocketAddr) -> io::Result<Udp> {
        let local: SocketAddr = if target.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        match entry {
            Entry::Socks(proxy) => {
                let mut control = dial(proxy).await?;
                let mut relay = handshake(&mut control, 3, ([0, 0, 0, 0], 0).into()).await?;
                if relay.ip().is_unspecified() {
                    relay.set_ip(proxy.ip());
                }
                let socket = bind(local).await?;
                socket.connect(relay).await?;
                let mut header = vec![0, 0, 0];
                put_address(&mut header, target);
                Ok(Udp {
                    socket,
                    header,
                    _control: Some(control),
                })
            }
            Entry::Tun => {
                let socket = bind(local).await?;
                socket.connect(target).await?;
                Ok(Udp {
                    socket,
                    header: Vec::new(),
                    _control: None,
                })
            }
        }
    }

    pub fn header_len(&self) -> usize {
        self.header.len()
    }

    pub async fn send(&self, packet: &mut [u8]) -> io::Result<()> {
        packet[..self.header.len()].copy_from_slice(&self.header);
        self.socket.send(packet).await.map(drop)
    }

    pub async fn recv<'a>(&self, buf: &'a mut [u8]) -> io::Result<&'a [u8]> {
        let n = self.socket.recv(buf).await?;
        if self.header.is_empty() {
            return Ok(&buf[..n]);
        }
        let skip = match buf.get(3) {
            Some(1) => 4 + 4 + 2,
            Some(4) => 4 + 16 + 2,
            Some(3) => 4 + 1 + usize::from(buf.get(4).copied().unwrap_or(0)) + 2,
            _ => return Err(io::Error::other("bad socks udp header")),
        };
        if n < skip {
            return Err(io::Error::other("short socks udp packet"));
        }
        Ok(&buf[skip..n])
    }
}

async fn bind(local: SocketAddr) -> io::Result<UdpSocket> {
    let socket = owned(|| std::net::UdpSocket::bind(local))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket)?;
    let _ = socket2::SockRef::from(&socket).set_recv_buffer_size(8 << 20);
    let _ = socket2::SockRef::from(&socket).set_send_buffer_size(8 << 20);
    Ok(socket)
}
