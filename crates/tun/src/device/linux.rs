use super::*;

impl DeviceIo {
    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tokio(device) => device.try_clone().map(Self::Tokio),
            Self::Queued { .. } => {
                Err(io::Error::other("TUN queues are cloned before preparation"))
            }
        }
    }

    pub(super) fn tcp_gso(&self) -> bool {
        match self {
            Self::Tokio(device) => device.tcp_gso(),
            Self::Queued { device, .. } => device.tcp_gso(),
        }
    }

    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Tokio(device) => device.poll_writable(cx),
            Self::Queued { ready, .. } => ready.poll_write_ready(cx),
        }
    }

    fn try_send_vectored(&self, parts: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            Self::Tokio(device) => device.try_send_vectored(parts),
            Self::Queued { device, ready, .. } => ready.try_write(|| device.send_vectored(parts)),
        }
    }
}

impl TunDevice {
    fn open_queue(&self) -> io::Result<Self> {
        let inner = self.inner.try_clone()?;
        if self.vnet {
            use std::os::fd::AsRawFd;

            // Opening a queue re-applies tun-rs's offload set, UDP segmentation included.
            crate::vnet::restrict_to_tcp(inner.as_raw_fd())?;
        }
        Ok(TunDevice {
            inner,
            name: self.name.clone(),
            index: self.index,
            vnet: self.vnet,
            segment_limit: self.segment_limit,
            queues: 1,
            udp_merge: std::sync::atomic::AtomicBool::new(true),
        })
    }

    fn poll_send_vnet(
        &self,
        cx: &mut Context<'_>,
        packet: &[u8],
        segment: u16,
    ) -> Poll<io::Result<usize>> {
        let header = crate::vnet::header_for(packet, segment);
        let parts = [
            std::io::IoSlice::new(&header),
            std::io::IoSlice::new(packet),
        ];
        loop {
            ready!(self.inner.poll_writable(cx))?;
            match self.inner.try_send_vectored(&parts) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                result => {
                    return Poll::Ready(
                        result.map(|sent| sent.saturating_sub(crate::vnet::HEADER_LEN)),
                    );
                }
            }
        }
    }
}

impl Device for TunDevice {
    fn prepare(self) -> io::Result<Self> {
        self.queued()
    }

    fn socket_owner(&self) -> Option<std::sync::Arc<dyn concord_netstack::SocketOwner>> {
        self.queue_owner()
    }

    fn socket_watcher(
        &self,
    ) -> Option<std::sync::Arc<dyn concord_common::SocketWatcher + Send + Sync>> {
        self.queue_watcher()
    }

    fn poll_io(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_queue(cx, false)
    }

    fn poll_park(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_queue(cx, true)
    }

    fn set_busy(&self, busy: bool) -> io::Result<bool> {
        self.set_queue_busy(busy)
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        if self.vnet {
            let read = ready!(self.inner.poll_recv(cx, buf))?;
            return Poll::Ready(Ok(crate::vnet::packet_len(buf, read)));
        }
        self.inner.poll_recv(cx, buf)
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        if self.vnet {
            return self.poll_send_vnet(cx, packet, 0);
        }
        self.inner.poll_send(cx, packet)
    }

    fn segment_limit(&self) -> usize {
        self.segment_limit
    }

    fn send_batch(&self) -> usize {
        if self.vnet {
            crate::vnet::UDP_RUN_LIMIT
        } else {
            Self::BATCH
        }
    }

    fn poll_send_batch(
        &self,
        cx: &mut Context<'_>,
        packets: &[&[u8]],
        failed: &mut usize,
    ) -> Poll<usize> {
        if !self.vnet || packets.is_empty() {
            return send_one(self, cx, packets, failed);
        }
        loop {
            if ready!(self.inner.poll_writable(cx)).is_err() {
                *failed += 1;
                return Poll::Ready(1);
            }
            let sent = crate::vnet::send_packets(packets, &self.udp_merge, failed, |parts| {
                self.inner.try_send_vectored(parts)
            });
            if sent > 0 {
                return Poll::Ready(sent);
            }
        }
    }

    fn into_queues(self) -> Vec<Self> {
        let mut extra = Vec::with_capacity(self.queues.saturating_sub(1));
        for _ in 1..self.queues {
            match self.open_queue() {
                Ok(queue) => extra.push(queue),
                Err(err) => {
                    tracing::warn!("tun runs on {} queues: {err}", extra.len() + 1);
                    break;
                }
            }
        }
        let mut all = vec![self];
        all.append(&mut extra);
        all
    }

    fn poll_send_segmented(
        &self,
        cx: &mut Context<'_>,
        packet: &[u8],
        segment: u16,
    ) -> Poll<io::Result<usize>> {
        self.poll_send_vnet(cx, packet, segment)
    }

    fn try_send_parts(&self, parts: &[IoSlice<'_>], segment: u16) -> io::Result<usize> {
        const MAX_PARTS: usize = 10;
        let Some(head) = parts
            .first()
            .filter(|_| self.vnet && parts.len() < MAX_PARTS)
        else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        let header = crate::vnet::header_for(head, segment);
        let mut all = [IoSlice::new(&header); MAX_PARTS];
        for (slot, part) in all.iter_mut().skip(1).zip(parts) {
            *slot = *part;
        }
        let all = all.get(..=parts.len()).unwrap_or_default();
        let sent = self.inner.try_send_vectored(all)?;
        Ok(sent.saturating_sub(crate::vnet::HEADER_LEN))
    }

    fn rx_offset(&self) -> usize {
        if self.vnet {
            crate::vnet::HEADER_LEN
        } else {
            0
        }
    }

    fn checksum_offload(&self) -> bool {
        self.vnet
    }
}
