use super::*;

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
        self.inner.poll_recv(cx, buf)
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        self.inner.poll_send(cx, packet)
    }
}
