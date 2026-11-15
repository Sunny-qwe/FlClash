use super::*;

/// The interface resolves through the DNS hijack address only with `auto-route`, as in sing-tun.
pub(super) fn set_windows_dns(
    device: &tun_rs::AsyncDevice,
    options: &TunOptions,
) -> io::Result<()> {
    for (addresses, is_v4) in [
        (&options.inet4_address, true),
        (&options.inet6_address, false),
    ] {
        let Some(first) = addresses.first() else {
            continue;
        };
        match first.next_host().filter(|_| options.auto_route) {
            Some(server) => device.set_dns_servers(&[server])?,
            None => device.clear_dns_servers(is_v4)?,
        }
    }
    Ok(())
}

pub(super) fn wintun_path(options: &TunOptions) -> io::Result<String> {
    let path = match &options.wintun_path {
        Some(path) => path.clone(),
        None => crate::wintun::install()?,
    };
    Ok(path.to_string_lossy().into_owned())
}
