# Compatibility With mihomo

Concord reads the configuration mihomo reads and aims to behave as mihomo does. This file lists where it does not:
deliberate differences, what is left out, and what is supported only in part.

## How Unsupported Input Is Handled

| Handling | When |
|---|---|
| The profile is rejected, and the built-in empty config runs instead, routing everything direct | The profile is wrong: an unknown or malformed rule, an illegal field, a reference to something that does not exist |
| The node is set aside with a warning | The node uses something Concord does not support, or its options cannot be built into a working node (a certificate that cannot be read, a malformed fingerprint pin, REALITY over `ws`). A group left empty by this, or whose selected node was set aside, refuses connections instead of falling back to another member; `empty-fallback` applies when given |
| The key is ignored with a warning | It does not change where traffic goes |

A key that a node's type does not have in mihomo, such as `reality-opts` on `hysteria2` or `alpn` on `socks5`, is
ignored with a warning, as is a `smux` that is not a map. A number mihomo keeps without checking its range, such as
`mixed-port: 70000`, `dns.fake-ip-ttl: -1` or a negative `heartbeat-interval` on a node, is ignored with a warning
(`out_of_range` for the general, `dns` and `ntp` settings): a port leaves its listener closed and any other number takes
its default. A number that picks a protocol version, such as `version` on `snell`, is still refused. Warnings carry a
stable `code` and are returned by
`config.warnings`. Settings whose loss would change routing or
widen exposure are never ignored silently, and keys that name a server's identity (`fingerprint`, `certificate`,
`reality-opts`) are never dropped while the node keeps working.

## Deliberate Differences

| Behaviour | mihomo | Concord |
|---|---|---|
| A node of an unsupported type, or one whose options cannot be built | The whole profile fails, or, for options checked when connecting, the node's connections fail | The node is set aside with a warning |
| `listeners`, `tunnels`, `external-controller-tls`, `-unix`, `-pipe`, `external-ui` and `external-doh-server` | Opened | Never opened; the host opens listeners through the API |
| `external-controller`, `secret` and `external-controller-cors` | Read from the profile | Read from the profile when Concord runs on its own (`concord run`). An app that embeds Concord sets them itself, and the profile's values are ignored with a warning |
| Dashboard changes in an app that embeds Concord | mihomo's embedded builds refuse `PUT`/`PATCH /configs` and the geo update | Allowed, except `PUT /configs` and `tun` in `PATCH /configs`, which belong to the app; the app is told of every change so it stays in step |
| Dial retries | Up to 10 per connection within 5 s | None: one dial per connection, as sing-box does; a failed dial fails the connection |
| UDP routing | The first packet from a source decides the route for all its destinations | Each destination is routed by the rules; flows that reach one outbound share its session, so the external mapping stays endpoint-independent. Single-destination protocols such as plain VMess are the exception |
| `GEOIP` | Reads the mmdb or `GeoIP.dat` | Reads the mmdb only; `geodata-mode: true` and `geox-url.geoip` are ignored with a warning, and a code that only a custom `GeoIP.dat` held does not match. `GEOIP,!cn` negates against the mmdb |
| `IP-ASN` and `SRC-IP-ASN` without `ASN.mmdb` | The apply downloads the file and fails if the download does | The apply goes ahead; the rules match nothing until the file, fetched in the background and retried, loads, and a `NOT` around one does not turn that into a match |
| `dns.fallback-filter` left out | `geoip: true`, `geoip-code: CN` | `geoip: false` and no code, so no region is singled out; `geoip: true` without a `geoip-code` skips the GeoIP filter with a warning |
| The process name of connections the core opens itself (provider updates, health checks, DNS through the tunnel) | `mihomo`, in the connections API, the routing log and `PROCESS-NAME` | `concord` |
| File providers | Reloaded on file-system events | Reloaded by polling the file every 2 s |
| A provider `path` outside the home directory, or one that passes through a symlink | Read when `SAFE_PATHS` lists the directory; a symlink is followed | Refused: the apply fails, naming the provider and the path |
| Picking a dead `fallback` member | Stores the pick, then tests the member; a connection during the test drops the pick (`adapter/outboundgroup/fallback.go:105-145`) | Stores the pick, then tests the member; a connection during the test uses another member, and the pick stays until the test decides |

## External Controller

Concord serves the Clash REST and WebSocket API, in mihomo's shapes, for dashboards such as metacubexd, zashboard and yacd, with the same
paths, fields, status codes, `Authorization: Bearer` secret and CORS. The differences:

- Not served, answered with status 501: `/restart`, `/upgrade` (core, UI and geo), `/debug`, `/storage`, `/ui`
  (there is no `external-ui`) and `PATCH /rules/disable`.
- `PATCH /configs` changes what Concord changes live: `mode`, `log-level`, `ipv6`, `allow-lan`, `mixed-port`,
  `tcp-concurrent`, `find-process-mode` and, when Concord runs on its own, `tun`. A request that names any other
  setting (ports other than `mixed-port`, `interface-name`, `sniffing`, `bind-address`, the LAN lists and the like)
  is refused with status 400 naming the settings, and nothing in it is applied; mihomo applies them.
- `PUT /configs` reads a `path` only inside the home directory; `SAFE_PATHS` is not read. The profile, given by
  `path` or `payload` or, with neither, the file `concord run` started with, replaces the working `config.yaml`.
- Connection `id`s are decimal numbers, not UUIDs.
- `GET /` answers `{"hello":"concord"}`. metacubexd and zashboard check the backend with `/version` and do not read
  it.
- `/version` reports Concord's version with `meta: true`. Dashboards compare it with mihomo's releases, so they may
  offer a core update; the update itself answers 501.
- `/rules` has no hit counters (`extra`), and `size` is always -1.
- The `tun` object of `GET /configs` carries `enable`, `device`, `stack`, `dns-hijack`, `auto-route`,
  `auto-detect-interface` and `mtu`; settings Concord does not have keep mihomo's zero values, and mihomo's defaults
  for the TUN addresses, `recvmsgx` and `processors-per-channel` are not reported.
- `lan-allowed-ips` and `lan-disallowed-ips` in `GET /configs` are `null`: Concord does not restrict the LAN listener
  by address, and a profile that does is not opened to the LAN.
- An empty list is `[]` where mihomo writes `null` (`authentication`, `skip-auth-prefixes`, `dns-hijack`, and
  `connections` with none open).

## Not Supported

- Outbound types, networks, TLS options and Shadowsocks plugins outside Concord's scope (among them tailscale,
  easytier, zerotier, openvpn, masque, sudoku, kcp, restls, jls and kcptun): the node is set aside with a warning,
  also when the TLS option is given in xhttp `download-settings`. The full lists are the `T2_*` constants in
  `crates/config/src/proxy/parse.rs`.
- A provider's `override.override-expr`: the provider gets no proxies and a warning, because its nodes must not run
  without the expressions.
- A rule provider's `path-in-bundle`: `BundleMRS.7z` is not read, so a provider whose local file is missing loads
  from its `url` or fails to load, as in mihomo when the home directory has no `BundleMRS.7z`. The key is ignored
  with a warning.
- The `relay` group type, which mihomo also removed; use `dialer-proxy`.
- ShadowsocksR `chacha20` and `xchacha20` (obsolete unauthenticated ciphers); VLESS `encryption`; xhttp over HTTP/3;
  Hysteria `faketcp`; ShadowQUIC over QUIC v2; Snell version 6, whose node is set aside with a warning.
- sing-mux brutal on the client's own socket, which needs a Linux kernel module. The sing-mux exchange is done, so
  the server still paces its sends.
- A node's `tfo` on macOS and Windows, where it does nothing.
- SSH RSA host keys. Modern servers offer ed25519; RSA client keys are supported.
- `global-client-fingerprint`, which mihomo also removed, and a node's `ws-path` and `ws-headers`, which it removed
  in favour of `ws-opts`; a node that writes them gets a warning.

## Partial Support

- **mieru:** both transports work against mihomo's mieru listener; the UDP transport with a `dialer-proxy` is
  rejected when the node is built, and padding statistics are approximated.
- **Hysteria2 `realm-opts`:** works against mihomo's `hysteria2-realm` listener, including through two NATs; it speaks
  HTTP/1.1 to the control server (the realm `alpn` is ignored and redirects are not followed), and a node that also
  sets `dialer-proxy` is rejected when built.
- **ECH (`ech-opts`):** works from a `config` or an HTTPS record lookup, on both TLS backends and over QUIC; a
  Shadowsocks `v2ray-plugin` node with `ech-opts` is rejected when built.
  A server that rejects the ECH offer and sends `retry_configs` gets one more TCP connection with that list (as in
  sing-box, unlike mihomo); QUIC nodes do not retry.
- **sing-mux `brutal-opts`:** performs the exchange so the server paces its sends; see above for the client side.
- **`bbr-profile`:** `standard` is quinn's BBR; `conservative` and `aggressive` apply the profile's gains, startup
  length and drain rule, without overshoot detection or overestimate avoidance.
- **WireGuard `amnezia-wg-option`:** runs against amneziawg-go as the server, legacy and version 3. Version 3's
  content-padding addition, the rekey, reject, keepalive and handshake-attempt timings, and the transport-message part
  of random trailers are not applied; the node works and `config.warnings` names the options it sets.
- **Snell `obfs-opts` `shadow-tls`:** works against mihomo's Snell listener with ShadowTLS v2 and v3, over TCP and
  UDP; Snell with `restls` or `jls` is rejected when built.
- **TUN:** ICMP echo is forwarded from an unprivileged ICMP socket on Unix and a raw ICMP socket on Windows; only echo
  replies come back, so `traceroute` through the TUN shows no hops. `tun.gso` is ignored with a warning. On Windows
  the interface's forwarding, router-discovery, DAD and DNS-registration options are not set. `tun.dns-mode` is not
  read: with `auto-route` the TUN becomes the system resolver on every desktop platform, macOS included, where mihomo
  leaves it off unless `dns-mode` asks; the macOS entry lives in the dynamic store and goes away with the process.
  The keys that narrow what the TUN captures by package, Android user, uid range, port range, MAC address or route
  set are ignored, so the TUN captures other traffic than they say; the warning says so. An app that embeds Concord
  picks the apps that go through its TUN itself.
- **DNS:** a `dhcp://<interface>` upstream runs as `system://` with a warning.
- **Accepted without effect:** `skip-auth-prefixes` and `inbound-tfo` (a non-empty value gets a warning).
- **Deprecated fingerprint names:** `chrome_psk`, the other `chrome_*` variants and `randomized` are read as `chrome`
  and `random` with a warning.
- **TProxy UDP** does not carry DSCP.
- **MITM:** `cron` scripts are not exercised end to end; WebSocket over HTTP/2, reclaiming upstream connections after
  90 s idle, and a per-chunk limit against zip bombs are not implemented. Body rewrites run on the blocking pool and
  give up after 5 s (the Surge script default), leaving the body as it came; a jq filter that never ends, such as
  `until(false; .)`, keeps its blocking thread busy until the process exits, as jaq cannot be interrupted.
