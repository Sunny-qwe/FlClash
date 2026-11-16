//! One outbound per protocol and the listener that serves it. Listener and
//! client fields follow `crates/proxy/tests/interop.rs`.

use std::path::Path;

use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub name: &'static str,
    pub udp: bool,
    pub about: &'static str,
}

pub const ALL: &[Spec] = &[
    spec(
        "direct",
        true,
        "no outbound protocol: the inbound, router and relay alone",
    ),
    spec("ss-aes128", true, "shadowsocks aes-128-gcm"),
    spec("ss-chacha", true, "shadowsocks chacha20-ietf-poly1305"),
    spec("ss2022", true, "shadowsocks 2022-blake3-aes-128-gcm"),
    spec(
        "ss2022-chacha8",
        true,
        "shadowsocks 2022-blake3-chacha8-poly1305",
    ),
    spec("vmess", true, "vmess aes-128-gcm, alterId 0"),
    spec("vmess-chacha", true, "vmess chacha20-poly1305, alterId 0"),
    spec("vmess-none", true, "vmess unencrypted body, alterId 0"),
    spec(
        "vmess-ws-tls",
        false,
        "vmess aes-128-gcm over WebSocket and TLS",
    ),
    spec(
        "vmess-grpc-tls",
        false,
        "vmess aes-128-gcm over gRPC and TLS",
    ),
    spec("vless-tls", true, "vless over TLS"),
    spec(
        "vless-xhttp-packet-up",
        false,
        "vless XHTTP packet-up over HTTP/2",
    ),
    spec(
        "vless-xhttp-stream-up",
        false,
        "vless XHTTP stream-up over HTTP/2",
    ),
    spec(
        "vless-xhttp-stream-one",
        false,
        "vless XHTTP stream-one over HTTP/2",
    ),
    spec(
        "ss-smux-h2mux",
        true,
        "shadowsocks aes-128-gcm with sing h2mux",
    ),
    spec("trojan-tls", true, "trojan over TLS"),
    spec(
        "trojan-chrome",
        false,
        "trojan over TLS with the chrome client fingerprint (BoringSSL)",
    ),
    spec("anytls", true, "anytls"),
    spec("hysteria2", true, "hysteria2 over QUIC"),
    spec(
        "hysteria-brutal",
        true,
        "hysteria v1, Brutal at 100 Mbit/s (needs --sing-box)",
    ),
    spec("hysteria2-brutal", true, "hysteria2, Brutal at 100 Mbit/s"),
    spec(
        "shadowquic-brutal",
        true,
        "shadowquic, Brutal at 100 Mbit/s",
    ),
    spec("tuic", true, "tuic v5 over QUIC"),
    spec(
        "snell",
        false,
        "snell v4; mihomo's listener stalls some flows",
    ),
    spec("mieru-tcp", false, "mieru over TCP"),
];

pub const QUICK: &[&str] = &[
    "direct",
    "ss-aes128",
    "trojan-tls",
    "vmess-grpc-tls",
    "hysteria2",
];

const fn spec(name: &'static str, udp: bool, about: &'static str) -> Spec {
    Spec { name, udp, about }
}

pub fn find(name: &str) -> Option<Spec> {
    ALL.iter().copied().find(|s| s.name == name)
}

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const TUIC_UUID: &str = "b3f1a6d2-5c0e-4a11-9c43-7e2d8f6a0b15";
const KEY16: &str = "MDEyMzQ1Njc4OWFiY2RlZg==";
const KEY32: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

pub struct Case {
    pub spec: Spec,
    /// The mihomo `listeners:` entry; absent for DIRECT and the sing-box-served Hysteria v1 case.
    pub listener: Option<String>,
    pub singbox_listener: Option<Value>,
    pub proxy: Option<Value>,
}

impl Case {
    pub fn name(&self) -> &'static str {
        self.spec.name
    }

    pub fn rule_target(&self) -> &str {
        if self.proxy.is_some() {
            self.spec.name
        } else {
            "DIRECT"
        }
    }
}

pub fn build(spec: Spec, host: &str, port: u16, certs: &Path) -> Case {
    let tls = format!(
        "    certificate: {}\n    private-key: {}\n",
        certs.join("cert.pem").display(),
        certs.join("key.pem").display()
    );
    let insecure = json!({"sni": "localhost", "skip-cert-verify": true});
    if spec.name == "hysteria-brutal" {
        return Case {
            spec,
            listener: None,
            singbox_listener: Some(json!({
                "type": "hysteria", "tag": spec.name, "listen": host, "listen_port": port,
                "up_mbps": 100, "down_mbps": 100,
                "users": [{"name": "bench", "auth_str": "hy1-pw"}],
                "tls": {"enabled": true, "alpn": ["hysteria"],
                    "certificate_path": certs.join("cert.pem"), "key_path": certs.join("key.pem")}
            })),
            proxy: Some(json!({
                "name": spec.name, "type": "hysteria", "server": host, "port": port,
                "udp": true, "auth-str": "hy1-pw", "up": "100", "down": "100",
                "sni": "localhost", "skip-cert-verify": true
            })),
        };
    }
    let ss = |cipher: &str, password: &str| {
        (
            "ss",
            "shadowsocks",
            format!("    password: {password}\n    cipher: {cipher}\n    udp: true\n"),
            json!({"cipher": cipher, "password": password}),
        )
    };
    let trojan = |extra: Value| {
        (
            "trojan",
            "trojan",
            format!("    users:\n      - username: a\n        password: trojan-pw\n{tls}"),
            merge(merge(json!({"password": "trojan-pw"}), &insecure), &extra),
        )
    };
    let (kind, listener_kind, body, extra) = match spec.name {
        "ss-aes128" => ss("aes-128-gcm", "pw"),
        "ss-chacha" => ss("chacha20-ietf-poly1305", "pw"),
        "ss2022" => ss("2022-blake3-aes-128-gcm", KEY16),
        "ss2022-chacha8" => ss("2022-blake3-chacha8-poly1305", KEY32),
        "vmess" | "vmess-chacha" | "vmess-none" => (
            "vmess",
            "vmess",
            format!("    users:\n      - username: a\n        uuid: {UUID}\n        alterId: 0\n"),
            json!({"uuid": UUID, "alterId": 0, "cipher": match spec.name {
                "vmess-chacha" => "chacha20-poly1305",
                "vmess-none" => "none",
                _ => "aes-128-gcm",
            }}),
        ),
        "vmess-ws-tls" => (
            "vmess",
            "vmess",
            format!(
                "    users:\n      - username: a\n        uuid: {UUID}\n        alterId: 0\n    ws-path: /vm\n{tls}"
            ),
            json!({"uuid": UUID, "alterId": 0, "cipher": "aes-128-gcm", "tls": true, "servername": "localhost", "skip-cert-verify": true, "network": "ws", "ws-opts": {"path": "/vm"}}),
        ),
        "vmess-grpc-tls" => (
            "vmess",
            "vmess",
            format!(
                "    users:\n      - username: a\n        uuid: {UUID}\n        alterId: 0\n    grpc-service-name: gun\n{tls}"
            ),
            json!({"uuid": UUID, "alterId": 0, "cipher": "aes-128-gcm", "tls": true, "servername": "localhost", "skip-cert-verify": true, "network": "grpc", "grpc-opts": {"grpc-service-name": "gun"}}),
        ),
        "vless-tls" => (
            "vless",
            "vless",
            format!("    users:\n      - username: a\n        uuid: {UUID}\n{tls}"),
            json!({"uuid": UUID, "tls": true, "servername": "localhost", "skip-cert-verify": true}),
        ),
        "vless-xhttp-packet-up" | "vless-xhttp-stream-up" | "vless-xhttp-stream-one" => {
            let mode = spec.name.strip_prefix("vless-xhttp-").unwrap();
            (
                "vless",
                "vless",
                format!(
                    "    users:\n      - username: a\n        uuid: {UUID}\n    xhttp-config:\n      path: /xh\n      mode: {mode}\n{tls}"
                ),
                json!({"uuid": UUID, "tls": true, "servername": "localhost", "skip-cert-verify": true, "network": "xhttp", "alpn": ["h2"], "xhttp-opts": {"path": "/xh", "mode": mode}}),
            )
        }
        "ss-smux-h2mux" => {
            let (kind, listener_kind, body, extra) = ss("aes-128-gcm", "pw");
            (
                kind,
                listener_kind,
                body,
                merge(extra, &json!({"smux": {"enabled": true}})),
            )
        }
        "trojan-tls" => trojan(json!({})),
        "trojan-chrome" => trojan(json!({"client-fingerprint": "chrome"})),
        "anytls" => (
            "anytls",
            "anytls",
            format!("    users:\n      user: anytls-pw\n{tls}"),
            merge(json!({"password": "anytls-pw"}), &insecure),
        ),
        "hysteria2" => (
            "hysteria2",
            "hysteria2",
            format!("    users:\n      user: hy2-pw\n{tls}"),
            merge(json!({"password": "hy2-pw"}), &insecure),
        ),
        "hysteria2-brutal" => (
            "hysteria2",
            "hysteria2",
            format!("    users:\n      user: hy2-pw\n    up: 100\n    down: 100\n{tls}"),
            merge(
                json!({"password": "hy2-pw", "up": "100", "down": "100"}),
                &insecure,
            ),
        ),
        "shadowquic-brutal" => (
            "shadowquic",
            "shadowquic",
            format!(
                "    users:\n      - username: bench\n        password: sq-pw\n    up: 100\n    down: 100\n    jls-upstream:\n      addr: {host}:{port}\n      sni: localhost\n  - name: shadowquic-tls\n    type: trojan\n    listen: {host}\n    port: {port}\n    users:\n      - username: bench\n        password: unused\n{tls}"
            ),
            merge(
                json!({"username": "bench", "password": "sq-pw", "up": "100", "down": "100"}),
                &insecure,
            ),
        ),
        "tuic" => (
            "tuic",
            "tuic",
            format!("    users:\n      {TUIC_UUID}: tuic-pw\n    alpn: [h3]\n{tls}"),
            merge(
                json!({"uuid": TUIC_UUID, "password": "tuic-pw", "alpn": ["h3"]}),
                &insecure,
            ),
        ),
        "snell" => (
            "snell",
            "snell",
            "    psk: snell-psk\n    version: 4\n".to_string(),
            json!({"psk": "snell-psk", "version": 4}),
        ),
        "mieru-tcp" => (
            "mieru",
            "mieru",
            "    transport: TCP\n    users:\n      mu: mp\n".to_string(),
            json!({"transport": "TCP", "username": "mu", "password": "mp"}),
        ),
        _ => {
            return Case {
                spec,
                listener: None,
                singbox_listener: None,
                proxy: None,
            };
        }
    };
    let listener = format!(
        "  - name: {}\n    type: {listener_kind}\n    listen: {host}\n    port: {port}\n{body}",
        spec.name
    );
    let base =
        json!({"name": spec.name, "type": kind, "server": host, "port": port, "udp": spec.udp});
    Case {
        spec,
        listener: Some(listener),
        singbox_listener: None,
        proxy: Some(merge(base, &extra)),
    }
}

fn merge(mut base: Value, more: &Value) -> Value {
    if let (Some(base), Some(more)) = (base.as_object_mut(), more.as_object()) {
        for (key, value) in more {
            base.insert(key.clone(), value.clone());
        }
    }
    base
}

pub fn write_certs(dir: &Path) -> std::io::Result<()> {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(std::io::Error::other)?;
    std::fs::write(dir.join("cert.pem"), made.cert.pem())?;
    std::fs::write(dir.join("key.pem"), made.signing_key.serialize_pem())
}

/// Both clients get the same profile: one node, one rule, nothing that costs per
/// connection besides the outbound itself.
pub fn client_profile(case: &Case, mixed: u16, tun: Option<&Value>) -> String {
    let proxies = match &case.proxy {
        Some(proxy) => format!("proxies:\n  - {proxy}\n"),
        None => String::new(),
    };
    let tun = tun.map(|t| format!("tun: {t}\n")).unwrap_or_default();
    format!(
        "mixed-port: {mixed}\nallow-lan: false\nmode: rule\nlog-level: error\nipv6: false\n\
         find-process-mode: off\ngeo-auto-update: false\nunified-delay: false\n\
         dns:\n  enable: false\n{tun}{proxies}rules:\n  - MATCH,{}\n",
        case.rule_target()
    )
}

pub fn server_config(cases: &[Case]) -> String {
    let mut config = "log-level: error\nmode: direct\nipv6: false\nfind-process-mode: off\n\
                      geo-auto-update: false\nlisteners:\n"
        .to_string();
    for listener in cases.iter().filter_map(|case| case.listener.as_deref()) {
        config.push_str(listener);
    }
    if cases.iter().all(|c| c.listener.is_none()) {
        config = config.replace("listeners:\n", "");
    }
    config
}

pub fn singbox_config(cases: &[Case]) -> Value {
    json!({
        "log": {"level": "error"},
        "inbounds": cases.iter().filter_map(|c| c.singbox_listener.clone()).collect::<Vec<_>>(),
        "outbounds": [{"type": "direct", "tag": "direct"}]
    })
}

/// A profile shaped like a large subscription: `proxies` shadowsocks nodes in one
/// select group and `rules` domain rules with an IP tail, all unreachable, so only
/// parse, compile and resident cost are measured.
pub fn large_profile(mixed: u16, proxies: usize, rules: usize) -> String {
    use std::fmt::Write;
    let mut out = format!(
        "mixed-port: {mixed}\nallow-lan: false\nmode: rule\nlog-level: error\nipv6: false\n\
         find-process-mode: off\ngeo-auto-update: false\ndns:\n  enable: false\nproxies:\n"
    );
    for i in 0..proxies {
        let _ = writeln!(
            out,
            "  - {{name: n{i}, type: ss, server: 10.{}.{}.{}, port: {}, cipher: aes-128-gcm, password: p{i}}}",
            (i >> 16) & 255,
            (i >> 8) & 255,
            i & 255,
            10_000 + i % 50_000
        );
    }
    out.push_str("proxy-groups:\n  - name: all\n    type: select\n    proxies:\n");
    for i in 0..proxies {
        let _ = writeln!(out, "      - n{i}");
    }
    out.push_str("rules:\n");
    for i in 0..rules {
        let _ = match i % 10 {
            0..=5 => writeln!(out, "  - DOMAIN-SUFFIX,s{i}.example{}.com,all", i % 97),
            6 | 7 => writeln!(out, "  - DOMAIN,h{i}.example.net,DIRECT"),
            8 => writeln!(out, "  - DOMAIN-KEYWORD,kw{i},all"),
            _ => writeln!(
                out,
                "  - IP-CIDR,{}.{}.{}.0/24,DIRECT,no-resolve",
                1 + (i >> 16) % 220,
                (i >> 8) & 255,
                i & 255
            ),
        };
    }
    out.push_str("  - MATCH,DIRECT\n");
    out
}
