#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
    pub(crate) path: String,
    /// `user:password` from the URL, percent-decoded as `url.User` holds it.
    pub(crate) userinfo: Option<Vec<u8>>,
}

impl Target {
    pub(crate) fn port_or_default(&self) -> u16 {
        self.port
            .unwrap_or(if self.scheme == "https" { 443 } else { 80 })
    }

    /// The `Host` header value: `:80` is dropped as `removeExtraHTTPHostPort`
    /// does, and an IPv6 literal keeps its brackets.
    pub(crate) fn host_header(&self) -> String {
        host_header(&self.host, self.port)
    }
}

pub(crate) fn host_header(host: &str, port: Option<u16>) -> String {
    let bracketed = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    match port {
        Some(port) if port != 80 => format!("{bracketed}:{port}"),
        _ => bracketed,
    }
}

pub(crate) fn parse_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => None,
            _ => Some(tail.strip_prefix(':')?.parse().ok()?),
        };
        return (!host.is_empty()).then(|| (host.to_owned(), port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() => (host, Some(port.parse().ok()?)),
        Some((host, _)) => (host, None),
        None => (authority, None),
    };
    (!host.is_empty() && !host.contains(':')).then(|| (host.to_owned(), port))
}

pub(crate) fn parse_absolute(target: &str) -> Option<Target> {
    let (scheme, rest) = target.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or_default();
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at_checked(end)?;
    let (host, port) = parse_authority(authority)?;
    let userinfo = authority.rsplit_once('@').map(|(info, _)| {
        let (user, password) = info.split_once(':').unwrap_or((info, ""));
        let mut out = unescape(user);
        out.push(b':');
        out.extend(unescape(password));
        out
    });
    let path = if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    Some(Target {
        scheme: scheme.to_ascii_lowercase(),
        host,
        port,
        path,
        userinfo,
    })
}

fn unescape(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (byte, hex) {
            (b'%', Some(decoded)) => {
                out.push(decoded);
                i += 3;
            }
            _ => {
                out.push(byte);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_targets_split_into_host_port_and_path() {
        let target = parse_absolute("http://example.com:8080/a/b?x=1#frag").unwrap();
        assert_eq!(target.scheme, "http");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, Some(8080));
        assert_eq!(target.path, "/a/b?x=1");
        assert_eq!(target.host_header(), "example.com:8080");
    }

    #[test]
    fn an_empty_path_becomes_a_slash_and_keeps_the_query() {
        assert_eq!(parse_absolute("http://a.test").unwrap().path, "/");
        assert_eq!(parse_absolute("http://a.test?x=1").unwrap().path, "/?x=1");
    }

    #[test]
    fn port_80_is_dropped_from_the_host_header() {
        assert_eq!(
            parse_absolute("http://a.test:80/").unwrap().host_header(),
            "a.test"
        );
        assert_eq!(
            parse_absolute("http://a.test:81/").unwrap().host_header(),
            "a.test:81"
        );
    }

    #[test]
    fn ipv6_literals_keep_their_brackets_in_the_header_only() {
        let target = parse_absolute("http://[::1]:8080/").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.host_header(), "[::1]:8080");
        assert_eq!(
            parse_absolute("http://[::1]/").unwrap().host_header(),
            "[::1]"
        );
    }

    #[test]
    fn userinfo_is_not_part_of_the_host() {
        let target = parse_absolute("http://user:p%40w@a.test/x").unwrap();
        assert_eq!(target.host, "a.test");
        assert_eq!(target.userinfo.as_deref(), Some(&b"user:p@w"[..]));
        let bare = parse_absolute("http://user@a.test/").unwrap();
        assert_eq!(bare.userinfo.as_deref(), Some(&b"user:"[..]));
        assert_eq!(parse_absolute("http://a.test/").unwrap().userinfo, None);
    }

    #[test]
    fn targets_without_a_scheme_or_host_are_not_absolute() {
        assert!(parse_absolute("/path").is_none());
        assert!(parse_absolute("example.com:443").is_none());
        assert!(parse_absolute("*").is_none());
        assert!(parse_absolute("http:///path").is_none());
        assert!(parse_absolute("http://a.test:port/").is_none());
    }

    #[test]
    fn authorities_for_connect() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(("example.com".into(), Some(443)))
        );
        assert_eq!(
            parse_authority("example.com"),
            Some(("example.com".into(), None))
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:443"),
            Some(("2001:db8::1".into(), Some(443)))
        );
        assert_eq!(parse_authority("::1:443"), None);
        assert_eq!(parse_authority(":443"), None);
    }
}
