use url::{Host, Url};

pub(crate) const HTTPS_PORT: u16 = 443;
pub(crate) const HTTP_PORT: u16 = 80;

pub(crate) fn default_port(https: bool) -> u16 {
    if https { HTTPS_PORT } else { HTTP_PORT }
}

/// Where a request is going. `raw` is what the rules match and the capture shows.
#[derive(Clone, Debug)]
pub(crate) struct TargetUrl {
    pub raw: String,
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path_and_query: String,
}

impl TargetUrl {
    /// A URL a rewrite or a script may send the request to instead.
    pub fn parse_http(raw: &str) -> Option<TargetUrl> {
        let url = Url::parse(raw).ok()?;
        let https = match url.scheme() {
            "http" => false,
            "https" => true,
            _ => return None,
        };
        let host = match url.host()? {
            Host::Domain(name) if !name.is_empty() => name.to_string(),
            Host::Domain(_) => return None,
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        let authority = match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_string(),
            _ => return None,
        };
        let mut path_and_query = url.path().to_string();
        if let Some(query) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(query);
        }
        Some(TargetUrl {
            raw: url.as_str().to_string(),
            https,
            host,
            port: url.port_or_known_default().unwrap_or(default_port(https)),
            authority,
            path_and_query,
        })
    }

    /// From the authority and path as a client sent them, kept byte for byte.
    pub fn from_request(https: bool, authority: &str, path_and_query: &str) -> Option<TargetUrl> {
        let scheme = if https { "https" } else { "http" };
        let (host, explicit) = split_authority(authority)?;
        Some(TargetUrl {
            raw: format!("{scheme}://{authority}{path_and_query}"),
            https,
            host,
            port: explicit.unwrap_or(default_port(https)),
            authority: authority.to_string(),
            path_and_query: path_and_query.to_string(),
        })
    }
}

fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            Some((host.to_string(), Some(port.parse().ok()?)))
        }
        Some(_) => None,
        None => Some((authority.to_string(), None)),
    }
    .filter(|(host, _)| !host.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_urls_keep_their_bytes() {
        let url = TargetUrl::from_request(true, "example.test", "/a{b}?q=1").unwrap();
        assert_eq!(url.raw, "https://example.test/a{b}?q=1");
        assert_eq!((url.host.as_str(), url.port), ("example.test", 443));
        let url = TargetUrl::from_request(false, "[::1]:8080", "/").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("::1", 8080));
        assert!(TargetUrl::from_request(true, "", "/").is_none());
        assert!(TargetUrl::from_request(true, "host:notaport", "/").is_none());
    }

    #[test]
    fn rewritten_urls_must_be_http_or_https() {
        let url = TargetUrl::parse_http("https://other.test:8443/p?x=1").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("other.test", 8443));
        assert_eq!(url.authority, "other.test:8443");
        assert_eq!(url.path_and_query, "/p?x=1");
        assert_eq!(
            TargetUrl::parse_http("http://a.test")
                .unwrap()
                .path_and_query,
            "/"
        );
        for bad in ["ftp://a.test/", "file:///x", "not a url", "//a.test/"] {
            assert!(TargetUrl::parse_http(bad).is_none(), "{bad}");
        }
    }
}
