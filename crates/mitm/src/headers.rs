use http::header::{HeaderMap, HeaderName, HeaderValue};

use crate::script::HeaderList;
use crate::text::canonical_header;

pub(crate) fn to_list(map: &HeaderMap) -> HeaderList {
    let mut list = HeaderList::new();
    for (name, value) in map {
        list.entry(canonical_header(name.as_str()))
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    list
}

pub(crate) fn with_host(map: &HeaderMap, host: &str) -> HeaderList {
    let mut list = to_list(map);
    list.insert("Host".to_string(), vec![host.to_string()]);
    list
}

/// Names and values that cannot be put on the wire are left out.
pub(crate) fn from_list(list: &HeaderList) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, values) in list {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        for value in values {
            if let Ok(value) = HeaderValue::from_str(value) {
                map.append(name.clone(), value);
            }
        }
    }
    map
}

/// What frames the message is the body sent's to decide.
pub(crate) fn script_header(list: &HeaderList) -> HeaderMap {
    let mut map = from_list(list);
    for name in [
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
    ] {
        map.remove(name);
    }
    map
}

pub(crate) fn text(map: &HeaderMap, name: impl http::header::AsHeaderName) -> &str {
    map.get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

pub(crate) fn is_grpc(map: &HeaderMap) -> bool {
    text(map, http::header::CONTENT_TYPE)
        .to_ascii_lowercase()
        .starts_with("application/grpc")
}

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

/// Removes the headers that describe one hop, as a reverse proxy does; `upgrade`
/// stays when the exchange is a protocol switch, and `te: trailers` for gRPC.
pub(crate) fn remove_hop_by_hop(map: &mut HeaderMap, keep_upgrade: bool) {
    let named: Vec<String> = map
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    let trailers = map
        .get_all(http::header::TE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("trailers"));
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        if keep_upgrade && name == "connection" {
            continue;
        }
        map.remove(name);
    }
    if !keep_upgrade {
        map.remove(http::header::UPGRADE);
    }
    if trailers {
        map.insert(http::header::TE, HeaderValue::from_static("trailers"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_use_canonical_names_and_keep_every_value() {
        let mut map = HeaderMap::new();
        map.append("set-cookie", "a=1".parse().unwrap());
        map.append("set-cookie", "b=2".parse().unwrap());
        map.append("x-mitm", "yes".parse().unwrap());
        let list = to_list(&map);
        assert_eq!(list["Set-Cookie"], ["a=1", "b=2"]);
        assert_eq!(list["X-Mitm"], ["yes"]);
        assert_eq!(from_list(&list).get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn script_headers_drop_what_frames_the_message() {
        let list = HeaderList::from([
            ("Content-Length".to_string(), vec!["9".to_string()]),
            ("Connection".to_string(), vec!["close".to_string()]),
            ("X-A".to_string(), vec!["b".to_string()]),
        ]);
        let map = script_header(&list);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("x-a"));
    }

    #[test]
    fn hop_by_hop_headers_go_unless_the_exchange_upgrades() {
        let build = || {
            let mut map = HeaderMap::new();
            map.insert("connection", "keep-alive, x-private".parse().unwrap());
            map.insert("x-private", "1".parse().unwrap());
            map.insert("upgrade", "websocket".parse().unwrap());
            map.insert("te", "trailers".parse().unwrap());
            map.insert("x-keep", "1".parse().unwrap());
            map
        };
        let mut plain = build();
        remove_hop_by_hop(&mut plain, false);
        assert!(plain.contains_key("x-keep") && plain.contains_key("te"));
        assert!(
            !plain.contains_key("connection")
                && !plain.contains_key("x-private")
                && !plain.contains_key("upgrade")
        );
        let mut switching = build();
        remove_hop_by_hop(&mut switching, true);
        assert!(switching.contains_key("upgrade") && switching.contains_key("connection"));
    }
}
