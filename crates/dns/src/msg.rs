use std::fmt;
use std::net::IpAddr;

use concord_common::addr::unmap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

pub const SERVER_FAILURE_TTL: u32 = 5;

pub fn qtype_code(rt: RecordType) -> u16 {
    u16::from(rt)
}

pub fn qtype_name(rt: RecordType) -> String {
    match rt {
        RecordType::Unknown(code) => format!("TYPE{code}"),
        other => other.to_string(),
    }
}

pub fn rcode_name(code: ResponseCode) -> String {
    match u16::from(code) {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMPL".into(),
        5 => "REFUSED".into(),
        6 => "YXDOMAIN".into(),
        7 => "YXRRSET".into(),
        8 => "NXRRSET".into(),
        9 => "NOTAUTH".into(),
        10 => "NOTZONE".into(),
        16 => "BADSIG".into(),
        17 => "BADKEY".into(),
        18 => "BADTIME".into(),
        19 => "BADMODE".into(),
        20 => "BADNAME".into(),
        21 => "BADALG".into(),
        22 => "BADTRUNC".into(),
        23 => "BADCOOKIE".into(),
        other => format!("RCODE{other}"),
    }
}

pub fn first_query(msg: &Message) -> Option<&Query> {
    msg.queries.first()
}

pub fn is_ip_request(query: &Query) -> bool {
    query.query_class == DNSClass::IN
        && matches!(
            query.query_type,
            RecordType::A | RecordType::AAAA | RecordType::CNAME
        )
}

pub fn query_domain(query: &Query) -> String {
    let mut text = query.name.to_ascii();
    while text.ends_with('.') {
        text.pop();
    }
    text
}

pub fn msg_domain(msg: &Message) -> String {
    first_query(msg).map(query_domain).unwrap_or_default()
}

/// Writes the cache key: the lower-cased labels with bytes outside `[A-Za-z0-9_-]` escaped,
/// then the class and type codes.
fn write_cache_key(query: &Query, out: &mut impl fmt::Write) -> fmt::Result {
    if query.name.is_root() {
        out.write_char('.')?;
    }
    for label in query.name.iter() {
        for byte in label.iter().copied() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                out.write_char(char::from(byte.to_ascii_lowercase()))?;
            } else {
                write!(out, "\\{byte:02x}")?;
            }
        }
        out.write_char('.')?;
    }
    write!(
        out,
        "\t{}\t{}",
        u16::from(query.query_class),
        qtype_code(query.query_type)
    )
}

pub fn cache_key(query: &Query) -> String {
    let mut key = String::new();
    let _ = write_cache_key(query, &mut key);
    key
}

struct StackKey {
    bytes: [u8; 320],
    len: usize,
}

impl fmt::Write for StackKey {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len + text.len();
        self.bytes
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Runs `read` on the cache key without allocating when it fits a stack buffer, which
/// every name of ordinary length does.
pub fn with_cache_key<R>(query: &Query, read: impl FnOnce(&str) -> R) -> R {
    let mut key = StackKey {
        bytes: [0; 320],
        len: 0,
    };
    if write_cache_key(query, &mut key).is_ok()
        && let Some(text) = key
            .bytes
            .get(..key.len)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
    {
        return read(text);
    }
    read(&cache_key(query))
}

pub fn fqdn_name(host: &str) -> Option<Name> {
    let mut text = host.to_string();
    if !text.ends_with('.') {
        text.push('.');
    }
    Name::from_utf8(&text)
        .or_else(|_| Name::from_ascii(&text))
        .ok()
}

pub fn build_query(host: &str, rt: RecordType) -> Option<Message> {
    let mut msg = Message::query();
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(fqdn_name(host)?, rt));
    Some(msg)
}

pub fn answer_ips(msg: &Message) -> Vec<IpAddr> {
    msg.answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(A(ip)) => Some(unmap(IpAddr::V4(*ip))),
            RData::AAAA(AAAA(ip)) => Some(unmap(IpAddr::V6(*ip))),
            _ => None,
        })
        .collect()
}

/// The first `ech` parameter among the answer's HTTPS records, in answer order.
pub fn ech_config_list(msg: &Message) -> Option<Vec<u8>> {
    msg.answers.iter().find_map(|record| match &record.data {
        RData::HTTPS(https) => https
            .0
            .svc_params
            .iter()
            .find_map(|(_, value)| match value {
                SvcParamValue::EchConfigList(list) => Some(list.0.clone()),
                _ => None,
            }),
        _ => None,
    })
}

pub fn answer_text(record: &Record) -> String {
    match &record.data {
        RData::A(A(ip)) => ip.to_string(),
        RData::AAAA(AAAA(ip)) => ip.to_string(),
        RData::CNAME(CNAME(name)) => {
            let mut text = name.to_ascii();
            while text.ends_with('.') {
                text.pop();
            }
            text
        }
        other => other.to_string().trim().to_string(),
    }
}

pub fn set_reply(resp: &mut Message, request: &Message, rcode: ResponseCode) {
    resp.metadata.id = request.metadata.id;
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.op_code = request.metadata.op_code;
    resp.metadata.recursion_desired = request.metadata.recursion_desired;
    resp.metadata.checking_disabled = request.metadata.checking_disabled;
    resp.metadata.response_code = rcode;
    resp.queries = request.queries.clone();
}

pub fn empty_answer(request: &Message) -> Message {
    let mut resp = Message::response(request.metadata.id, OpCode::Query);
    set_reply(&mut resp, request, ResponseCode::NoError);
    resp.metadata.authoritative = true;
    resp.metadata.recursion_available = true;
    resp
}

pub fn error_reply(request: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::response(request.metadata.id, OpCode::Query);
    set_reply(&mut resp, request, rcode);
    resp
}

fn all_ttls(msg: &Message) -> impl Iterator<Item = u32> + '_ {
    msg.answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
        .map(|record| record.ttl)
}

pub fn minimal_ttl(msg: &Message) -> u32 {
    all_ttls(msg).min().unwrap_or(0)
}

pub fn cache_ttl(msg: &Message) -> u32 {
    if msg.metadata.response_code == ResponseCode::ServFail {
        SERVER_FAILURE_TTL
    } else {
        minimal_ttl(msg)
    }
}

pub fn set_msg_ttl(msg: &mut Message, ttl: u32) {
    for record in msg
        .answers
        .iter_mut()
        .chain(&mut msg.authorities)
        .chain(&mut msg.additionals)
    {
        record.ttl = ttl;
    }
}

fn update_section_ttl(records: &mut [Record], ttl: u32) {
    let Some(min) = records.iter().map(|record| record.ttl).min() else {
        return;
    };
    let delta = min.wrapping_sub(ttl);
    for record in records {
        record.ttl = record.ttl.wrapping_sub(delta).clamp(1, record.ttl.max(1));
    }
}

pub fn update_msg_ttl(msg: &mut Message, ttl: u32) {
    update_section_ttl(&mut msg.answers, ttl);
    update_section_ttl(&mut msg.authorities, ttl);
    update_section_ttl(&mut msg.additionals, ttl);
}

pub fn is_acme_challenge(query: &Query) -> bool {
    query.query_type == RecordType::TXT
        && query
            .name
            .to_ascii()
            .to_ascii_lowercase()
            .starts_with("_acme-challenge.")
}

pub fn strip_ip_hints(msg: &mut Message) {
    strip_hints(msg, false);
}

pub fn strip_ipv6_hints(msg: &mut Message) {
    strip_hints(msg, true);
}

fn strip_hints(msg: &mut Message, keep_ipv4: bool) {
    for record in msg.answers.iter_mut().chain(&mut msg.additionals) {
        let svcb = match &mut record.data {
            RData::HTTPS(https) => &mut https.0,
            RData::SVCB(svcb) => svcb,
            _ => continue,
        };
        svcb.svc_params.retain(|(key, value)| {
            !matches!(
                (key, value),
                (SvcParamKey::Ipv6Hint, _) | (_, SvcParamValue::Ipv6Hint(_))
            ) && (keep_ipv4
                || !matches!(
                    (key, value),
                    (SvcParamKey::Ipv4Hint, _) | (_, SvcParamValue::Ipv4Hint(_))
                ))
        });
    }
}

pub enum Admission {
    Accept,
    Ignore,
    Reply(Vec<u8>),
}

/// What a DNS server does with a packet before resolving it, as miekg/dns does by default.
pub fn admit(query: &[u8]) -> Admission {
    let Some([id0, id1, flags, low, qd0, qd1, ..]) = query.first_chunk::<12>() else {
        return Admission::Accept;
    };
    if flags & 0x80 != 0 {
        return Admission::Ignore;
    }
    let opcode = OpCode::from_u8((flags >> 3) & 0x0f);
    let rcode = if opcode != OpCode::Query {
        ResponseCode::NotImp
    } else if u16::from_be_bytes([*qd0, *qd1]) != 1 {
        ResponseCode::FormErr
    } else {
        return Admission::Accept;
    };
    let mut resp = Message::response(u16::from_be_bytes([*id0, *id1]), opcode);
    resp.metadata.recursion_desired = flags & 0x01 != 0;
    resp.metadata.checking_disabled = low & 0x10 != 0;
    resp.metadata.response_code = rcode;
    if rcode == ResponseCode::NotImp
        && let Ok(req) = Message::from_vec(query)
    {
        resp.queries = req.queries;
    }
    encode(&resp).map_or(Admission::Ignore, Admission::Reply)
}

pub fn request_udp_size(request: &Message) -> usize {
    request
        .edns
        .as_ref()
        .map(|edns| usize::from(edns.max_payload()).max(512))
        .unwrap_or(512)
}

pub fn echo_edns(request: &Message, resp: &mut Message) {
    let Some(req_edns) = &request.edns else {
        return;
    };
    if resp.edns.is_some() {
        return;
    }
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
    resp.edns = Some(edns);
}

pub fn encode(msg: &Message) -> Option<Vec<u8>> {
    msg.to_vec().ok()
}

pub fn fit_udp(mut resp: Message, limit: usize) -> Option<Vec<u8>> {
    let bytes = encode(&resp)?;
    if bytes.len() <= limit {
        return Some(bytes);
    }
    resp.additionals.clear();
    let bytes = encode(&resp)?;
    if bytes.len() <= limit {
        return Some(bytes);
    }
    resp.authorities.clear();
    resp.metadata.truncation = true;
    while !resp.answers.is_empty() {
        let bytes = encode(&resp)?;
        if bytes.len() <= limit {
            return Some(bytes);
        }
        resp.answers.pop();
    }
    encode(&resp)
}

pub fn a_record(name: &Name, ttl: u32, ip: std::net::Ipv4Addr) -> Record {
    Record::from_rdata(name.clone(), ttl, RData::A(A(ip)))
}

pub fn aaaa_record(name: &Name, ttl: u32, ip: std::net::Ipv6Addr) -> Record {
    Record::from_rdata(name.clone(), ttl, RData::AAAA(AAAA(ip)))
}

pub fn cname_record(name: &Name, ttl: u32, target: &str) -> Option<Record> {
    let target = fqdn_name(target)?;
    Some(Record::from_rdata(
        name.clone(),
        ttl,
        RData::CNAME(CNAME(target)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_query(labels: &[&[u8]], qtype: RecordType, class: DNSClass) -> Query {
        let mut name = Name::from_labels(labels.iter().copied()).unwrap();
        name.set_fqdn(true);
        let mut query = Query::query(name, qtype);
        query.set_query_class(class);
        query
    }

    const ESCAPED_NAMES: [&[&[u8]]; 14] = [
        &[b"a.b", b"test"],
        &[b"a", b"b", b"test"],
        &[b"a\\", b"test"],
        &[b"a\\\\", b"test"],
        &[b"a5c", b"test"],
        &[b"a\\5c", b"test"],
        &[b"\xe4", b"test"],
        &[b"e4", b"test"],
        &[b"\\e4", b"test"],
        &[b"\xc3\xa4", b"test"],
        &[b"a b", b"test"],
        &[b"a_b", b"test"],
        &[b"a-b", b"test"],
        &[b"a\tb", b"test"],
    ];

    #[test]
    fn a_cache_key_folds_case_and_keeps_everything_else_apart() {
        let a = |labels: &[&[u8]]| cache_key(&key_query(labels, RecordType::A, DNSClass::IN));
        assert_eq!(
            a(&[b"Cache", b"EXAMPLE", b"com"]),
            a(&[b"cache", b"example", b"com"])
        );
        let name: &[&[u8]] = &[b"x", b"test"];
        assert_ne!(
            a(name),
            cache_key(&key_query(name, RecordType::AAAA, DNSClass::IN))
        );
        assert_ne!(
            a(name),
            cache_key(&key_query(name, RecordType::A, DNSClass::CH))
        );
        let keys: std::collections::HashSet<String> = ESCAPED_NAMES.iter().map(|n| a(n)).collect();
        assert_eq!(keys.len(), ESCAPED_NAMES.len(), "{keys:?}");
    }

    #[test]
    fn the_stack_key_is_the_heap_key() {
        let long = [[0xe4u8; 63]; 3];
        let long: Vec<&[u8]> = long.iter().map(|label| &label[..]).collect();
        let mut names: Vec<&[&[u8]]> = ESCAPED_NAMES.to_vec();
        names.push(&[b"Cache", b"EXAMPLE", b"com"]);
        names.push(&long);
        for labels in names {
            for (qtype, class) in [
                (RecordType::A, DNSClass::IN),
                (RecordType::HTTPS, DNSClass::CH),
            ] {
                let query = key_query(labels, qtype, class);
                assert_eq!(
                    with_cache_key(&query, str::to_string),
                    cache_key(&query),
                    "{labels:?}"
                );
            }
        }
    }

    #[test]
    fn names_for_events_match_the_go_spelling() {
        assert_eq!(qtype_name(RecordType::HTTPS), "HTTPS");
        assert_eq!(qtype_name(RecordType::A), "A");
        assert_eq!(qtype_name(RecordType::Unknown(65280)), "TYPE65280");
        assert_eq!(rcode_name(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_name(ResponseCode::NotImp), "NOTIMPL");
    }

    #[test]
    fn ttl_update_keeps_the_relative_gap_and_never_reaches_zero() {
        let name = Name::from_ascii("a.test.").unwrap();
        let mut msg = Message::response(1, OpCode::Query);
        msg.add_answer(a_record(&name, 60, "1.1.1.1".parse().unwrap()));
        msg.add_answer(a_record(&name, 300, "1.1.1.2".parse().unwrap()));
        update_msg_ttl(&mut msg, 20);
        let ttls: Vec<u32> = msg.answers.iter().map(|r| r.ttl).collect();
        assert_eq!(ttls, vec![20, 260]);
        update_msg_ttl(&mut msg, 0);
        assert!(msg.answers.iter().all(|r| r.ttl >= 1));
    }

    fn raw_query(flags: [u8; 2], qdcount: u8) -> Vec<u8> {
        let mut bytes = vec![0x12, 0x34, flags[0], flags[1], 0, qdcount, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(b"\x01a\x04test\x00\x00\x01\x00\x01");
        bytes
    }

    fn reply_of(admission: Admission) -> Message {
        match admission {
            Admission::Reply(bytes) => Message::from_vec(&bytes).unwrap(),
            _ => panic!("expected a reply"),
        }
    }

    #[test]
    fn a_server_ignores_responses_and_answers_what_it_cannot_serve() {
        assert!(matches!(admit(&raw_query([0x81, 0], 1)), Admission::Ignore));
        assert!(matches!(admit(&raw_query([0x01, 0], 1)), Admission::Accept));
        assert!(matches!(admit(&[1, 2, 3]), Admission::Accept));

        let notimp = reply_of(admit(&raw_query([0x20 | 0x01, 0], 1)));
        assert_eq!(notimp.metadata.id, 0x1234);
        assert_eq!(notimp.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(notimp.metadata.message_type, MessageType::Response);
        assert_eq!(notimp.metadata.op_code, OpCode::Notify);
        assert!(notimp.metadata.recursion_desired);
        assert_eq!(notimp.queries.len(), 1);

        for count in [0, 2] {
            let formerr = reply_of(admit(&raw_query([0x01, 0], count)));
            assert_eq!(formerr.metadata.id, 0x1234);
            assert_eq!(formerr.metadata.response_code, ResponseCode::FormErr);
            assert!(formerr.queries.is_empty());
        }
    }

    #[test]
    fn fit_udp_truncates_answers_and_sets_the_bit() {
        let name = Name::from_ascii("big.test.").unwrap();
        let mut msg = Message::response(1, OpCode::Query);
        msg.add_query(Query::query(name.clone(), RecordType::A));
        for i in 0..100u8 {
            msg.add_answer(a_record(&name, 60, std::net::Ipv4Addr::new(10, 0, 0, i)));
        }
        let bytes = fit_udp(msg, 512).unwrap();
        assert!(bytes.len() <= 512);
        let parsed = Message::from_vec(&bytes).unwrap();
        assert!(parsed.metadata.truncation);
        assert!(!parsed.answers.is_empty() && parsed.answers.len() < 100);
    }
}
