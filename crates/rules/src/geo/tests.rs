use std::net::IpAddr;

use super::dat::testing::site;
use super::test_mmdb::{Value, build};
use super::*;

fn addr(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn store() -> (tempfile::TempDir, GeoStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = GeoStore::new(dir.path());
    (dir, store)
}

#[test]
fn absent_files_are_reported_not_downloaded() {
    let (dir, store) = store();
    for file in [GeoFile::Mmdb, GeoFile::Asn, GeoFile::GeoSite] {
        assert!(
            matches!(store.ensure(file), Err(GeoError::Missing { .. })),
            "{file}"
        );
    }
    assert!(matches!(
        store.site_slot("cn"),
        Err(GeoError::Missing { .. })
    ));
    assert!(!store.has_country(addr("1.1.1.1"), "cn"));
    assert!(!store.asn_is(addr("1.1.1.1"), "0"));
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
}

#[test]
fn file_names_match_case_insensitively_with_a_default() {
    let (dir, store) = store();
    assert_eq!(store.path(GeoFile::Mmdb), dir.path().join("geoip.metadb"));
    std::fs::write(dir.path().join("GEOIP.METADB"), b"x").unwrap();
    std::fs::write(dir.path().join("geosite.dat"), b"x").unwrap();
    assert_eq!(store.path(GeoFile::Mmdb), dir.path().join("GEOIP.METADB"));
    assert_eq!(store.path(GeoFile::GeoSite), dir.path().join("geosite.dat"));
    assert_eq!(store.path(GeoFile::Asn), dir.path().join("ASN.mmdb"));
}

#[test]
fn maxmind_country_layout_lowercases_the_code() {
    let (dir, store) = store();
    let country = |code: &str| {
        Value::map(vec![(
            "country",
            Value::map(vec![("iso_code", Value::s(code))]),
        )])
    };
    let bytes = build(
        "GeoLite2-Country",
        &[
            ("1.0.0.0", 8, country("CN")),
            ("8.8.0.0", 16, country("US")),
        ],
    );
    std::fs::write(dir.path().join("geoip.metadb"), bytes).unwrap();
    store.ensure(GeoFile::Mmdb).unwrap();
    assert!(store.has_country(addr("1.2.3.4"), "cn"));
    assert!(!store.has_country(addr("1.2.3.4"), "us"));
    assert!(store.has_country(addr("8.8.4.4"), "us"));
    assert!(!store.has_country(addr("9.9.9.9"), "cn"));
    assert_eq!(store.country_codes(addr("1.2.3.4")), ["cn"]);
    assert_eq!(store.country_codes(addr("::ffff:1.2.3.4")), ["cn"]);
    assert!(store.country_codes(addr("9.9.9.9")).is_empty());
}

#[test]
fn sing_and_meta_layouts() {
    let (dir, store) = store();
    let sing = build("sing-geoip", &[("1.0.0.0", 8, Value::s("cn"))]);
    std::fs::write(dir.path().join("geoip.metadb"), sing).unwrap();
    store.ensure(GeoFile::Mmdb).unwrap();
    assert!(store.has_country(addr("1.9.9.9"), "cn"));

    let meta = build(
        "Meta-geoip0",
        &[
            ("1.0.0.0", 8, Value::s("cn")),
            (
                "2.0.0.0",
                8,
                Value::Array(vec![Value::s("us"), Value::s("ca")]),
            ),
        ],
    );
    std::fs::write(dir.path().join("geoip.metadb"), meta).unwrap();
    store.reload(GeoFile::Mmdb).unwrap();
    assert!(store.has_country(addr("1.9.9.9"), "cn"));
    assert!(store.has_country(addr("2.9.9.9"), "ca") && store.has_country(addr("2.9.9.9"), "us"));
    assert!(!store.has_country(addr("2.9.9.9"), "cn"));
    assert_eq!(store.country_codes(addr("2.9.9.9")), ["us", "ca"]);
}

#[test]
fn asn_layouts() {
    let (dir, store) = store();
    let record = |n: u32, org: &str| {
        Value::map(vec![
            ("autonomous_system_number", Value::U32(n)),
            ("autonomous_system_organization", Value::s(org)),
        ])
    };
    let bytes = build(
        "GeoLite2-ASN",
        &[("1.1.1.0", 24, record(13335, "Cloudflare"))],
    );
    std::fs::write(dir.path().join("ASN.mmdb"), bytes).unwrap();
    store.ensure(GeoFile::Asn).unwrap();
    assert!(store.asn_is(addr("1.1.1.1"), "13335"));
    assert!(!store.asn_is(addr("1.1.1.1"), "13336"));
    assert!(store.asn_is(addr("9.9.9.9"), "0"));
    let found = store.asn(addr("1.1.1.1")).unwrap();
    assert_eq!(
        (found.asn.as_str(), found.org.as_str()),
        ("13335", "Cloudflare")
    );

    let ipinfo = build(
        "ipinfo generic_asn_free.mmdb",
        &[(
            "5.5.5.0",
            24,
            Value::map(vec![
                ("asn", Value::s("AS4134")),
                ("name", Value::s("Chinanet")),
            ]),
        )],
    );
    std::fs::write(dir.path().join("ASN.mmdb"), ipinfo).unwrap();
    store.reload(GeoFile::Asn).unwrap();
    assert!(store.asn_is(addr("5.5.5.5"), "4134"));
    assert!(!store.asn_is(addr("6.6.6.6"), "4134"));
}

#[test]
fn a_broken_mmdb_is_invalid() {
    let (dir, store) = store();
    std::fs::write(dir.path().join("geoip.metadb"), b"not a database").unwrap();
    assert!(matches!(
        store.ensure(GeoFile::Mmdb),
        Err(GeoError::Invalid { .. })
    ));
}

#[test]
fn site_slots_load_one_category_and_pick_up_reloads() {
    let (dir, store) = store();
    let path = dir.path().join("GeoSite.dat");
    let mut data = site("cn", &[(2, "baidu.com", &[])]);
    data.extend(site(
        "ads",
        &[(2, "ads.example", &["ads"]), (2, "plain.example", &[])],
    ));
    std::fs::write(&path, &data).unwrap();

    let cn = store.site_slot("CN").unwrap();
    assert!(cn.matches("www.baidu.com") && !cn.matches("google.com"));
    let ads = store.site_slot("ads@ads").unwrap();
    assert!(ads.matches("x.ads.example") && !ads.matches("plain.example"));
    let not_cn = store.site_slot("!cn").unwrap();
    assert!(not_cn.matches("google.com") && !not_cn.matches("baidu.com"));
    assert!(
        matches!(store.site_slot("missing"), Err(GeoError::Load(m)) if m.contains("code not found"))
    );

    std::fs::write(&path, site("cn", &[(2, "qq.com", &[])])).unwrap();
    store.reload(GeoFile::GeoSite).unwrap_err();
    assert!(cn.matches("www.qq.com") && !cn.matches("www.baidu.com"));
    assert!(Arc::ptr_eq(&cn, &store.site_slot("cn").unwrap()));
}

#[test]
fn lan_covers_the_go_helper_set() {
    for lan in [
        "10.1.1.1",
        "172.16.0.1",
        "192.168.0.1",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "169.254.1.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::",
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.0.1",
    ] {
        assert!(is_lan(addr(lan)), "{lan}");
    }
    for wan in [
        "8.8.8.8",
        "172.32.0.1",
        "2001:db8::1",
        "1.1.1.1",
        "::ffff:0.0.0.0",
        "::ffff:8.8.8.8",
    ] {
        assert!(!is_lan(addr(wan)), "{wan}");
    }
}

#[cfg(unix)]
static MAPPED_OPENS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(unix)]
fn open_counting_mappings(path: &Path) -> std::io::Result<Box<dyn AsRef<[u8]> + Send + Sync>> {
    let file = concord_platform::mmap::MappedFile::open(path)?;
    if file.is_mapped() {
        MAPPED_OPENS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    Ok(Box::new(file))
}

fn country_db(code: &str) -> Vec<u8> {
    let country = Value::map(vec![(
        "country",
        Value::map(vec![("iso_code", Value::s(code))]),
    )]);
    build("GeoLite2-Country", &[("1.0.0.0", 8, country)])
}

fn replace_atomically(dir: &Path, name: &str, bytes: &[u8]) {
    let staged = dir.join(format!("{name}.tmp"));
    std::fs::write(&staged, bytes).unwrap();
    std::fs::rename(&staged, dir.join(name)).unwrap();
}

#[cfg(unix)]
#[test]
fn a_database_is_read_through_a_file_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let store = GeoStore::new(dir.path()).with_opener(open_counting_mappings);
    std::fs::write(dir.path().join("geoip.metadb"), country_db("CN")).unwrap();
    store.reload(GeoFile::Mmdb).unwrap();
    assert!(store.has_country(addr("1.2.3.4"), "cn"));
    assert_eq!(
        MAPPED_OPENS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the reader's bytes are a mapping, not a heap copy"
    );
}

#[test]
fn a_reload_answers_from_the_replaced_file_and_stores_stay_independent() {
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let open = concord_platform::mmap::open_read_only;
    let store = GeoStore::new(dir.path()).with_opener(open);
    let sibling = GeoStore::new(other.path()).with_opener(open);
    std::fs::write(dir.path().join("geoip.metadb"), country_db("CN")).unwrap();
    std::fs::write(other.path().join("geoip.metadb"), country_db("JP")).unwrap();
    store.reload(GeoFile::Mmdb).unwrap();
    sibling.reload(GeoFile::Mmdb).unwrap();

    replace_atomically(dir.path(), "geoip.metadb", &country_db("US"));
    assert!(
        store.has_country(addr("1.2.3.4"), "cn"),
        "before the reload"
    );
    store.reload(GeoFile::Mmdb).unwrap();
    assert!(store.has_country(addr("1.2.3.4"), "us"));
    assert!(!store.has_country(addr("1.2.3.4"), "cn"));
    assert!(sibling.has_country(addr("1.2.3.4"), "jp"));
}

const PROBES: [&str; 12] = [
    "1.2.3.4",
    "1.1.1.1",
    "2.9.9.9",
    "8.8.4.4",
    "8.8.8.8",
    "9.9.9.9",
    "0.0.0.0",
    "255.255.255.255",
    "::ffff:1.1.1.1",
    "::ffff:8.8.8.8",
    "2001:db8::1",
    "::",
];

type Answer = (Vec<String>, Option<(String, String)>, bool);

fn write_probe_databases(dir: &Path) {
    let meta = build(
        "Meta-geoip0",
        &[
            ("1.0.0.0", 8, Value::s("cn")),
            (
                "2.0.0.0",
                8,
                Value::Array(vec![Value::s("us"), Value::s("ca")]),
            ),
            ("8.8.0.0", 16, Value::s("us")),
        ],
    );
    let record = |n: u32, org: &str| {
        Value::map(vec![
            ("autonomous_system_number", Value::U32(n)),
            ("autonomous_system_organization", Value::s(org)),
        ])
    };
    let asn = build(
        "GeoLite2-ASN",
        &[
            ("1.1.1.0", 24, record(13335, "Cloudflare")),
            ("8.8.8.0", 24, record(15169, "Google")),
        ],
    );
    std::fs::write(dir.join("geoip.metadb"), meta).unwrap();
    std::fs::write(dir.join("ASN.mmdb"), asn).unwrap();
}

fn probe_answers(store: &GeoStore) -> Vec<Answer> {
    store.reload(GeoFile::Mmdb).unwrap();
    store.reload(GeoFile::Asn).unwrap();
    PROBES
        .iter()
        .map(|text| {
            let ip = addr(text);
            (
                store.country_codes(ip),
                store.asn(ip).map(|found| (found.asn, found.org)),
                store.asn_is(ip, "13335"),
            )
        })
        .collect()
}

#[test]
fn the_probe_addresses_get_the_answers_the_databases_hold() {
    let (dir, store) = store();
    write_probe_databases(dir.path());
    let answers = probe_answers(&store);
    let codes = |codes: &[&str]| {
        codes
            .iter()
            .map(|code| code.to_string())
            .collect::<Vec<_>>()
    };
    let asn = |n: &str, org: &str| Some((n.to_string(), org.to_string()));
    assert_eq!(answers[0], (codes(&["cn"]), asn("0", ""), false));
    assert_eq!(
        answers[1],
        (codes(&["cn"]), asn("13335", "Cloudflare"), true)
    );
    assert_eq!(answers[2], (codes(&["us", "ca"]), asn("0", ""), false));
    assert_eq!(answers[3], (codes(&["us"]), asn("0", ""), false));
    assert_eq!(answers[4], (codes(&["us"]), asn("15169", "Google"), false));
    assert_eq!(answers[5], (codes(&[]), asn("0", ""), false));
}

#[test]
fn a_mapped_database_answers_like_the_heap_copy() {
    let dir = tempfile::tempdir().unwrap();
    write_probe_databases(dir.path());
    let heap = probe_answers(&GeoStore::new(dir.path()));
    let mapped = GeoStore::new(dir.path()).with_opener(concord_platform::mmap::open_read_only);
    assert_eq!(probe_answers(&mapped), heap);
    assert_eq!(probe_answers(&mapped), heap, "after a second reload");
}
