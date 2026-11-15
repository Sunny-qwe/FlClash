use std::fmt;
use std::net::IpAddr;

use maxminddb::Reader;
use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use smallvec::SmallVec;

use super::GeoError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpKind {
    Maxmind,
    Sing,
    MetaV0,
}

/// The bytes of a database, owned by whoever opened them.
pub(super) struct Source(Box<dyn AsRef<[u8]> + Send + Sync>);

impl Source {
    pub(super) fn new(bytes: Box<dyn AsRef<[u8]> + Send + Sync>) -> Source {
        Source(bytes)
    }
}

impl AsRef<[u8]> for Source {
    fn as_ref(&self) -> &[u8] {
        (*self.0).as_ref()
    }
}

pub(crate) struct IpDb {
    reader: Reader<Source>,
    kind: IpKind,
}

#[derive(Deserialize, Default)]
struct CountryRecord<'a> {
    #[serde(default, borrow)]
    country: CountryInner<'a>,
}

#[derive(Deserialize, Default)]
struct CountryInner<'a> {
    #[serde(default, borrow)]
    iso_code: Option<&'a str>,
}

/// The `Meta-geoip0` record: a single code or a list of codes.
struct Codes<'a>(SmallVec<[&'a str; 4]>);

impl<'de> Deserialize<'de> for Codes<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CodesVisitor;
        impl<'de> Visitor<'de> for CodesVisitor {
            type Value = Codes<'de>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a country code or a list of them")
            }

            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                Ok(Codes(SmallVec::from_buf_and_len([v, "", "", ""], 1)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut codes = SmallVec::new();
                while let Some(code) = seq.next_element::<&'de str>()? {
                    codes.push(code);
                }
                Ok(Codes(codes))
            }
        }
        deserializer.deserialize_any(CodesVisitor)
    }
}

impl IpDb {
    pub(super) fn validate(bytes: &[u8]) -> Result<(), String> {
        Reader::from_source(bytes)
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    pub(super) fn from_source(source: Source) -> Result<IpDb, String> {
        let reader = Reader::from_source(source).map_err(|err| err.to_string())?;
        let kind = match reader.metadata().database_type.as_str() {
            "sing-geoip" => IpKind::Sing,
            "Meta-geoip0" => IpKind::MetaV0,
            _ => IpKind::Maxmind,
        };
        Ok(IpDb { reader, kind })
    }

    /// Calls `f` with each country code the database holds for `ip`, in
    /// lowercase for the MaxMind layout, until it returns true.
    pub(crate) fn any_code(&self, ip: IpAddr, mut f: impl FnMut(&str) -> bool) -> bool {
        let Ok(result) = self.reader.lookup(ip) else {
            return false;
        };
        match self.kind {
            IpKind::Maxmind => {
                let Ok(Some(record)) = result.decode::<CountryRecord<'_>>() else {
                    return false;
                };
                match record.country.iso_code {
                    Some(code) if !code.is_empty() => {
                        let mut lower: SmallVec<[u8; 8]> = SmallVec::new();
                        lower.extend(code.bytes().map(|b| b.to_ascii_lowercase()));
                        std::str::from_utf8(&lower).is_ok_and(f)
                    }
                    _ => false,
                }
            }
            IpKind::Sing => match result.decode::<&str>() {
                Ok(Some(code)) if !code.is_empty() => f(code),
                _ => false,
            },
            IpKind::MetaV0 => match result.decode::<Codes<'_>>() {
                Ok(Some(codes)) => codes.0.iter().any(|code| f(code)),
                _ => false,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsnKind {
    GeoLite2,
    IpInfo,
    Unsupported,
}

pub(crate) struct AsnDb {
    reader: Reader<Source>,
    kind: AsnKind,
}

#[derive(Deserialize, Default)]
struct GeoLite2Asn<'a> {
    #[serde(default)]
    autonomous_system_number: u32,
    #[serde(default, borrow)]
    autonomous_system_organization: &'a str,
}

#[derive(Deserialize, Default)]
struct IpInfoAsn<'a> {
    #[serde(default, borrow)]
    asn: &'a str,
    #[serde(default, borrow)]
    name: &'a str,
}

/// What a lookup yields: the number as text and the organisation.
pub struct AsnRecord {
    pub asn: String,
    pub org: String,
}

impl AsnDb {
    pub(super) fn from_source(source: Source) -> Result<AsnDb, String> {
        let reader = Reader::from_source(source).map_err(|err| err.to_string())?;
        let kind = match reader.metadata().database_type.as_str() {
            "GeoLite2-ASN" | "DBIP-ASN-Lite (compat=GeoLite2-ASN)" => AsnKind::GeoLite2,
            "ipinfo generic_asn_free.mmdb" => AsnKind::IpInfo,
            _ => AsnKind::Unsupported,
        };
        Ok(AsnDb { reader, kind })
    }

    /// Compares the record's ASN, rendered the way mihomo renders it, with `asn`.
    pub(crate) fn asn_is(&self, ip: IpAddr, asn: &str) -> bool {
        let Ok(result) = self.reader.lookup(ip) else {
            return false;
        };
        match self.kind {
            AsnKind::GeoLite2 => {
                let number = match result.decode::<GeoLite2Asn<'_>>() {
                    Ok(Some(record)) => record.autonomous_system_number,
                    _ => 0,
                };
                let mut buf = [0u8; 10];
                decimal(number, &mut buf) == asn
            }
            AsnKind::IpInfo => match result.decode::<IpInfoAsn<'_>>() {
                Ok(Some(record)) => record.asn.get(2..).is_some_and(|rest| rest == asn),
                _ => false,
            },
            AsnKind::Unsupported => false,
        }
    }

    pub(crate) fn lookup(&self, ip: IpAddr) -> Option<AsnRecord> {
        let result = self.reader.lookup(ip).ok()?;
        match self.kind {
            AsnKind::GeoLite2 => {
                let record = result
                    .decode::<GeoLite2Asn<'_>>()
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                Some(AsnRecord {
                    asn: record.autonomous_system_number.to_string(),
                    org: record.autonomous_system_organization.to_string(),
                })
            }
            AsnKind::IpInfo => {
                let record = result.decode::<IpInfoAsn<'_>>().ok().flatten()?;
                Some(AsnRecord {
                    asn: record.asn.get(2..)?.to_string(),
                    org: record.name.to_string(),
                })
            }
            AsnKind::Unsupported => None,
        }
    }
}

fn decimal(mut n: u32, buf: &mut [u8; 10]) -> &str {
    let mut at = buf.len();
    loop {
        at -= 1;
        if let Some(slot) = buf.get_mut(at) {
            *slot = b'0' + (n % 10) as u8;
        }
        n /= 10;
        if n == 0 || at == 0 {
            break;
        }
    }
    buf.get(at..)
        .and_then(|digits| std::str::from_utf8(digits).ok())
        .unwrap_or("")
}

pub(super) fn invalid(file: super::GeoFile, message: String) -> GeoError {
    GeoError::Invalid { file, message }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_renders_like_sprint() {
        let mut buf = [0u8; 10];
        assert_eq!(decimal(0, &mut buf), "0");
        assert_eq!(decimal(13335, &mut buf), "13335");
        assert_eq!(decimal(u32::MAX, &mut buf), "4294967295");
    }
}
