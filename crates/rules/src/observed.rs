/// What GEOIP and IP-ASN rules learned about a flow; `None` means no rule asked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observed {
    pub src_geoip: Option<Vec<String>>,
    pub dst_geoip: Option<Vec<String>>,
    pub src_asn: String,
    pub dst_asn: String,
}

impl Observed {
    pub(crate) fn geoip_mut(&mut self, src: bool) -> &mut Option<Vec<String>> {
        if src {
            &mut self.src_geoip
        } else {
            &mut self.dst_geoip
        }
    }

    pub(crate) fn asn_mut(&mut self, src: bool) -> &mut String {
        if src {
            &mut self.src_asn
        } else {
            &mut self.dst_asn
        }
    }
}
