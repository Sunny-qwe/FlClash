const ISO3166_PACKED: &str = concat!(
    "ABWAWAFGAFAGOAOAIAAIALAAXALBALANDADAREAEARGARARMAMASMASATAAQ",
    "ATFTFATGAGAUSAUAUTATAZEAZBDIBIBELBEBENBJBESBQBFABFBGDBDBGRBG",
    "BHRBHBHSBSBIHBABLMBLBLRBYBLZBZBMUBMBOLBOBRABRBRBBBBRNBNBTNBT",
    "BVTBVBWABWCAFCFCANCACCKCCCHECHCHLCLCHNCNCIVCICMRCMCODCDCOGCG",
    "COKCKCOLCOCOMKMCPVCVCRICRCUBCUCUWCWCXRCXCYMKYCYPCYCZECZDEUDE",
    "DJIDJDMADMDNKDKDOMDODZADZECUECEGYEGERIERESHEHESPESESTEEETHET",
    "FINFIFJIFJFLKFKFRAFRFROFOFSMFMGABGAGBRGBGEOGEGGYGGGHAGHGIBGI",
    "GINGNGLPGPGMBGMGNBGWGNQGQGRCGRGRDGDGRLGLGTMGTGUFGFGUMGUGUYGY",
    "HKGHKHMDHMHNDHNHRVHRHTIHTHUNHUIDNIDIMNIMINDINIOTIOIRLIEIRNIR",
    "IRQIQISLISISRILITAITJAMJMJEYJEJORJOJPNJPKAZKZKENKEKGZKGKHMKH",
    "KIRKIKNAKNKORKRKWTKWLAOLALBNLBLBRLRLBYLYLCALCLIELILKALKLSOLS",
    "LTULTLUXLULVALVMACMOMAFMFMARMAMCOMCMDAMDMDGMGMDVMVMEXMXMHLMH",
    "MKDMKMLIMLMLTMTMMRMMMNEMEMNGMNMNPMPMOZMZMRTMRMSRMSMTQMQMUSMU",
    "MWIMWMYSMYMYTYTNAMNANCLNCNERNENFKNFNGANGNICNINIUNUNLDNLNORNO",
    "NPLNPNRUNRNZLNZOMNOMPAKPKPANPAPCNPNPERPEPHLPHPLWPWPNGPGPOLPL",
    "PRIPRPRKKPPRTPTPRYPYPSEPSPYFPFQATQAREUREROURORUSRURWARWSAUSA",
    "SDNSDSENSNSGPSGSGSGSSHNSHSJMSJSLBSBSLESLSLVSVSMRSMSOMSOSPMPM",
    "SRBRSSSDSSSTPSTSURSRSVKSKSVNSISWESESWZSZSXMSXSYCSCSYRSYTCATC",
    "TCDTDTGOTGTHATHTJKTJTKLTKTKMTMTLSTLTONTOTTOTTTUNTNTURTRTUVTV",
    "TWNTWTZATZUGAUGUKRUAUMIUMURYUYUSAUSUZBUZVATVAVCTVCVENVEVGBVG",
    "VIRVIVNMVNVUTVUWLFWFWSMWSYEMYEZAFZAZMBZMZWEZW"
);

const ENTRY: usize = 5;

/// Folds a country code to the alpha-2 form Dart renders a flag from, or an
/// empty string when it is not one. Only Gemini reports alpha-3.
pub fn normalize_region(code: &str) -> String {
    let code = code.trim().to_ascii_uppercase();
    match code.len() {
        2 if is_ascii_upper(&code) => code,
        3 if is_ascii_upper(&code) => alpha2(&code).unwrap_or_default().to_string(),
        _ => String::new(),
    }
}

pub fn is_ascii_upper(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn alpha2(code: &str) -> Option<&'static str> {
    let (mut low, mut high) = (0, ISO3166_PACKED.len() / ENTRY);
    while low < high {
        let mid = (low + high) / 2;
        let entry = ISO3166_PACKED.get(mid * ENTRY..(mid + 1) * ENTRY)?;
        match entry.get(..3)?.cmp(code) {
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
            std::cmp::Ordering::Equal => return entry.get(3..),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_codes_to_alpha_2() {
        let cases = [
            ("US", "US"),
            ("jp", "JP"),
            ("CHN", "CN"),
            ("usa", "US"),
            ("HKG", "HK"),
            ("ZZZ", ""),
            ("C", ""),
            ("CNAAA", ""),
            ("", ""),
            ("1A", ""),
            (" gb ", "GB"),
            ("É", ""),
        ];
        for (input, want) in cases {
            assert_eq!(normalize_region(input), want, "normalize_region({input:?})");
        }
    }

    #[test]
    fn table_is_sorted_and_whole() {
        let entries: Vec<&str> = (0..ISO3166_PACKED.len() / ENTRY)
            .filter_map(|index| ISO3166_PACKED.get(index * ENTRY..(index + 1) * ENTRY))
            .collect();
        assert_eq!(entries.len() * ENTRY, ISO3166_PACKED.len());
        assert!(entries.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(entries.len() > 240);
    }
}
