#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionInfo {
    pub upload: i64,
    pub download: i64,
    pub total: i64,
    pub expire: i64,
}

impl SubscriptionInfo {
    pub fn parse(userinfo: &str) -> SubscriptionInfo {
        let userinfo = userinfo.to_lowercase().replace(' ', "");
        let mut info = SubscriptionInfo::default();
        for field in userinfo.split(';') {
            let Some((name, value)) = field.split_once('=') else {
                continue;
            };
            let Some(value) = parse_value(value) else {
                tracing::warn!(
                    "[Provider] get subscription-userinfo: failed to parse value '{value}'"
                );
                continue;
            };
            match name {
                "upload" => info.upload = value,
                "download" => info.download = value,
                "total" => info.total = value,
                "expire" => info.expire = value,
                _ => {}
            }
        }
        info
    }
}

fn parse_value(value: &str) -> Option<i64> {
    if let Ok(int) = value.parse::<i64>() {
        return Some(int);
    }
    value.parse::<f64>().ok().map(|float| float as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_reads_like_mihomo_does() {
        let info =
            SubscriptionInfo::parse("upload=1; Download=2.9e3 ;total=4294967296;expire=1700000000");
        assert_eq!(
            info,
            SubscriptionInfo {
                upload: 1,
                download: 2900,
                total: 4_294_967_296,
                expire: 1_700_000_000
            }
        );
    }

    #[test]
    fn bad_fields_are_skipped_and_the_rest_kept() {
        let info = SubscriptionInfo::parse("upload=x;junk;download=5;;total=");
        assert_eq!(
            (info.upload, info.download, info.total, info.expire),
            (0, 5, 0, 0)
        );
    }
}
