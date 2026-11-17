mod fetch;
mod geo;
mod rule_providers;

use std::path::Path;
use std::time::SystemTime;

pub(crate) use self::fetch::{TunnelFetcher, download};
pub(crate) use self::geo::{GeoUpdater, GeoUrls, geo_file_of, geo_kind_of};
pub(crate) use self::rule_providers::{RuleProvider, RuleProviders, behavior_of, rule_set_request};
pub(crate) use crate::error::{GeoUpdateError, ResourceError, RuleLoadError, WriteError};

fn touch(path: &Path) {
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(SystemTime::now()));
}
