use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use concord_common::backoff::{GEO_RETRY_CAP, provider_backoff};
use concord_common::sync::lock;
use concord_common::{
    CoreError, CoreEvent, CoreOptions, EventSink, Fetch, Refresh, ResourceKind, ResourcePhase,
    ResourceUpdate,
};
use concord_config::geox::GeoConfig;
use concord_config::provider::{RuleBehavior, RuleFormat, RuleProviderDef, RuleSource};
use concord_group::http::{HttpError, Target, TlsSettings, connect};
use concord_group::{FetchError, FetchErrorKind, FetchRequest, FetchResponse, Fetcher};
use concord_platform::HomeDir;
use concord_rules::geo::{GeoFile, GeoStore};
use concord_rules::{
    Behavior, CompileEnv, Format, GeoFault, ParsedRuleSet, RuleSet, RuleSetHandle, RuleSetStore,
};
use concord_tls::TrustStore;
use concord_tunnel::Tunnel;
use md5::{Digest, Md5};
use tokio::time::{Instant, sleep};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub(crate) use crate::error::{GeoUpdateError, ResourceError, RuleLoadError, WriteError};
use crate::route::RouteCounters;

const PROVIDER_TIMEOUT: Duration = Duration::from_secs(20);
const GEO_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_REDIRECTS: usize = 10;

type Hash = [u8; 16];

/// Everything the core downloads goes through the tunnel as an inner flow, so a
/// provider can name the proxy it is fetched through.
pub(crate) struct TunnelFetcher {
    pub tunnel: Tunnel,
    pub trust: ArcSwap<TrustStore>,
    pub options: Arc<ArcSwap<CoreOptions>>,
    pub user_agent: ArcSwap<String>,
}

fn fetch_error(kind: FetchErrorKind, message: impl Into<String>) -> FetchError {
    FetchError {
        kind,
        message: message.into(),
    }
}

fn dial_error(err: &std::io::Error) -> FetchError {
    let kind = match (CoreError::of(err), err.kind()) {
        (Some(CoreError::IpNotFound(_)), _) => FetchErrorKind::Dns,
        (_, std::io::ErrorKind::TimedOut) => FetchErrorKind::Timeout,
        _ => FetchErrorKind::Connection,
    };
    fetch_error(kind, err.to_string())
}

fn http_error(err: HttpError) -> FetchError {
    let kind = match &err {
        HttpError::Tls(_) => FetchErrorKind::Tls,
        HttpError::Protocol(_) => FetchErrorKind::Connection,
        HttpError::Url(_) => FetchErrorKind::Other,
    };
    fetch_error(kind, err.to_string())
}

#[async_trait]
impl Fetcher for TunnelFetcher {
    async fn get(&self, request: FetchRequest) -> Result<FetchResponse, FetchError> {
        let deadline = Instant::now() + request.timeout;
        let mut url = request.url.clone();
        let mut headers = request.headers.clone();
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        {
            headers.push(("User-Agent".to_string(), self.user_agent.load().to_string()));
        }
        let limit = request
            .size_limit
            .and_then(|limit| usize::try_from(limit).ok())
            .unwrap_or(usize::MAX);
        let tls = TlsSettings {
            trust: self.trust.load_full(),
            skip_cert_verify: self.options.load().skip_cert_verify,
            offer_h2: true,
        };
        for _ in 0..MAX_REDIRECTS {
            let target = Target::parse(&url).map_err(http_error)?;
            let exchange = async {
                let stream = self
                    .tunnel
                    .dial_inner(&target.address(), request.via_proxy.as_deref())
                    .await
                    .map_err(|err| dial_error(&err))?;
                let mut connection = connect(stream, &target, &tls).await.map_err(http_error)?;
                connection
                    .send(http::Method::GET, &headers, Bytes::new(), limit)
                    .await
                    .map_err(http_error)
            };
            let response = tokio::time::timeout_at(deadline, exchange)
                .await
                .map_err(|_| fetch_error(FetchErrorKind::Timeout, "context deadline exceeded"))??;
            if response.status / 100 == 3
                && let Some(location) = response
                    .headers
                    .get(http::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
            {
                url = url::Url::parse(&url)
                    .and_then(|base| base.join(location))
                    .map_err(|err| fetch_error(FetchErrorKind::Other, err.to_string()))?
                    .to_string();
                continue;
            }
            return Ok(FetchResponse {
                status: response.status,
                headers: response
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        Some((name.to_string(), value.to_str().ok()?.to_string()))
                    })
                    .collect(),
                body: response.body.to_vec(),
            });
        }
        Err(fetch_error(
            FetchErrorKind::Other,
            "stopped after 10 redirects",
        ))
    }
}

/// A plain GET that treats anything but 2xx as a failure, as `HTTPVehicle.Read` does.
pub(crate) async fn download(
    fetcher: &dyn Fetcher,
    request: FetchRequest,
) -> Result<Vec<u8>, ResourceError> {
    let response = fetcher.get(request).await.map_err(ResourceError::Fetch)?;
    if !(200..=299).contains(&response.status) {
        return Err(ResourceError::Status(response.status));
    }
    Ok(response.body)
}

pub(crate) fn rule_set_request(url: &str) -> FetchRequest {
    FetchRequest {
        url: url.to_string(),
        headers: Vec::new(),
        via_proxy: None,
        size_limit: None,
        timeout: PROVIDER_TIMEOUT,
    }
}

fn md5_of(bytes: &[u8]) -> Hash {
    Md5::digest(bytes).into()
}

fn touch(path: &Path) {
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(SystemTime::now()));
}

pub(crate) struct RuleProvider {
    pub def: RuleProviderDef,
    pub handle: Arc<RuleSetHandle>,
    path: Option<PathBuf>,
    updated_at: Mutex<Option<SystemTime>>,
    hash: Mutex<Option<Hash>>,
    updating: AtomicBool,
    gate: tokio::sync::Mutex<()>,
}

pub(crate) fn behavior_of(behavior: RuleBehavior) -> Behavior {
    match behavior {
        RuleBehavior::Domain => Behavior::Domain,
        RuleBehavior::IpCidr => Behavior::IpCidr,
        RuleBehavior::Classical => Behavior::Classical,
    }
}

pub(crate) fn format_of(format: RuleFormat) -> Format {
    match format {
        RuleFormat::Yaml => Format::Yaml,
        RuleFormat::Text => Format::Text,
        RuleFormat::Mrs => Format::Mrs,
    }
}

impl RuleProvider {
    pub fn vehicle(&self) -> &'static str {
        match self.def.source {
            RuleSource::File { .. } => "File",
            RuleSource::Http(_) => "HTTP",
            RuleSource::Inline { .. } => "Inline",
        }
    }

    pub fn path_text(&self) -> String {
        self.path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    pub fn updated_at(&self) -> Option<SystemTime> {
        *lock(&self.updated_at)
    }

    /// An inline provider is reachable by name but not listed, as in `toExternalProvider`.
    pub fn is_listed(&self) -> bool {
        !matches!(self.def.source, RuleSource::Inline { .. })
    }

    fn remember(&self, hash: Option<Hash>, at: SystemTime) {
        if let Some(hash) = hash {
            *lock(&self.hash) = Some(hash);
        }
        {
            let mut updated = lock(&self.updated_at);
            *updated = Some(at);
        }
    }

    fn holds(&self, hash: Hash) -> bool {
        *lock(&self.hash) == Some(hash)
    }

    fn since_update(&self) -> Duration {
        self.updated_at()
            .and_then(|at| at.elapsed().ok())
            .unwrap_or(Duration::ZERO)
    }
}

/// The rule providers of one config. Their sets live in `RuleSetHandle`s the
/// route program already holds, so an update needs no recompile.
pub(crate) struct RuleProviders {
    pub list: Vec<Arc<RuleProvider>>,
    env: Arc<CompileEnv>,
    geo: Arc<GeoUpdater>,
    home: Arc<HomeDir>,
    fetcher: Arc<dyn Fetcher>,
    events: Arc<dyn EventSink>,
    route: Arc<RouteCounters>,
}

/// Rounds of fetching geo files and parsing again; each round can only add the files a rule-set needs.
const GEO_REPARSES: usize = 2;

impl RuleProviders {
    pub fn new(
        defs: &[RuleProviderDef],
        store: &Arc<RuleSetStore>,
        geo: &Arc<GeoUpdater>,
        home: Arc<HomeDir>,
        fetcher: Arc<dyn Fetcher>,
        events: Arc<dyn EventSink>,
        route: Arc<RouteCounters>,
    ) -> Result<Self, RuleLoadError> {
        let mut list = Vec::with_capacity(defs.len());
        for def in defs {
            let handle = store.declare(&def.name, behavior_of(def.behavior));
            let confine = |path: &str| home.confine(path).map_err(RuleLoadError::path(def, path));
            let path = match &def.source {
                RuleSource::File { path } => Some(confine(path)?),
                RuleSource::Http(http) => {
                    let relative = if http.path.is_empty() {
                        format!("rules/{:x}", Md5::digest(http.url.as_bytes()))
                    } else {
                        http.path.clone()
                    };
                    Some(confine(&relative)?)
                }
                RuleSource::Inline { .. } => None,
            };
            list.push(Arc::new(RuleProvider {
                def: def.clone(),
                handle,
                path,
                updated_at: Mutex::new(None),
                hash: Mutex::new(None),
                updating: AtomicBool::new(false),
                gate: tokio::sync::Mutex::new(()),
            }));
        }
        Ok(RuleProviders {
            list,
            env: Arc::new(CompileEnv::new(geo.store.clone(), store.clone())),
            geo: geo.clone(),
            home,
            fetcher,
            events,
            route,
        })
    }

    pub fn get(&self, name: &str) -> Option<&Arc<RuleProvider>> {
        self.list.iter().find(|provider| provider.def.name == name)
    }

    /// Downloads the geo files that classical entries needed and did not find, as mihomo does while
    /// parsing them. True when every file arrived, so parsing again can keep those entries.
    async fn fetch_geo_faults(&self, faults: &[GeoFault]) -> bool {
        if faults.is_empty() {
            return false;
        }
        for fault in faults {
            let fetched = match *fault {
                GeoFault::Missing(file) => self.geo.fetch_missing(file, &*self.fetcher).await,
                GeoFault::Invalid(file) => self.geo.replace_invalid(file, &*self.fetcher).await,
            };
            if let Err(err) = fetched {
                tracing::warn!("[Provider] {err}");
                return false;
            }
        }
        true
    }

    async fn parse_entries(&self, provider: &RuleProvider, entries: &[String]) -> ParsedRuleSet {
        let behavior = behavior_of(provider.def.behavior);
        let mut rounds = 0;
        loop {
            let parsed = RuleSet::from_entries(behavior, entries, &self.env);
            if rounds < GEO_REPARSES && self.fetch_geo_faults(&parsed.geo_faults).await {
                rounds += 1;
                continue;
            }
            return parsed;
        }
    }

    /// Hands the bytes back so the caller can write what it just parsed.
    async fn parse(
        &self,
        provider: &RuleProvider,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>, RuleLoadError> {
        let behavior = behavior_of(provider.def.behavior);
        let format = format_of(provider.def.format);
        let mut bytes = bytes;
        let mut rounds = 0;
        let parsed = loop {
            let env = self.env.clone();
            let (back, parsed) = tokio::task::spawn_blocking(move || {
                let parsed = RuleSet::parse(behavior, format, &bytes, &env);
                (bytes, parsed)
            })
            .await?;
            bytes = back;
            let parsed = parsed?;
            if rounds < GEO_REPARSES && self.fetch_geo_faults(&parsed.geo_faults).await {
                rounds += 1;
                continue;
            }
            break parsed;
        };
        for warning in &parsed.warnings {
            tracing::warn!("[Provider] {}: {warning}", provider.def.name);
        }
        provider.handle.store(parsed.set);
        Ok(bytes)
    }

    /// mihomo's `Fetcher.loadBuf`.
    async fn load_buf(
        &self,
        provider: &RuleProvider,
        bytes: Vec<u8>,
        update_file: bool,
    ) -> Result<Refresh, RuleLoadError> {
        let _gate = provider.gate.lock().await;
        let hash = md5_of(&bytes);
        if provider.holds(hash) {
            if let (true, Some(path)) = (update_file, provider.path.clone()) {
                let _ = tokio::task::spawn_blocking(move || touch(&path)).await;
            }
            provider.remember(None, SystemTime::now());
            return Ok(Refresh::Unchanged);
        }
        if bytes.is_empty() {
            return Ok(Refresh::Updated);
        }
        let bytes = self.parse(provider, bytes).await?;
        if let (true, Some(path)) = (update_file, provider.path.clone()) {
            let home = self.home.clone();
            tokio::task::spawn_blocking(move || home.write_atomic(&path, &bytes))
                .await?
                .map_err(RuleLoadError::Write)?;
        }
        provider.remember(Some(hash), SystemTime::now());
        self.route.moved();
        Ok(Refresh::Updated)
    }

    /// True means what is on disk is older than the update interval.
    async fn initial(&self, provider: &RuleProvider) -> Result<bool, RuleLoadError> {
        if let RuleSource::Inline { payload } = &provider.def.source {
            let parsed = self.parse_entries(provider, payload).await;
            for warning in &parsed.warnings {
                tracing::warn!("[Provider] {}: {warning}", provider.def.name);
            }
            provider.handle.store(parsed.set);
            provider.remember(None, SystemTime::now());
            return Ok(false);
        }
        if !provider.def.fallback.is_empty() {
            let parsed = self.parse_entries(provider, &provider.def.fallback).await;
            for warning in &parsed.warnings {
                tracing::warn!("[Provider] {}: {warning}", provider.def.name);
            }
            provider.handle.store(parsed.set);
        }
        if let Some(path) = &provider.path
            && let Ok(bytes) = tokio::fs::read(path).await
        {
            let modified = tokio::fs::metadata(path)
                .await
                .and_then(|meta| meta.modified())
                .ok();
            let loaded = self.load_buf(provider, bytes, false).await;
            if let Some(at) = modified {
                provider.remember(None, at);
            }
            match loaded {
                Ok(_) => {
                    let interval = Duration::from_secs(u64::from(provider.def.interval));
                    return Ok(provider.since_update() > interval);
                }
                Err(err) => {
                    tracing::warn!("[Provider] {} read local file: {err}", provider.def.name);
                }
            }
        }
        Ok(self.pull(provider).await.map(|_| false)?)
    }

    /// mihomo's `Fetcher.Update`.
    pub async fn pull(&self, provider: &RuleProvider) -> Result<Refresh, ResourceError> {
        let (bytes, update_file) = match &provider.def.source {
            RuleSource::Inline { .. } => {
                provider.remember(None, SystemTime::now());
                return Ok(Refresh::Unchanged);
            }
            RuleSource::File { .. } => {
                let path = provider
                    .path
                    .as_ref()
                    .ok_or_else(|| ResourceError::Other("no path".to_string()))?;
                let bytes = tokio::fs::read(path)
                    .await
                    .map_err(|err| ResourceError::Other(err.to_string()))?;
                (bytes, false)
            }
            RuleSource::Http(http) => {
                let headers = http
                    .header
                    .iter()
                    .flat_map(|(name, values)| {
                        values
                            .iter()
                            .map(move |value| (name.clone(), value.clone()))
                    })
                    .collect();
                let bytes = download(
                    &*self.fetcher,
                    FetchRequest {
                        url: http.url.clone(),
                        headers,
                        via_proxy: Some(http.proxy.clone()).filter(|proxy| !proxy.is_empty()),
                        size_limit: u64::try_from(http.size_limit)
                            .ok()
                            .filter(|limit| *limit > 0),
                        timeout: PROVIDER_TIMEOUT,
                    },
                )
                .await?;
                (bytes, true)
            }
        };
        self.load_buf(provider, bytes, update_file)
            .await
            .map_err(|err| ResourceError::Load(Box::new(err)))
    }

    pub async fn side_load(
        &self,
        provider: &RuleProvider,
        bytes: Vec<u8>,
    ) -> Result<(), RuleLoadError> {
        self.reported(provider, self.load_buf(provider, bytes, true))
            .await
            .map(|_| ())
    }

    fn report(&self, provider: &RuleProvider, phase: ResourcePhase) {
        if self.events.enabled() {
            self.events.publish(CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::RuleProvider,
                name: Arc::from(provider.def.name.as_str()),
                phase,
            }));
        }
    }

    pub async fn reported<E: std::fmt::Display>(
        &self,
        provider: &RuleProvider,
        work: impl Future<Output = Result<Refresh, E>>,
    ) -> Result<Refresh, E> {
        let fetch = Fetch::start(|phase| self.report(provider, phase));
        let outcome = work.await;
        fetch.finish(ResourcePhase::of(&outcome));
        outcome
    }

    pub fn claim(&self, provider: &RuleProvider) -> bool {
        !provider.updating.swap(true, Ordering::AcqRel)
    }

    pub fn release(&self, provider: &RuleProvider) {
        provider.updating.store(false, Ordering::Release);
    }

    /// `answered` holds back every step of each first load, as
    /// `Outbounds::start_background` does for proxy providers.
    pub fn start(
        self: &Arc<Self>,
        stop: CancellationToken,
        answered: CancellationToken,
        tasks: &TaskTracker,
    ) {
        let loading = Arc::new(AtomicUsize::new(self.list.len()));
        for provider in self.list.clone() {
            let providers = self.clone();
            let stop = stop.clone();
            let answered = answered.clone();
            let loading = loading.clone();
            tasks.spawn(async move {
                tokio::select! {
                    () = stop.cancelled() => {}
                    () = providers.run(&provider, &answered, &loading) => {}
                }
            });
        }
    }

    async fn run(
        &self,
        provider: &RuleProvider,
        answered: &CancellationToken,
        loading: &AtomicUsize,
    ) {
        let report = |phase| self.report(provider, phase);
        let (fetch, initial) = {
            let load = self.initial(provider);
            tokio::pin!(load);
            tokio::select! {
                initial = &mut load => (None, initial),
                () = answered.cancelled() => (Some(Fetch::start(report)), load.await),
            }
        };
        let fetch = match fetch {
            Some(fetch) => fetch,
            None => {
                answered.cancelled().await;
                Fetch::start(report)
            }
        };
        let stale = match initial {
            Ok(stale) => {
                fetch.finish(ResourcePhase::Updated);
                stale
            }
            Err(err) => {
                tracing::error!("initial rule provider {} error: {err}", provider.def.name);
                fetch.finish(ResourcePhase::Failed(err.to_string()));
                if matches!(provider.def.source, RuleSource::Http(_)) && provider.def.interval > 0 {
                    self.retry_until_loaded(provider).await;
                }
                false
            }
        };
        // mihomo collects garbage once every provider it waits for has loaded.
        if loading.fetch_sub(1, Ordering::AcqRel) == 1 {
            tokio::task::spawn_blocking(concord_platform::release_free_memory);
        }
        if let (RuleSource::File { .. }, Some(path)) = (&provider.def.source, &provider.path) {
            let mut watch = concord_platform::FileWatch::new(path.clone());
            loop {
                watch.changed().await;
                self.pull_with_log(provider).await;
            }
        }
        if provider.def.interval == 0 || !matches!(provider.def.source, RuleSource::Http(_)) {
            return;
        }
        let interval = Duration::from_secs(u64::from(provider.def.interval));
        if stale {
            tracing::warn!(
                "[Provider] {} not updated for a long time, force refresh",
                provider.def.name
            );
            self.pull_with_log(provider).await;
        }
        sleep(interval.saturating_sub(provider.since_update())).await;
        loop {
            self.pull_with_log(provider).await;
            sleep(interval).await;
        }
    }

    async fn retry_until_loaded(&self, provider: &RuleProvider) {
        let interval = Duration::from_secs(u64::from(provider.def.interval));
        let mut failures = 0;
        loop {
            sleep(provider_backoff(failures, interval)).await;
            if self.pull_with_log(provider).await {
                return;
            }
            failures = failures.saturating_add(1);
        }
    }

    async fn pull_with_log(&self, provider: &RuleProvider) -> bool {
        if !self.claim(provider) {
            return false;
        }
        let pulled = self.reported(provider, self.pull(provider)).await;
        if let Err(err) = &pulled {
            tracing::warn!("[Provider] {} pull error: {err}", provider.def.name);
        }
        self.release(provider);
        pulled.is_ok()
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GeoUrls {
    pub mmdb: String,
    pub asn: String,
    pub geosite: String,
}

impl GeoUrls {
    pub fn from_config(config: &GeoConfig) -> Self {
        GeoUrls {
            mmdb: config.mmdb_url.clone(),
            asn: config.asn_url.clone(),
            geosite: config.geosite_url.clone(),
        }
    }

    pub fn url(&self, file: GeoFile) -> &str {
        match file {
            GeoFile::Mmdb => &self.mmdb,
            GeoFile::Asn => &self.asn,
            GeoFile::GeoSite => &self.geosite,
        }
    }

    pub fn set(&mut self, kind: &str, link: String) -> bool {
        let slot = match kind.to_ascii_uppercase().as_str() {
            "MMDB" => &mut self.mmdb,
            "ASN" => &mut self.asn,
            "GEOSITE" => &mut self.geosite,
            _ => return false,
        };
        if !link.is_empty() {
            *slot = link;
        }
        true
    }
}

pub(crate) fn geo_file_of(kind: &str) -> Option<GeoFile> {
    match kind {
        "MMDB" => Some(GeoFile::Mmdb),
        "ASN" => Some(GeoFile::Asn),
        "GEOSITE" => Some(GeoFile::GeoSite),
        _ => None,
    }
}

pub(crate) fn geo_kind_of(file: GeoFile) -> &'static str {
    match file {
        GeoFile::Mmdb => "MMDB",
        GeoFile::Asn => "ASN",
        GeoFile::GeoSite => "GEOSITE",
    }
}

fn geo_label(file: GeoFile) -> &'static str {
    match file {
        GeoFile::Mmdb => "MMDB",
        GeoFile::Asn => "ASN",
        GeoFile::GeoSite => "GeoSite",
    }
}

fn geo_file_name(file: GeoFile) -> &'static str {
    match file {
        GeoFile::Mmdb => "MMDB",
        GeoFile::Asn => "ASN",
        GeoFile::GeoSite => "GeoSite.dat",
    }
}

fn geo_request(url: &str) -> FetchRequest {
    FetchRequest {
        url: url.to_string(),
        headers: Vec::new(),
        via_proxy: None,
        size_limit: None,
        timeout: GEO_TIMEOUT,
    }
}

/// Geo data outlives configs, and one resource updates at a time.
pub(crate) struct GeoUpdater {
    pub store: Arc<GeoStore>,
    pub urls: ArcSwap<GeoUrls>,
    claims: Mutex<HashSet<&'static str>>,
    home: Mutex<Option<Arc<HomeDir>>>,
    events: Arc<dyn EventSink>,
    route: Arc<RouteCounters>,
    auto: Mutex<Option<(CancellationToken, u32)>>,
}

impl GeoUpdater {
    pub fn new(
        store: Arc<GeoStore>,
        events: Arc<dyn EventSink>,
        route: Arc<RouteCounters>,
    ) -> Arc<Self> {
        Arc::new(GeoUpdater {
            store,
            urls: ArcSwap::from_pointee(GeoUrls::default()),
            claims: Mutex::new(HashSet::new()),
            home: Mutex::new(None),
            events,
            route,
            auto: Mutex::new(None),
        })
    }

    pub fn set_home(&self, home: Arc<HomeDir>) {
        {
            let mut slot = lock(&self.home);
            *slot = Some(home);
        }
    }

    pub fn claim(&self, kind: &'static str) -> bool {
        lock(&self.claims).insert(kind)
    }

    fn release(&self, kind: &str) {
        {
            let mut claims = lock(&self.claims);
            claims.remove(kind);
        }
    }

    fn report(&self, file: GeoFile, phase: ResourcePhase) {
        if self.events.enabled() {
            self.events.publish(CoreEvent::Resource(ResourceUpdate {
                kind: ResourceKind::Geo,
                name: Arc::from(geo_kind_of(file)),
                phase,
            }));
        }
    }

    /// The first download of a file a config needs: no events, no comparison.
    async fn reported(
        &self,
        file: GeoFile,
        work: impl Future<Output = Result<(), GeoUpdateError>>,
    ) -> Result<(), GeoUpdateError> {
        let fetch = Fetch::start(|phase| self.report(file, phase));
        let outcome = work.await;
        fetch.finish(match &outcome {
            Ok(()) => ResourcePhase::Updated,
            Err(err) => ResourcePhase::Failed(err.to_string()),
        });
        outcome
    }

    pub async fn fetch_missing(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        self.reported(file, self.download_missing(file, fetcher))
            .await
    }

    async fn download_missing(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        let name = geo_file_name(file);
        tracing::info!("Can't find {name}, start download");
        let urls = self.urls.load_full();
        let bytes = download(fetcher, geo_request(urls.url(file)))
            .await
            .map_err(|source| GeoUpdateError::Download {
                what: name.to_string(),
                source,
            })?;
        self.write(file, &bytes)?;
        Ok(self.store.ensure(file)?)
    }

    /// Files the rules wait for instead of holding the apply, fetched once it has answered.
    pub fn fetch_deferred(
        self: &Arc<Self>,
        files: &[GeoFile],
        fetcher: Arc<dyn Fetcher>,
        stop: &CancellationToken,
        answered: &CancellationToken,
        tasks: &TaskTracker,
    ) {
        for &file in files {
            let updater = self.clone();
            let fetcher = fetcher.clone();
            let stop = stop.clone();
            let answered = answered.clone();
            tasks.spawn(async move {
                tokio::select! {
                    () = stop.cancelled() => {}
                    () = updater.fetch_until_loaded(file, &*fetcher, &answered) => {}
                }
            });
        }
    }

    async fn fetch_until_loaded(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
        answered: &CancellationToken,
    ) {
        answered.cancelled().await;
        let mut failures = 0;
        while self.store.ensure(file).is_err() {
            if let Err(err) = self.fetch_missing(file, fetcher).await {
                tracing::warn!("[GEO] {err}");
                sleep(provider_backoff(failures, GEO_RETRY_CAP)).await;
                failures = failures.saturating_add(1);
            }
        }
    }

    /// A file on disk that does not parse is replaced, as `geodata.InitGeoSite` does.
    pub async fn replace_invalid(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        self.reported(file, self.download_replacement(file, fetcher))
            .await
    }

    async fn download_replacement(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<(), GeoUpdateError> {
        let name = geo_file_name(file);
        tracing::warn!("{name} invalid, remove and download");
        let urls = self.urls.load_full();
        let bytes = download(fetcher, geo_request(urls.url(file)))
            .await
            .map_err(|source| GeoUpdateError::Download {
                what: name.to_string(),
                source,
            })?;
        self.write(file, &bytes)?;
        Ok(self.store.reload(file)?)
    }

    fn write(&self, file: GeoFile, bytes: &[u8]) -> Result<(), WriteError> {
        let home = lock(&self.home).clone().ok_or(WriteError::NotInitialized)?;
        Ok(home.write_atomic(self.store.path(file), bytes)?)
    }

    /// The caller holds the claim; this gives it back.
    pub async fn update(&self, file: GeoFile, fetcher: &dyn Fetcher) {
        let kind = geo_kind_of(file);
        let fetch = Fetch::start(|phase| self.report(file, phase));
        let outcome = self.update_inner(file, fetcher).await;
        self.release(kind);
        match &outcome {
            Ok(Refresh::Updated) => self.route.moved(),
            Ok(Refresh::Unchanged) => {}
            Err(err) => tracing::error!("updateGeoData({kind}) error: {err}"),
        }
        fetch.finish(ResourcePhase::of(&outcome));
    }

    async fn update_inner(
        &self,
        file: GeoFile,
        fetcher: &dyn Fetcher,
    ) -> Result<Refresh, GeoUpdateError> {
        let label = geo_label(file);
        let path = self.store.path(file);
        let urls = self.urls.load_full();
        let bytes = download(fetcher, geo_request(urls.url(file)))
            .await
            .map_err(|source| GeoUpdateError::Download {
                what: format!("{label} database file"),
                source,
            })?;
        let same = tokio::fs::read(&path).await.is_ok_and(|old| old == bytes);
        if same {
            let _ = tokio::task::spawn_blocking(move || touch(&path)).await;
            return Ok(Refresh::Unchanged);
        }
        if bytes.is_empty() {
            return Err(GeoUpdateError::NoData { label });
        }
        let bytes =
            tokio::task::spawn_blocking(move || GeoStore::validate(file, &bytes).map(|()| bytes))
                .await?
                .map_err(|message| GeoUpdateError::Invalid { label, message })?;
        self.write(file, &bytes)
            .map_err(|source| GeoUpdateError::Save { label, source })?;
        self.store.reload(file)?;
        Ok(Refresh::Updated)
    }

    pub fn sync_auto(self: &Arc<Self>, enabled: bool, hours: u32, fetcher: Arc<dyn Fetcher>) {
        let mut auto = lock(&self.auto);
        if enabled && auto.as_ref().is_some_and(|(_, current)| *current == hours) {
            return;
        }
        if let Some((stop, _)) = auto.take() {
            stop.cancel();
        }
        if !enabled {
            return;
        }
        if hours == 0 {
            tracing::info!("[GEO] Invalid update interval: {hours}");
            return;
        }
        let stop = CancellationToken::new();
        *auto = Some((stop.clone(), hours));
        let updater = self.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = stop.cancelled() => {}
                () = updater.auto_loop(hours, fetcher) => {}
            }
        });
    }

    fn last_update(&self) -> Option<SystemTime> {
        [GeoFile::Mmdb, GeoFile::Asn, GeoFile::GeoSite]
            .into_iter()
            .find_map(|file| {
                std::fs::metadata(self.store.path(file))
                    .and_then(|meta| meta.modified())
                    .ok()
            })
    }

    async fn update_all(&self, fetcher: &dyn Fetcher) {
        tracing::info!("[GEO] Updating GEO database");
        for file in [GeoFile::Mmdb, GeoFile::Asn, GeoFile::GeoSite] {
            if self.store.in_use(file) && self.claim(geo_kind_of(file)) {
                self.update(file, fetcher).await;
            }
        }
    }

    /// mihomo gives up for good when the first update fails; this keeps its schedule.
    async fn auto_loop(&self, hours: u32, fetcher: Arc<dyn Fetcher>) {
        let interval = Duration::from_secs(u64::from(hours) * 3600);
        let Some(last) = self.last_update() else {
            tracing::info!("[GEO] Get GEO database update time error");
            return;
        };
        if last.elapsed().is_ok_and(|age| age > interval) {
            tracing::info!("[GEO] Database has not been updated for {hours}h, update now");
            self.update_all(&*fetcher).await;
        }
        loop {
            sleep(interval).await;
            self.update_all(&*fetcher).await;
        }
    }

    pub fn stop_auto(&self) {
        if let Some((stop, _)) = lock(&self.auto).take() {
            stop.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use concord_common::NullSink;

    use super::*;

    #[test]
    fn a_panicked_holder_leaves_the_home_and_the_claims_usable() {
        let dir = tempfile::tempdir().unwrap();
        let sink: Arc<dyn EventSink> = Arc::new(NullSink);
        let geo = GeoUpdater::new(
            Arc::new(GeoStore::new(dir.path())),
            sink.clone(),
            Arc::new(RouteCounters::new(sink)),
        );
        concord_test_support::poison(&geo.home);
        geo.set_home(Arc::new(HomeDir::new(dir.path())));
        geo.write(GeoFile::Mmdb, b"written").unwrap();
        assert_eq!(
            std::fs::read(geo.store.path(GeoFile::Mmdb)).unwrap(),
            b"written"
        );

        concord_test_support::poison(&geo.claims);
        assert!(geo.claim("geoip"));
        assert!(!geo.claim("geoip"));
        geo.release("geoip");
        assert!(geo.claim("geoip"));
    }
}
