use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use concord_common::sync::lock;
use concord_common::{CoreOptions, Origin};
use concord_engine::{
    ControllerCors, Engine, Failure, SetupRequest, StatusRanges, TunPatch as EngineTunPatch,
    UpdateRequest, ops,
};
use concord_proto::types::*;
use concord_proto::{ApiError, ErrorData};
use serde_json::{Map, Value};
use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::bus::EventBus;
use crate::convert::{self, Blame, api_error};
use crate::service::{ControlService, ServiceInfo};
use crate::stream::Subscription;
use crate::watch as streams;

#[cfg(unix)]
use crate::fds::AdoptedFds;

/// What the process that embeds the core knows and the core cannot find out.
#[derive(Clone, Debug, Default)]
pub struct ControlOptions {
    pub privileged: bool,
    /// What the host lets the core do, such as `tun.inherited`.
    pub capabilities: Vec<String>,
    pub build: String,
    /// The core runs on its own, so the profile's `external-controller` and
    /// `secret` count; otherwise only `config.patch` sets them.
    pub profile_controller: bool,
}

/// Where the external controller listens; an empty address opens nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerSettings {
    pub address: String,
    pub secret: String,
    pub cors: ControllerCors,
}

pub struct Control {
    engine: Arc<Engine>,
    bus: Arc<EventBus>,
    options: ControlOptions,
    status: watch::Sender<EngineStatus>,
    configured: AtomicBool,
    failed: Mutex<Option<String>>,
    controller: watch::Sender<ControllerSettings>,
    profile_source: Mutex<Option<PathBuf>>,
    /// One reload at a time, as they share the staged file.
    reloading: AsyncMutex<()>,
    #[cfg(unix)]
    fds: AdoptedFds,
}

fn empty_update() -> UpdateRequest {
    UpdateRequest {
        tun: None,
        allow_lan: None,
        bind_address: None,
        lan_allowed_ips: None,
        lan_disallowed_ips: None,
        mixed_port: None,
        find_process_mode: None,
        mode: None,
        log_level: None,
        ipv6: None,
        tcp_concurrent: None,
        unified_delay: None,
        authentication: None,
        geo_auto_update: None,
        geo_update_interval: None,
        geox_url: BTreeMap::new(),
        options: None,
    }
}

fn core_options(options: Options) -> CoreOptions {
    CoreOptions {
        test_url: options.test_url,
        skip_cert_verify: options.skip_cert_verify,
        delay_test_timeout: options.delay_test_timeout,
        mitm_capture: options.mitm_capture,
    }
}

fn mappings(values: Vec<Value>, field: &str) -> Result<Vec<Map<String, Value>>, ApiError> {
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            convert::value_to_object(value).ok_or_else(|| {
                ApiError::invalid_field(format!("{field}[{index}]"), "a proxy must be a mapping")
            })
        })
        .collect()
}

fn issues(found: Vec<concord_engine::ValidationIssue>) -> IssueList {
    IssueList {
        issues: found
            .into_iter()
            .map(|issue| IndexedIssue {
                index: u32::try_from(issue.index).unwrap_or(u32::MAX),
                message: issue.message,
            })
            .collect(),
    }
}

/// The working profile an apply without a `profile` reads.
const CONFIG_FILE: &str = "config.yaml";
const STAGED_FILE: &str = "config.reload.yaml";

/// What `reload_profile_as` reads.
pub enum Reload {
    Text(String),
    Path(String),
    /// The file the core was started with, or the working profile.
    Started,
}

/// Whether `expected` of a delay test reads as status ranges.
pub fn valid_status_ranges(text: &str) -> bool {
    StatusRanges::parse(text).is_some()
}

fn expected_statuses(text: Option<&str>) -> Result<StatusRanges, ApiError> {
    StatusRanges::parse(text.unwrap_or_default())
        .ok_or_else(|| ApiError::invalid_field("expected", "invalid status ranges"))
}

fn data_error(failure: Failure) -> ApiError {
    api_error(failure, Blame::Data)
}

fn core_error(failure: Failure) -> ApiError {
    api_error(failure, Blame::Core)
}

impl Control {
    /// `engine` must have been built with `bus` as its sink.
    pub fn new(engine: Arc<Engine>, bus: Arc<EventBus>, options: ControlOptions) -> Arc<Self> {
        bus.attach(&engine);
        engine.set_profile_controller(options.profile_controller);
        let (status, _) = watch::channel(EngineStatus {
            state: EngineState::Created,
            kind: None,
            faults: Vec::new(),
        });
        Arc::new(Control {
            engine,
            bus,
            options,
            status,
            configured: AtomicBool::new(false),
            failed: Mutex::new(None),
            controller: watch::Sender::new(ControllerSettings::default()),
            profile_source: Mutex::new(None),
            reloading: AsyncMutex::new(()),
            #[cfg(unix)]
            fds: AdoptedFds::default(),
        })
    }

    pub fn external_controller(&self) -> watch::Receiver<ControllerSettings> {
        self.controller.subscribe()
    }

    /// A host owns the profile, the selections and TUN; a dashboard may change
    /// what it can sync back, and the host learns of it from `events.watch`.
    pub fn host_owned(&self) -> bool {
        !self.options.profile_controller
    }

    fn set_external_controller(&self, next: ControllerSettings) {
        self.controller.send_if_modified(|current| {
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }

    /// Takes the controller from the profile in force. A core running on its own
    /// calls this when it loads its profile, not on a dashboard's reload, as
    /// mihomo recreates the controller only when it parses its config.
    pub async fn adopt_profile_controller(&self) {
        if self.host_owned() {
            return;
        }
        let (address, secret, cors) = self.engine.profile_controller().await;
        self.set_external_controller(ControllerSettings {
            address,
            secret,
            cors,
        });
    }

    /// The file a core running on its own was started with, which a reload
    /// that names no profile reads again, as mihomo's does.
    /// The picks in force, which a reload of the profile carries over as
    /// mihomo's cache file does.
    pub fn selections(&self) -> BTreeMap<String, String> {
        self.engine.selections()
    }

    pub fn set_profile_source(&self, path: PathBuf) {
        {
            let mut source = lock(&self.profile_source);
            *source = Some(path);
        }
    }

    /// mihomo's `PUT /configs` for a core running on its own: the profile
    /// replaces the working `config.yaml` whole, after it validates, and is
    /// applied as `concord run` applies it. A path must be absolute and inside
    /// the home directory, as mihomo's safe paths are by default.
    pub async fn reload_profile_as(
        &self,
        origin: Origin,
        reload: Reload,
    ) -> Result<ConfigApplyResult, ApiError> {
        self.require_initialized()?;
        if self.host_owned() {
            return Err(ApiError::unsupported_capability(
                "profile_reload",
                "the host owns the profile",
            ));
        }
        let _reloading = self.reloading.lock().await;
        let home = self
            .engine
            .home()
            .ok_or_else(|| ApiError::internal("not initialized"))?;
        let started = lock(&self.profile_source).clone();
        let working = home.join(CONFIG_FILE);
        let staged = home.join(STAGED_FILE);
        let (read_home, write_to) = (home.clone(), staged.clone());
        let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, ApiError> {
            let bytes = match reload {
                Reload::Text(text) => text.into_bytes(),
                Reload::Path(path) => {
                    if !Path::new(&path).is_absolute() {
                        return Err(ApiError::invalid_field(
                            "path",
                            "path is not a absolute path",
                        ));
                    }
                    read_home
                        .read(&path)
                        .map_err(|err| ApiError::invalid_field("path", format!("{path}: {err}")))?
                }
                Reload::Started => std::fs::read(started.as_deref().unwrap_or(&working))
                    .map_err(|err| ApiError::internal(err.to_string()))?,
            };
            read_home
                .write_atomic(&write_to, &bytes)
                .map_err(|err| ApiError::internal(err.to_string()))?;
            Ok(bytes)
        })
        .await
        .map_err(|err| ApiError::internal(err.to_string()))??;
        let validated = self
            .config_validate(ConfigValidateParams {
                profile: ProfileRef {
                    path: staged.to_string_lossy().into_owned(),
                },
            })
            .await;
        let _ = std::fs::remove_file(&staged);
        if let Some(issue) = validated?.issues.into_iter().next() {
            return Err(ApiError::invalid_field("profile", issue.message));
        }
        home.write_atomic(home.join(CONFIG_FILE), &bytes)
            .map_err(|err| ApiError::internal(err.to_string()))?;
        let params = ConfigApplyParams {
            selection: self.selections(),
            ..ConfigApplyParams::default()
        };
        self.config_apply_as(origin, params).await
    }

    pub async fn config_apply_as(
        &self,
        origin: Origin,
        params: ConfigApplyParams,
    ) -> Result<ConfigApplyResult, ApiError> {
        self.require_initialized()?;
        let _answering = self.engine.hold_first_loads();
        let base = match (params.profile, params.overlay) {
            (Some(profile), overlay) => Some((
                profile.path,
                overlay
                    .map(|overlay| overlay.to_string())
                    .unwrap_or_default(),
            )),
            (None, Some(_)) => {
                return Err(ApiError::invalid_field(
                    "overlay",
                    "an overlay needs the profile it is applied to",
                ));
            }
            (None, None) => None,
        };
        let applied = self
            .engine
            .setup_as(
                origin,
                SetupRequest {
                    base,
                    selected: params.selection,
                    options: core_options(params.options),
                },
            )
            .await;
        if let Some(level) = self.engine.log_level().await {
            self.bus.gate().set_level(level);
        }
        match applied {
            Ok(()) => {
                self.configured.store(true, Ordering::SeqCst);
                self.clear_failure();
                self.refresh();
                Ok(ConfigApplyResult {
                    warnings: self
                        .engine
                        .warnings()
                        .into_iter()
                        .map(convert::warning)
                        .collect(),
                })
            }
            Err(failure) => {
                let error = core_error(failure);
                if matches!(error.data, ErrorData::Rejected { .. }) {
                    self.configured.store(true, Ordering::SeqCst);
                    self.clear_failure();
                    self.refresh();
                } else {
                    self.fail(&error);
                }
                Err(error)
            }
        }
    }

    pub async fn config_patch_as(
        &self,
        origin: Origin,
        params: ConfigPatchParams,
    ) -> Result<ChangeSeq, ApiError> {
        self.require_configured()?;
        if let Some(level) = params.log_level {
            self.bus.gate().set_level(convert::engine_level(level));
        }
        let request = UpdateRequest {
            tun: params.tun.map(|tun| EngineTunPatch {
                enable: tun.enable,
                device: tun.device,
                stack: tun.stack,
                auto_route: tun.auto_route,
            }),
            allow_lan: params.allow_lan,
            bind_address: params.bind_address,
            lan_allowed_ips: params.lan_allowed_ips,
            lan_disallowed_ips: params.lan_disallowed_ips,
            mixed_port: params.mixed_port,
            find_process_mode: params.find_process_mode,
            mode: params.mode,
            log_level: params
                .log_level
                .map(|level| convert::engine_level(level).as_str().to_string()),
            ipv6: params.ipv6,
            tcp_concurrent: params.tcp_concurrent,
            unified_delay: params.unified_delay,
            authentication: params.authentication,
            geo_auto_update: params.geo_auto_update,
            geo_update_interval: params.geo_update_interval,
            geox_url: params.geox_url,
            options: params.options.map(core_options),
        };
        let updated = self
            .engine
            .update_as(origin, request)
            .await
            .map_err(core_error);
        self.refresh();
        updated.map(|seq| ChangeSeq { seq })
    }

    pub async fn proxy_select_as(
        &self,
        origin: Origin,
        params: ProxySelectParams,
    ) -> Result<ProxySelectResult, ApiError> {
        let outcome = self
            .engine
            .select_as(origin, &params.group, &params.proxy)
            .await;
        match outcome.message.as_str() {
            "" => Ok(ProxySelectResult {
                changed: outcome.changed,
                seq: outcome.seq,
            }),
            "Not found group" => Err(ApiError::not_found("group", params.group)),
            "proxy not exist" => Err(ApiError::not_found("proxy", params.proxy)),
            "Group is not selectable" => Err(ApiError::conflict(
                "not_selectable",
                format!("group {} is not selectable", params.group),
            )),
            other => Err(ApiError::conflict("select", other)),
        }
    }

    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }

    pub fn bus(&self) -> &Arc<EventBus> {
        &self.bus
    }

    #[cfg(unix)]
    pub fn adopted_fds(&self) -> &AdoptedFds {
        &self.fds
    }

    pub async fn shutdown(&self) {
        self.engine.shutdown().await;
        self.configured.store(false, Ordering::SeqCst);
        self.refresh();
    }

    async fn disable_tun(&self) -> Result<(), ApiError> {
        let mut request = empty_update();
        request.tun = Some(EngineTunPatch {
            enable: false,
            device: None,
            stack: None,
            auto_route: None,
        });
        self.engine.update(request).await.map_err(core_error)
    }

    fn state(&self) -> EngineStatus {
        let failed = lock(&self.failed).clone();
        let state = if failed.is_some() {
            EngineState::Failed
        } else if self.engine.is_running() {
            EngineState::Running
        } else if self.configured.load(Ordering::SeqCst) {
            EngineState::Configured
        } else if self.engine.is_initialized() {
            EngineState::Initialized
        } else {
            EngineState::Created
        };
        EngineStatus {
            state,
            kind: failed,
            faults: self
                .engine
                .faults()
                .into_iter()
                .map(convert::fault)
                .collect(),
        }
    }

    /// For hosts that change the engine behind the protocol's back, such as a VPN service.
    pub fn refresh_state(&self) {
        self.refresh();
    }

    fn refresh(&self) {
        let next = self.state();
        self.status.send_if_modified(|current| {
            if *current == next {
                return false;
            }
            *current = next;
            true
        });
    }

    fn fail(&self, error: &ApiError) {
        {
            let mut failed = lock(&self.failed);
            *failed = Some(error.data.kind().to_string());
        }
        self.refresh();
    }

    fn clear_failure(&self) {
        {
            let mut failed = lock(&self.failed);
            *failed = None;
        }
    }

    fn require_initialized(&self) -> Result<(), ApiError> {
        if self.engine.is_initialized() {
            Ok(())
        } else {
            Err(ApiError::conflict("created", "core.init has not run"))
        }
    }

    fn require_configured(&self) -> Result<(), ApiError> {
        self.require_initialized()?;
        if self.configured.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ApiError::conflict(
                "initialized",
                "config.apply has not run",
            ))
        }
    }

    fn output_error(err: &std::io::Error) -> ApiError {
        if err.kind() == std::io::ErrorKind::PermissionDenied {
            ApiError::invalid_field("output.file", err.to_string())
        } else {
            ApiError::internal(err.to_string())
        }
    }

    fn write_output(&self, file: &str, bytes: &[u8]) -> Result<u64, ApiError> {
        self.require_initialized()?;
        let home = self
            .engine
            .home()
            .ok_or_else(|| ApiError::conflict("created", "core.init has not run"))?;
        home.write_atomic(file, bytes)
            .map_err(|err| Self::output_error(&err))?;
        Ok(bytes.len() as u64)
    }

    fn text_result(&self, output: Output, text: String) -> Result<TextResult, ApiError> {
        match output {
            Output::Inline { .. } => Ok(TextResult {
                text: Some(text),
                file: None,
                size: None,
            }),
            Output::File { file } => {
                let size = self.write_output(&file, text.as_bytes())?;
                Ok(TextResult {
                    text: None,
                    file: Some(file),
                    size: Some(size),
                })
            }
        }
    }

    fn mitm_failure(failure: Failure) -> ApiError {
        api_error(failure, Blame::Core)
    }

    fn mitm_enabled(&self) -> Result<(), ApiError> {
        if self.engine.capabilities().features.mitm {
            Ok(())
        } else {
            Err(ApiError::unsupported_capability(
                "mitm",
                "this build has no MITM",
            ))
        }
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Engine) -> Result<T, Failure> + Send + 'static,
    ) -> Result<T, ApiError> {
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || work(&engine))
            .await
            .map_err(|err| ApiError::internal(err.to_string()))?
            .map_err(Self::mitm_failure)
    }
}

impl ControlService for Control {
    fn info(&self) -> ServiceInfo {
        let capabilities = self.engine.capabilities();
        ServiceInfo {
            server: ServerInfo {
                implementation: concord_common::CORE_NAME.to_string(),
                version: capabilities.version.to_string(),
                build: self.options.build.clone(),
            },
            platform: PlatformInfo {
                os: if self.engine.is_android() {
                    "android".to_string()
                } else {
                    std::env::consts::OS.to_string()
                },
                privileged: self.options.privileged,
                capabilities: self.options.capabilities.clone(),
            },
            features: Features {
                mitm: capabilities.features.mitm,
                ech: capabilities.features.ech,
                system_stack: capabilities.features.system_stack,
            },
            engine: self.state(),
            debug: cfg!(feature = "debug"),
        }
    }

    async fn core_init(&self, params: CoreInitParams) -> Result<Empty, ApiError> {
        if params.home.is_empty() {
            return Err(ApiError::invalid_field("home", "home must not be empty"));
        }
        let outcome = self
            .engine
            .init(&params.home, params.sdk_int.unwrap_or(0))
            .map_err(core_error);
        match outcome {
            Ok(()) => {
                self.clear_failure();
                self.refresh();
                Ok(Empty {})
            }
            Err(error) => {
                self.fail(&error);
                Err(error)
            }
        }
    }

    async fn core_release_memory(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.release_memory();
        Ok(Empty {})
    }

    async fn core_stats(&self, _params: Empty) -> Result<CoreStats, ApiError> {
        Ok(CoreStats {
            rss: self.engine.memory_stats().rss,
        })
    }

    async fn core_capabilities(&self, _params: Empty) -> Result<Capabilities, ApiError> {
        Ok(convert::capabilities(self.engine.capabilities()))
    }

    async fn core_set_pressure(&self, params: SetPressureParams) -> Result<Empty, ApiError> {
        self.engine.mitm().set_pressure(params.level);
        Ok(Empty {})
    }

    async fn core_last_warnings(&self, _params: Empty) -> Result<WarningList, ApiError> {
        Ok(WarningList {
            warnings: self
                .engine
                .warnings()
                .into_iter()
                .map(convert::warning)
                .collect(),
        })
    }

    #[cfg(feature = "debug")]
    async fn debug_crash(&self, _params: Empty) -> Result<Empty, ApiError> {
        eprintln!("[ERROR] debug.crash");
        std::process::abort()
    }

    async fn config_apply(&self, params: ConfigApplyParams) -> Result<ConfigApplyResult, ApiError> {
        self.config_apply_as(Origin::Host, params).await
    }

    async fn config_patch(&self, params: ConfigPatchParams) -> Result<ChangeSeq, ApiError> {
        let (address, secret) = (params.external_controller.clone(), params.secret.clone());
        let cors = params.external_controller_cors.clone();
        let patched = self.config_patch_as(Origin::Host, params).await?;
        if self.host_owned() && (address.is_some() || secret.is_some() || cors.is_some()) {
            let mut next = self.controller.borrow().clone();
            if let Some(address) = address {
                next.address = address;
            }
            if let Some(secret) = secret {
                next.secret = secret;
            }
            if let Some(cors) = cors {
                next.cors =
                    ControllerCors::or_defaults(cors.allow_origins, cors.allow_private_network);
            }
            self.set_external_controller(next);
        }
        Ok(patched)
    }

    async fn config_general(&self, _params: Empty) -> Result<GeneralState, ApiError> {
        self.require_configured()?;
        self.engine
            .general()
            .await
            .map(convert::general_state)
            .ok_or_else(|| ApiError::conflict("initialized", "config.apply has not run"))
    }

    async fn config_validate(
        &self,
        params: ConfigValidateParams,
    ) -> Result<ConfigValidateResult, ApiError> {
        let message = ops::validate_config(params.profile.path)
            .await
            .map_err(data_error)?;
        Ok(ConfigValidateResult {
            issues: message.into_iter().map(Issue::message).collect(),
        })
    }

    async fn config_decrypt(&self, params: ConfigDecryptParams) -> Result<TextResult, ApiError> {
        let text = ops::decrypt_config(params.profile.path, params.key)
            .await
            .map_err(data_error)?;
        self.text_result(params.output, text)
    }

    async fn config_read(&self, params: ConfigReadParams) -> Result<ConfigReadResult, ApiError> {
        let mut config = ops::read_config(params.profile.path)
            .await
            .map_err(data_error)?;
        if let Value::Object(map) = &mut config
            && let Some(rules) = map.remove("rule")
        {
            map.insert("rules".to_string(), rules);
        }
        match params.output {
            Output::Inline { .. } => Ok(ConfigReadResult {
                config: Some(config),
                file: None,
                size: None,
            }),
            Output::File { file } => {
                let bytes = serde_json::to_vec(&config)
                    .map_err(|err| ApiError::internal(err.to_string()))?;
                let size = self.write_output(&file, &bytes)?;
                Ok(ConfigReadResult {
                    config: None,
                    file: Some(file),
                    size: Some(size),
                })
            }
        }
    }

    async fn profile_inspect(&self, params: ProfileParams) -> Result<ProfileInspect, ApiError> {
        let value = ops::profile_base(params.profile.path)
            .await
            .map_err(data_error)?;
        serde_json::from_value(value).map_err(|err| ApiError::internal(err.to_string()))
    }

    async fn profile_outbounds(&self, params: ProfileParams) -> Result<ProfileOutbounds, ApiError> {
        let value = ops::profile_outbounds(params.profile.path)
            .await
            .map_err(data_error)?;
        serde_json::from_value(value).map_err(|err| ApiError::internal(err.to_string()))
    }

    async fn profile_build(&self, params: ProfileBuildParams) -> Result<TextResult, ApiError> {
        let merged = ops::merge_profile(params.profile.path, params.overlay.to_string())
            .await
            .map_err(data_error)?;
        self.text_result(params.output, merged)
    }

    async fn profile_clear_effect(&self, params: ClearEffectParams) -> Result<Empty, ApiError> {
        if params.profile_id <= 0 {
            return Err(ApiError::invalid_field("profileId", "must be positive"));
        }
        self.require_initialized()?;
        self.engine
            .clear_effect(params.profile_id)
            .map_err(core_error)?;
        Ok(Empty {})
    }

    async fn proxy_groups(&self, _params: Empty) -> Result<ProxyGroups, ApiError> {
        Ok(streams::proxy_groups(&self.engine))
    }

    async fn proxy_watch(
        &self,
        _params: ProxyWatchParams,
    ) -> Result<Subscription<ProxyGroups, ProxyDelta>, ApiError> {
        Ok(streams::proxies(self.engine.clone(), &self.bus))
    }

    async fn proxy_select(&self, params: ProxySelectParams) -> Result<ProxySelectResult, ApiError> {
        self.proxy_select_as(Origin::Host, params).await
    }

    async fn proxy_states(&self, params: ProxyStatesParams) -> Result<ProxyStates, ApiError> {
        Ok(ProxyStates {
            proxies: self
                .engine
                .node_states(params.names.as_deref())
                .into_iter()
                .map(convert::proxy_state)
                .collect(),
        })
    }

    async fn proxy_definition(
        &self,
        params: ProxyDefinitionParams,
    ) -> Result<ProxyDefinition, ApiError> {
        self.require_initialized()?;
        match self
            .engine
            .proxy_definition(params.name.clone())
            .await
            .map_err(data_error)?
        {
            Some(proxy) => Ok(ProxyDefinition { proxy }),
            None => Err(ApiError::not_found("proxy", params.name)),
        }
    }

    async fn delay_test(&self, params: DelayTestParams) -> Result<DelayResult, ApiError> {
        let expected = expected_statuses(params.expected.as_deref())?;
        let url = params.url.unwrap_or_default();
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        let result = self
            .engine
            .test_delay_expecting(&params.proxy, &url, &expected, timeout)
            .await;
        Ok(DelayResult {
            name: result.name,
            url: result.url,
            value: result.value,
        })
    }

    async fn delay_run(
        &self,
        params: DelayRunParams,
    ) -> Result<Subscription<Empty, DelayRunEvent>, ApiError> {
        let expected = expected_statuses(params.expected.as_deref())?;
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        Ok(Subscription::new(
            None,
            streams::delay_run(
                self.engine.clone(),
                params.proxies,
                params.url.unwrap_or_default(),
                expected,
                timeout,
                params.concurrency,
            ),
        ))
    }

    async fn validate_proxies(&self, params: ValidateProxiesParams) -> Result<IssueList, ApiError> {
        let proxies = mappings(params.proxies, "proxies")?;
        Ok(issues(ops::validate_proxies(&proxies)))
    }

    async fn validate_filters(&self, params: ValidateFiltersParams) -> Result<IssueList, ApiError> {
        Ok(issues(ops::validate_filters(&params.filters)))
    }

    async fn convert_subscription(
        &self,
        params: ConvertSubscriptionParams,
    ) -> Result<ProxyList, ApiError> {
        let proxies = ops::convert_proxies(params.profile.path)
            .await
            .map_err(data_error)?;
        Ok(ProxyList {
            proxies: proxies.into_iter().map(Value::Object).collect(),
        })
    }

    async fn convert_encode_links(&self, params: EncodeLinksParams) -> Result<LinkList, ApiError> {
        let proxies = mappings(params.proxies, "proxies")?;
        Ok(LinkList {
            links: ops::encode_share_links(&proxies),
        })
    }

    async fn convert_decode_links(
        &self,
        params: DecodeLinksParams,
    ) -> Result<DecodedLinks, ApiError> {
        Ok(DecodedLinks {
            results: ops::decode_share_links(&params.lines)
                .into_iter()
                .map(|line| line.into_iter().map(Value::Object).collect())
                .collect(),
        })
    }

    async fn provider_list(&self, _params: Empty) -> Result<ProviderList, ApiError> {
        Ok(ProviderList {
            providers: self
                .engine
                .providers()
                .list()
                .into_iter()
                .map(convert::provider_info)
                .collect(),
        })
    }

    async fn provider_get(&self, params: ProviderNameParams) -> Result<ProviderInfo, ApiError> {
        self.engine
            .providers()
            .get(&params.name)
            .map(convert::provider_info)
            .ok_or_else(|| ApiError::not_found("provider", params.name))
    }

    async fn provider_update(&self, params: ProviderNameParams) -> Result<Empty, ApiError> {
        self.engine
            .providers()
            .update(&params.name)
            .await
            .map_err(core_error)?;
        Ok(Empty {})
    }

    async fn provider_side_load(&self, params: ProviderSideLoadParams) -> Result<Empty, ApiError> {
        self.engine
            .providers()
            .side_load(&params.name, params.data)
            .await
            .map_err(core_error)?;
        Ok(Empty {})
    }

    async fn provider_health_check(&self, params: ProviderNameParams) -> Result<Empty, ApiError> {
        self.engine
            .providers()
            .health_check(&params.name)
            .await
            .map_err(core_error)?;
        Ok(Empty {})
    }

    async fn rule_list(&self, _params: Empty) -> Result<RuleList, ApiError> {
        Ok(RuleList {
            rules: self
                .engine
                .rules()
                .into_iter()
                .map(|rule| RuleEntry {
                    kind: rule.kind,
                    payload: rule.payload,
                    target: rule.target,
                })
                .collect(),
        })
    }

    async fn rule_set_dump(&self, params: RuleSetDumpParams) -> Result<TextResult, ApiError> {
        let text = ops::dump_rule_set(params.profile.path)
            .await
            .map_err(data_error)?;
        self.text_result(params.output, text)
    }

    async fn rule_set_compile(
        &self,
        params: RuleSetCompileParams,
    ) -> Result<RuleSetInfo, ApiError> {
        self.require_initialized()?;
        let info = self
            .engine
            .compile_rule_set(&params.name, &params.url.unwrap_or_default())
            .await
            .map_err(core_error)?;
        Ok(RuleSetInfo {
            behavior: info.behavior.to_string(),
            format: info.format.to_string(),
        })
    }

    async fn geo_update(&self, params: GeoUpdateParams) -> Result<Empty, ApiError> {
        self.engine.geo_update(&params.kind).map_err(|failure| {
            if failure
                .message
                .starts_with("geo update already in progress")
            {
                ApiError::conflict("updating", failure.message)
            } else {
                ApiError::invalid_field("type", failure.message)
            }
        })?;
        Ok(Empty {})
    }

    async fn traffic_watch(
        &self,
        params: TrafficWatchParams,
    ) -> Result<Subscription<Traffic, Traffic>, ApiError> {
        Ok(streams::traffic(
            self.engine.clone(),
            params.interval_ms,
            params.only_proxy,
        ))
    }

    async fn traffic_reset(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.traffic_reset();
        Ok(Empty {})
    }

    async fn connection_watch(
        &self,
        params: ConnectionWatchParams,
    ) -> Result<Subscription<ConnectionSnapshot, ConnectionDelta>, ApiError> {
        Ok(streams::connections(
            &self.engine,
            &self.bus,
            params.counters.unwrap_or(true),
        ))
    }

    async fn connection_close(&self, params: ConnectionCloseParams) -> Result<Empty, ApiError> {
        if params.all {
            self.engine.close_all_connections();
        } else if let Some(ids) = params.ids {
            for record in self.engine.connections() {
                if ids.contains(&record.seq) {
                    record.close();
                }
            }
        } else {
            return Err(ApiError::invalid_params("name ids or set all"));
        }
        Ok(Empty {})
    }

    async fn network_reset(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.reset_resolver_connections();
        Ok(Empty {})
    }

    async fn network_update(&self, params: NetworkUpdateParams) -> Result<Empty, ApiError> {
        if let Some(servers) = params.dns_servers {
            self.engine.update_system_dns(servers.join(","));
        }
        if params.interface_changed {
            self.engine.reset_network();
        } else {
            self.engine.network_changed();
        }
        Ok(Empty {})
    }

    async fn dns_clear_cache(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.clear_dns_cache();
        Ok(Empty {})
    }

    async fn dns_flush_fake_ip(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.flush_fake_ip();
        Ok(Empty {})
    }

    async fn dns_query(&self, params: DnsQueryParams) -> Result<DnsQueryResult, ApiError> {
        self.require_configured()?;
        let qtype = params.qtype.unwrap_or_else(|| "A".to_string());
        self.engine
            .dns_query(&params.name, &qtype)
            .await
            .map(convert::dns_query)
            .map_err(|failure| {
                if failure.code == "invalid_query" {
                    ApiError::invalid_field("qtype", failure.message)
                } else {
                    core_error(failure)
                }
            })
    }

    async fn log_watch(
        &self,
        params: LogWatchParams,
    ) -> Result<Subscription<Empty, LogEntry>, ApiError> {
        let events = streams::map_stream(
            self.bus.watch_log(params.level.unwrap_or_default()),
            |entry| entry,
        );
        Ok(Subscription::new(None, events))
    }

    async fn dns_watch(
        &self,
        _params: DnsWatchParams,
    ) -> Result<Subscription<Empty, DnsEntry>, ApiError> {
        let events = streams::map_stream(self.bus.watch_dns(), |entry| entry);
        Ok(Subscription::new(None, events))
    }

    async fn route_watch(
        &self,
        _params: RouteWatchParams,
    ) -> Result<Subscription<RouteStamp, RouteStamp>, ApiError> {
        let events = streams::map_stream(self.bus.watch_route(), |stamp| stamp);
        let stamp = convert::route_stamp(self.engine.route_view());
        Ok(Subscription::new(Some(stamp), events))
    }

    async fn events_watch(
        &self,
        params: EventsWatchParams,
    ) -> Result<Subscription<Empty, concord_proto::types::CoreEvent>, ApiError> {
        let events = streams::map_stream(
            self.bus.watch_events(params.delays, params.state),
            |event| event,
        );
        Ok(Subscription::new(None, events))
    }

    async fn engine_state(
        &self,
        _params: EngineStateParams,
    ) -> Result<Subscription<EngineStatus, EngineStatus>, ApiError> {
        Ok(streams::engine_state(self.status.subscribe()))
    }

    async fn engine_start(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        self.engine.start_listeners().await.map_err(core_error)?;
        self.refresh();
        Ok(Empty {})
    }

    async fn engine_stop(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        self.engine.stop_listeners().await.map_err(core_error)?;
        self.refresh();
        Ok(Empty {})
    }

    async fn tun_start(&self, params: TunStartParams) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        match params.source {
            TunSource::Device { name } => {
                if self.engine.is_android() {
                    return Err(ApiError::unsupported_capability(
                        "tun.device",
                        "this platform hands the core a descriptor instead",
                    ));
                }
                self.require_configured()?;
                let mut request = empty_update();
                request.tun = Some(EngineTunPatch {
                    enable: true,
                    device: name,
                    stack: params.stack,
                    auto_route: None,
                });
                self.engine.update(request).await.map_err(core_error)?;
                if let Some(fault) = self.engine.tun_fault() {
                    self.disable_tun().await?;
                    return Err(ApiError::unavailable("tun", fault.message));
                }
            }
            TunSource::Inherited { handle } => {
                #[cfg(unix)]
                {
                    let fd = self
                        .fds
                        .take(handle)
                        .ok_or_else(|| ApiError::not_found("handle", handle.to_string()))?;
                    let options = serde_json::json!({
                        "mtu": params.mtu.unwrap_or(0),
                        "congestion-controller": params.congestion_controller.unwrap_or_default(),
                    });
                    let started = self
                        .engine
                        .start_vpn_tun(
                            fd,
                            concord_engine::VpnTunRequest {
                                stack: params.stack.unwrap_or_default(),
                                address: params.address.join(","),
                                dns: params.dns.join(","),
                                options: options.to_string(),
                            },
                        )
                        .await;
                    if !started {
                        return Err(ApiError::unavailable("tun", "the TUN device did not start"));
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = handle;
                    return Err(ApiError::unsupported_capability(
                        "tun.inherited",
                        "this platform has no descriptors to inherit",
                    ));
                }
            }
        }
        self.refresh();
        Ok(Empty {})
    }

    async fn tun_stop(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.require_initialized()?;
        if self.engine.is_android() {
            #[cfg(unix)]
            self.engine.stop_vpn_tun().await;
        } else {
            self.require_configured()?;
            self.disable_tun().await?;
        }
        self.refresh();
        Ok(Empty {})
    }

    async fn route_check(&self, params: RouteCheckParams) -> Result<RouteCheckResult, ApiError> {
        let routes = params
            .routes
            .into_iter()
            .map(|route| {
                route
                    .into_iter()
                    .map(|hit| concord_engine::RouteHit {
                        host: hit.host,
                        proxy: hit.proxy,
                        exit: hit.exit,
                    })
                    .collect()
            })
            .collect();
        let (stamp, held) = self.engine.check_routes(routes).await;
        Ok(RouteCheckResult {
            epoch: stamp.epoch,
            version: stamp.version,
            held,
        })
    }

    async fn probe_outbound_ip(&self, params: OutboundIpParams) -> Result<OutboundIp, ApiError> {
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        let value = self
            .engine
            .probe_outbound_ip(params.proxy, params.urls, timeout)
            .await;
        serde_json::from_value(value).map_err(|err| ApiError::internal(err.to_string()))
    }

    async fn probe_services(&self, params: ServicesParams) -> Result<ServiceList, ApiError> {
        let timeout = params
            .timeout
            .map_or(0, |ms| i64::try_from(ms).unwrap_or(i64::MAX));
        let value = self
            .engine
            .probe_services(params.proxy, params.names, timeout)
            .await;
        Ok(ServiceList {
            items: serde_json::from_value(value)
                .map_err(|err| ApiError::internal(err.to_string()))?,
        })
    }

    async fn mitm_certificate(&self, _params: Empty) -> Result<MitmCertificate, ApiError> {
        self.mitm_enabled()?;
        let certificate = self.blocking(|engine| engine.mitm().certificate()).await?;
        Ok(MitmCertificate { certificate })
    }

    async fn mitm_generate_certificate(&self, _params: Empty) -> Result<MitmCertificate, ApiError> {
        self.mitm_enabled()?;
        let certificate = self
            .blocking(|engine| engine.mitm().generate_certificate())
            .await?;
        Ok(MitmCertificate {
            certificate: Some(certificate),
        })
    }

    async fn mitm_validate(
        &self,
        params: MitmValidateParams,
    ) -> Result<MitmValidateResult, ApiError> {
        self.mitm_enabled()?;
        let issues = self
            .blocking(move |engine| engine.mitm().validate(params.config))
            .await?;
        Ok(MitmValidateResult { issues })
    }

    async fn mitm_issue_certificate(&self, params: MitmIssueParams) -> Result<MitmPem, ApiError> {
        self.mitm_enabled()?;
        if params.host.is_empty() {
            return Err(ApiError::invalid_field("host", "host must not be empty"));
        }
        let pem = self
            .blocking(move |engine| engine.mitm().issue_certificate(&params.host))
            .await?;
        Ok(MitmPem { pem })
    }

    async fn mitm_run_script(&self, params: MitmScriptParams) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self
            .engine
            .mitm()
            .run_script(&params.name)
            .await
            .map_err(Self::mitm_failure)?;
        Ok(MitmResult { result })
    }

    async fn mitm_exchanges(&self, params: MitmExchangesParams) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let id = self
            .engine
            .connection_id(params.connection)
            .ok_or_else(|| ApiError::not_found("connection", params.connection.to_string()))?;
        let result = self
            .engine
            .mitm()
            .exchanges(&id)
            .map_err(Self::mitm_failure)?;
        Ok(MitmResult { result })
    }

    async fn mitm_exchange(&self, params: MitmExchangeParams) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self
            .engine
            .mitm()
            .exchange(params.id)
            .map_err(Self::mitm_failure)?;
        Ok(MitmResult { result })
    }

    async fn mitm_body(&self, params: MitmBodyParams) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self
            .engine
            .mitm()
            .body(params.id, params.response)
            .map_err(Self::mitm_failure)?;
        Ok(MitmResult { result })
    }
}
