use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::BoxStream;
use concord_common::sync::lock;
use sha2::{Digest, Sha256};

use crate::cron::CronSchedule;
use crate::heads::{HeadConditions, REQUEST_HEAD, RESPONSE_HEAD};
use crate::pattern::Pattern;
use crate::rules::read_resource;
use crate::text::{quote, split_fields};

pub const EVENT_NETWORK_CHANGED: &str = "network-changed";
pub const EVENT_ENGINE_STARTED: &str = "engine-started";
pub const EVENT_PROFILE_RELOADED: &str = "profile-reloaded";

pub(crate) const DEFAULT_SCRIPT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SCRIPT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TASK_TIMEOUT: Duration = Duration::from_secs(3600);
const LOON_NETWORK_CHANGED: &str = "network-changed";

const SCRIPT_TYPES: &[&str] = &[
    "http-request",
    "http-response",
    "cron",
    "event",
    "generic",
    "dns",
    "rule",
    LOON_NETWORK_CHANGED,
];

/// Header names in their canonical spelling, each with every value it carries.
pub type HeaderList = BTreeMap<String, Vec<String>>;

#[derive(Clone, Debug)]
pub struct ScriptRequest {
    pub id: String,
    pub url: String,
    pub method: String,
    pub header: HeaderList,
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ScriptResponse {
    pub status: u16,
    pub header: HeaderList,
    pub body: Option<Vec<u8>>,
}

/// What a script returned; whatever is empty stays as it was.
#[derive(Clone, Debug, Default)]
pub struct ScriptResult {
    pub url: String,
    pub status: u16,
    pub header: Option<HeaderList>,
    pub body: Option<Vec<u8>>,
    pub response: Option<ScriptResponse>,
    pub abort: bool,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ScriptEvent {
    pub name: String,
}

#[async_trait]
pub trait ScriptDial: Send + Sync {
    async fn dial(&self, host: &str, port: u16) -> io::Result<BoxStream>;
}

pub type ConsoleSink = Arc<dyn Fn(&str) + Send + Sync>;

pub struct ScriptInvocation {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub argument: Option<serde_json::Value>,
    pub binary_body: bool,
    pub request: Option<ScriptRequest>,
    pub response: Option<ScriptResponse>,
    /// Opens a connection the rules route like any other and that is never
    /// decrypted, so that a script's own requests do not run scripts.
    pub dial: Arc<dyn ScriptDial>,
    pub max_body_size: i64,
    pub memory_limit: u64,
    pub cronexp: String,
    pub event: Option<ScriptEvent>,
    pub trigger: String,
    pub console: Option<ConsoleSink>,
}

impl ScriptInvocation {
    pub fn base(dial: Arc<dyn ScriptDial>) -> ScriptInvocation {
        ScriptInvocation {
            name: String::new(),
            path: String::new(),
            kind: String::new(),
            argument: None,
            binary_body: false,
            request: None,
            response: None,
            dial,
            max_body_size: 0,
            memory_limit: 0,
            cronexp: String::new(),
            event: None,
            trigger: String::new(),
            console: None,
        }
    }
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("{0}")]
pub struct ScriptError(pub String);

pub trait ScriptRuntime: Send + Sync {
    fn compile(&self, name: &str, source: &[u8]) -> Result<Arc<dyn ScriptProgram>, String>;
}

/// Compiled once and run concurrently. The future must stop its work when it
/// is dropped, which is how a timeout ends a script.
#[async_trait]
pub trait ScriptProgram: Send + Sync {
    async fn run(&self, invocation: ScriptInvocation) -> Result<ScriptResult, ScriptError>;
}

/// The host's interpreter and the programs compiled so far. A resource is named
/// by a hash of its content by the app, but one written by hand may change
/// under the same name, so a program is cached by its source.
#[derive(Default)]
pub struct ScriptHost {
    runtime: Mutex<Option<Arc<dyn ScriptRuntime>>>,
    programs: Mutex<HashMap<[u8; 32], Arc<dyn ScriptProgram>>>,
}

impl ScriptHost {
    pub fn new(runtime: Option<Arc<dyn ScriptRuntime>>) -> ScriptHost {
        ScriptHost {
            runtime: Mutex::new(runtime),
            programs: Mutex::default(),
        }
    }

    pub fn set_runtime(&self, runtime: Option<Arc<dyn ScriptRuntime>>) {
        {
            let mut slot = lock(&self.runtime);
            *slot = runtime;
        }
        {
            let mut programs = lock(&self.programs);
            programs.clear();
        }
    }

    fn compile(
        &self,
        resources: &Path,
        name: &str,
    ) -> Result<(Arc<dyn ScriptProgram>, [u8; 32]), String> {
        let runtime = lock(&self.runtime)
            .clone()
            .ok_or("this build runs no scripts")?;
        let source = read_resource(resources, "script-path", name)?;
        let key: [u8; 32] = Sha256::digest(&source).into();
        let cached = lock(&self.programs).get(&key).cloned();
        if let Some(program) = cached {
            return Ok((program, key));
        }
        let program = runtime.compile(name, &source)?;
        {
            let mut programs = lock(&self.programs);
            programs.insert(key, program.clone());
        }
        Ok((program, key))
    }

    pub(crate) fn keep(&self, scripts: &[Arc<Script>]) {
        {
            let mut programs = lock(&self.programs);
            programs.retain(|key, _| scripts.iter().any(|script| &script.key == key));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptKind {
    HttpRequest,
    HttpResponse,
    Cron,
    Event,
    Generic,
}

impl ScriptKind {
    pub fn name(self) -> &'static str {
        match self {
            ScriptKind::HttpRequest => "http-request",
            ScriptKind::HttpResponse => "http-response",
            ScriptKind::Cron => "cron",
            ScriptKind::Event => "event",
            ScriptKind::Generic => "generic",
        }
    }
}

pub struct Script {
    pub name: String,
    pub path: String,
    pub kind: ScriptKind,
    pattern: Option<Pattern>,
    pub(crate) conditions: HeadConditions,
    pub requires_body: bool,
    pub binary_body: bool,
    pub max_size: i64,
    pub cronexp: String,
    pub(crate) cron: Option<CronSchedule>,
    pub event: String,
    pub timeout: Duration,
    pub argument: Option<serde_json::Value>,
    pub(crate) program: Arc<dyn ScriptProgram>,
    pub(crate) key: [u8; 32],
}

impl std::fmt::Debug for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Script")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Script {
    pub fn is_task(&self) -> bool {
        matches!(
            self.kind,
            ScriptKind::Cron | ScriptKind::Event | ScriptKind::Generic
        )
    }

    pub(crate) fn matches_http(&self, url: &str, response: bool) -> bool {
        let kind = if response {
            ScriptKind::HttpResponse
        } else {
            ScriptKind::HttpRequest
        };
        self.kind == kind && self.pattern.as_ref().is_some_and(|p| p.is_match(url))
    }

    pub(crate) fn body_limit(&self, max_body_size: i64) -> i64 {
        if self.max_size > 0 && self.max_size < max_body_size {
            self.max_size
        } else {
            max_body_size
        }
    }
}

type Params = HashMap<String, String>;

/// Reads Surge's line and Loon's legacy one; the script is a file in the resources directory.
pub(crate) fn parse_script(
    line: &str,
    resources: &Path,
    host: &ScriptHost,
) -> Result<Script, String> {
    let (name, kind, params) = split_script_line(line)?;
    let param = |key: &str| params.get(key).cloned().unwrap_or_default();
    let kind = match kind.as_str() {
        "http-request" => ScriptKind::HttpRequest,
        "http-response" => ScriptKind::HttpResponse,
        "cron" => ScriptKind::Cron,
        "event" => ScriptKind::Event,
        "generic" => ScriptKind::Generic,
        other if SCRIPT_TYPES.contains(&other) => {
            return Err(format!("{other} scripts are not supported"));
        }
        other => return Err(format!("unknown type {}", quote(other))),
    };
    let path = param("script-path");
    if path.is_empty() {
        return Err("script-path is missing".to_string());
    }
    let name = if name.is_empty() {
        Path::new(&path)
            .file_name()
            .map(|base| base.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone())
    } else {
        name
    };
    let mut script = ScriptDraft {
        name,
        path,
        kind,
        pattern: None,
        conditions: HeadConditions::default(),
        requires_body: false,
        binary_body: false,
        max_size: 0,
        cronexp: String::new(),
        cron: None,
        event: String::new(),
        timeout: DEFAULT_SCRIPT_TIMEOUT,
        argument: None,
    };
    match kind {
        ScriptKind::HttpRequest | ScriptKind::HttpResponse => {
            script.read_http(&params, kind == ScriptKind::HttpResponse)?
        }
        ScriptKind::Cron => {
            script.cronexp = param("cronexp");
            if script.cronexp.is_empty() {
                return Err("cronexp is missing".to_string());
            }
            script.cron = Some(CronSchedule::parse(&script.cronexp)?);
        }
        ScriptKind::Event => {
            script.event = param("event-name");
            match script.event.as_str() {
                EVENT_NETWORK_CHANGED | EVENT_ENGINE_STARTED | EVENT_PROFILE_RELOADED => {}
                "" => return Err("event-name is missing".to_string()),
                other => return Err(format!("the {other} event is not supported")),
            }
        }
        ScriptKind::Generic => {}
    }
    if let Some(text) = params.get("timeout") {
        let seconds = text
            .parse::<f64>()
            .ok()
            .filter(|seconds| *seconds > 0.0 && seconds.is_finite())
            .ok_or_else(|| format!("invalid timeout {}", quote(text)))?;
        let limit = if matches!(
            kind,
            ScriptKind::Cron | ScriptKind::Event | ScriptKind::Generic
        ) {
            MAX_TASK_TIMEOUT
        } else {
            MAX_SCRIPT_TIMEOUT
        };
        script.timeout = Duration::from_secs_f64(seconds.min(limit.as_secs_f64()));
    }
    if let Some(text) = params.get("argument-json") {
        let value = serde_json::from_str(text).map_err(|err| format!("argument-json: {err}"))?;
        script.argument = Some(value);
    } else if let Some(text) = params.get("argument") {
        script.argument = Some(serde_json::Value::String(text.clone()));
    }
    let (program, key) = host.compile(resources, &script.path)?;
    Ok(script.finish(program, key))
}

struct ScriptDraft {
    name: String,
    path: String,
    kind: ScriptKind,
    pattern: Option<Pattern>,
    conditions: HeadConditions,
    requires_body: bool,
    binary_body: bool,
    max_size: i64,
    cronexp: String,
    cron: Option<CronSchedule>,
    event: String,
    timeout: Duration,
    argument: Option<serde_json::Value>,
}

impl ScriptDraft {
    fn read_http(&mut self, params: &Params, response: bool) -> Result<(), String> {
        let pattern = params.get("pattern").cloned().unwrap_or_default();
        if pattern.is_empty() {
            return Err("pattern is missing".to_string());
        }
        for keyword in [REQUEST_HEAD, RESPONSE_HEAD] {
            if let Some(condition) = params.get(keyword) {
                self.conditions
                    .set(keyword, Some(condition), response)
                    .map_err(String::from)?;
            }
        }
        self.requires_body = script_bool(params, "requires-body")?;
        self.binary_body = script_bool(params, "binary-body-mode")?;
        if script_bool(params, "full-header-mode").unwrap_or(true) {
            return Err("full-header-mode is not supported".to_string());
        }
        if let Some(text) = params.get("max-size") {
            let size = text
                .parse::<i64>()
                .ok()
                .filter(|size| *size >= -1)
                .ok_or_else(|| format!("invalid max-size {}", quote(text)))?;
            if size > 0 {
                self.max_size = size;
            }
        }
        self.pattern = Some(Pattern::new(&pattern)?);
        Ok(())
    }

    fn finish(self, program: Arc<dyn ScriptProgram>, key: [u8; 32]) -> Script {
        Script {
            name: self.name,
            path: self.path,
            kind: self.kind,
            pattern: self.pattern,
            conditions: self.conditions,
            requires_body: self.requires_body,
            binary_body: self.binary_body,
            max_size: self.max_size,
            cronexp: self.cronexp,
            cron: self.cron,
            event: self.event,
            timeout: self.timeout,
            argument: self.argument,
            program,
            key,
        }
    }
}

/// A line with a type parameter is Surge's form, so that a name may start with
/// a type; any other is Loon's legacy one.
fn split_script_line(line: &str) -> Result<(String, String, Params), String> {
    let (name, rest) = match line.split_once('=') {
        Some((name, rest)) => (Some(name), Some(rest)),
        None => (None, None),
    };
    let parsed = rest.map(script_params);
    let typed =
        matches!(&parsed, Some(Ok(params)) if params.get("type").is_some_and(|t| !t.is_empty()));
    if !typed && let Some(at) = line.find([' ', '\t']).filter(|at| *at > 0) {
        let head = line.get(..at).unwrap_or_default().to_ascii_lowercase();
        if SCRIPT_TYPES.contains(&head.as_str()) {
            return split_legacy_script(&head, line.get(at..).unwrap_or_default());
        }
    }
    let (Some(name), Some(parsed)) = (name, parsed) else {
        return Err("expected name = parameters".to_string());
    };
    let params = parsed?;
    let mut kind = params
        .get("type")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind.is_empty() {
        kind = "generic".to_string();
    }
    Ok((name.trim().to_string(), kind, params))
}

/// Files the value after the type where Surge's form keeps it.
fn split_legacy_script(kind: &str, rest: &str) -> Result<(String, String, Params), String> {
    let fields = split_fields(rest)?;
    let mut value = String::new();
    let mut from = 0;
    if let Some(first) = fields.first() {
        let http = kind == "http-request" || kind == "http-response";
        if http || !first.text.contains('=') {
            value = first.text.clone();
            from = first.to;
        }
    }
    let mut params = script_params(rest.get(from..).unwrap_or_default())?;
    let mut name = params.get("tag").cloned().unwrap_or_default();
    let mut kind = kind.to_string();
    match kind.as_str() {
        "http-request" | "http-response" => {
            if value.is_empty() {
                return Err("expected a pattern".to_string());
            }
            params.insert("pattern".to_string(), value);
        }
        "cron" => {
            params.insert("cronexp".to_string(), value);
        }
        "event" => {
            params.insert("event-name".to_string(), value);
        }
        LOON_NETWORK_CHANGED => {
            kind = "event".to_string();
            params.insert("event-name".to_string(), EVENT_NETWORK_CHANGED.to_string());
        }
        _ => {
            if name.is_empty() {
                name = value;
            }
        }
    }
    Ok((name, kind, params))
}

/// Splits on the commas outside quotes, groups and character classes, so an
/// unquoted `{1,3}` or Loon's `argument=[{a},{b}]` stays one value.
fn script_params(text: &str) -> Result<Params, String> {
    let mut params = Params::new();
    let mut add = |item: &str| -> Result<(), String> {
        let item = item.trim();
        if item.is_empty() {
            return Ok(());
        }
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| format!("expected key=value, got {}", quote(item)))?;
        let mut value = value.trim().to_string();
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            value = value
                .get(1..value.len() - 1)
                .unwrap_or_default()
                .replace("\\\"", "\"");
        }
        params.insert(key.trim().to_ascii_lowercase(), value);
        Ok(())
    };
    let bytes = text.as_bytes();
    let (mut quoted, mut class, mut depth, mut from) = (false, false, 0usize, 0usize);
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if quoted {
            if c == b'\\' && bytes.get(i + 1) == Some(&b'"') {
                i += 1;
            } else if c == b'"' {
                quoted = false;
            }
        } else if c == b'\\' {
            i += 1;
        } else if c == b'"' {
            quoted = true;
        } else if class {
            class = c != b']';
        } else if c == b'[' {
            class = true;
        } else if c == b'(' || c == b'{' {
            depth += 1;
        } else if (c == b')' || c == b'}') && depth > 0 {
            depth -= 1;
        } else if c == b',' && depth == 0 {
            add(text.get(from..i).unwrap_or_default())?;
            from = i + 1;
        }
        i += 1;
    }
    if quoted {
        return Err("unclosed quote".to_string());
    }
    add(text.get(from.min(text.len())..).unwrap_or_default())?;
    Ok(params)
}

fn script_bool(params: &Params, key: &str) -> Result<bool, String> {
    let Some(text) = params.get(key) else {
        return Ok(false);
    };
    match text.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" | "" => Ok(false),
        _ => Err(format!("invalid {key} {}", quote(text))),
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    use std::future::Future;
    use std::pin::Pin;

    use super::*;

    pub type Behavior = Arc<
        dyn Fn(
                ScriptInvocation,
            )
                -> Pin<Box<dyn Future<Output = Result<ScriptResult, ScriptError>> + Send>>
            + Send
            + Sync,
    >;

    pub struct FakeProgram(pub Behavior);

    #[async_trait]
    impl ScriptProgram for FakeProgram {
        async fn run(&self, invocation: ScriptInvocation) -> Result<ScriptResult, ScriptError> {
            (self.0)(invocation).await
        }
    }

    pub fn sync_program(
        f: impl Fn(&ScriptInvocation) -> Result<ScriptResult, ScriptError> + Send + Sync + 'static,
    ) -> Arc<dyn ScriptProgram> {
        Arc::new(FakeProgram(Arc::new(move |invocation| {
            let result = f(&invocation);
            Box::pin(async move { result })
        })))
    }

    /// Compiles a script by looking its source up.
    #[derive(Default)]
    pub struct FakeRuntime(pub HashMap<String, Arc<dyn ScriptProgram>>);

    impl ScriptRuntime for FakeRuntime {
        fn compile(&self, _name: &str, source: &[u8]) -> Result<Arc<dyn ScriptProgram>, String> {
            let key = String::from_utf8_lossy(source).into_owned();
            self.0
                .get(&key)
                .cloned()
                .ok_or_else(|| format!("SyntaxError: {key}"))
        }
    }

    /// Writes each script into `resources` under its source and returns a host
    /// that compiles them.
    pub fn host_with(
        resources: &Path,
        scripts: Vec<(&str, Arc<dyn ScriptProgram>)>,
    ) -> Arc<ScriptHost> {
        std::fs::create_dir_all(resources).unwrap();
        let mut runtime = FakeRuntime::default();
        for (source, program) in scripts {
            std::fs::write(resources.join(format!("{source}.js")), source).unwrap();
            runtime.0.insert(source.to_string(), program);
        }
        Arc::new(ScriptHost::new(Some(Arc::new(runtime))))
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    fn setup() -> (tempfile::TempDir, std::path::PathBuf, Arc<ScriptHost>) {
        let home = tempfile::tempdir().unwrap();
        let resources = home.path().join("resources");
        let host = host_with(
            &resources,
            vec![("a", sync_program(|_| Ok(ScriptResult::default())))],
        );
        std::fs::write(resources.join("broken.js"), "broken").unwrap();
        (home, resources, host)
    }

    #[test]
    fn a_panicked_holder_leaves_the_runtime_and_its_programs_usable() {
        let (_home, resources, host) = setup();
        concord_test_support::poison(&host.runtime);
        concord_test_support::poison(&host.programs);
        let (first, _) = host.compile(&resources, "a.js").unwrap();
        let (again, _) = host.compile(&resources, "a.js").unwrap();
        assert!(Arc::ptr_eq(&first, &again), "the program was cached");
        host.set_runtime(None);
        assert_eq!(
            host.compile(&resources, "a.js").err().as_deref(),
            Some("this build runs no scripts")
        );
    }

    struct Want {
        name: &'static str,
        kind: ScriptKind,
        requires_body: bool,
        binary_body: bool,
        max_size: i64,
        timeout: Duration,
        cronexp: &'static str,
        event: &'static str,
        argument: Option<serde_json::Value>,
    }

    impl Default for Want {
        fn default() -> Self {
            Want {
                name: "",
                kind: ScriptKind::Generic,
                requires_body: false,
                binary_body: false,
                max_size: 0,
                timeout: DEFAULT_SCRIPT_TIMEOUT,
                cronexp: "",
                event: "",
                argument: None,
            }
        }
    }

    #[test]
    fn script_lines_read_surge_and_loon() {
        let (_home, resources, host) = setup();
        let s = |text: &str| Some(serde_json::Value::String(text.to_string()));
        let cases = vec![
            (
                r#"Ads = type=http-response,pattern=^https://a\.com/(x|y),requires-body=1,max-size=1024,timeout=10,script-path=a.js,argument="k=v,w""#,
                Want {
                    name: "Ads",
                    kind: ScriptKind::HttpResponse,
                    requires_body: true,
                    max_size: 1024,
                    timeout: Duration::from_secs(10),
                    argument: s("k=v,w"),
                    ..Want::default()
                },
            ),
            (
                r"Req = type=http-request,pattern=^https://a\.com/\d{1,3},script-path=a.js,binary-body-mode=true,timeout=600",
                Want {
                    name: "Req",
                    kind: ScriptKind::HttpRequest,
                    binary_body: true,
                    timeout: MAX_SCRIPT_TIMEOUT,
                    ..Want::default()
                },
            ),
            (
                r#"http-response ^https:\/\/a\.com\/x script-path=a.js, requires-body=true, max-size=-1, tag=Loon, argument-json="{\"on\":true}""#,
                Want {
                    name: "Loon",
                    kind: ScriptKind::HttpResponse,
                    requires_body: true,
                    argument: Some(serde_json::json!({"on": true})),
                    ..Want::default()
                },
            ),
            (
                r"http-request ^https://a\.com script-path=a.js",
                Want {
                    name: "a.js",
                    kind: ScriptKind::HttpRequest,
                    ..Want::default()
                },
            ),
            (
                r#"Sign = type=cron,cronexp="0 8 * * *",timeout=3600,wake-system=1,script-path=a.js"#,
                Want {
                    name: "Sign",
                    kind: ScriptKind::Cron,
                    cronexp: "0 8 * * *",
                    timeout: Duration::from_secs(3600),
                    ..Want::default()
                },
            ),
            (
                r#"cron "0 8 * * *" script-path=a.js, tag=Loon sign, timeout=7200"#,
                Want {
                    name: "Loon sign",
                    kind: ScriptKind::Cron,
                    cronexp: "0 8 * * *",
                    timeout: MAX_TASK_TIMEOUT,
                    ..Want::default()
                },
            ),
            (
                "Net = type=event,event-name=network-changed,script-path=a.js",
                Want {
                    name: "Net",
                    kind: ScriptKind::Event,
                    event: EVENT_NETWORK_CHANGED,
                    ..Want::default()
                },
            ),
            (
                "network-changed script-path=a.js, tag=Loon net",
                Want {
                    name: "Loon net",
                    kind: ScriptKind::Event,
                    event: EVENT_NETWORK_CHANGED,
                    ..Want::default()
                },
            ),
            (
                "event engine-started script-path=a.js",
                Want {
                    name: "a.js",
                    kind: ScriptKind::Event,
                    event: EVENT_ENGINE_STARTED,
                    ..Want::default()
                },
            ),
            (
                "Tool = script-path=a.js,timeout=30",
                Want {
                    name: "Tool",
                    kind: ScriptKind::Generic,
                    timeout: Duration::from_secs(30),
                    ..Want::default()
                },
            ),
            (
                "generic script-path=a.js, tag=Node info, img-url=x.png",
                Want {
                    name: "Node info",
                    kind: ScriptKind::Generic,
                    ..Want::default()
                },
            ),
        ];
        for (line, want) in cases {
            let got =
                parse_script(line, &resources, &host).unwrap_or_else(|e| panic!("{line}: {e}"));
            assert_eq!(
                (
                    got.name.as_str(),
                    got.kind,
                    got.requires_body,
                    got.binary_body,
                    got.max_size,
                    got.timeout
                ),
                (
                    want.name,
                    want.kind,
                    want.requires_body,
                    want.binary_body,
                    want.max_size,
                    want.timeout
                ),
                "{line}"
            );
            assert_eq!(
                (got.cronexp.as_str(), got.event.as_str()),
                (want.cronexp, want.event),
                "{line}"
            );
            assert_eq!(got.argument, want.argument, "{line}");
            assert_eq!(got.path, "a.js");
        }
        let req = parse_script(
            r"Req = type=http-request,pattern=^https://a\.com/\d{1,3},script-path=a.js",
            &resources,
            &host,
        )
        .unwrap();
        assert!(req.matches_http("https://a.com/12", false));
    }

    #[test]
    fn script_lines_read_head_conditions() {
        let (_home, resources, host) = setup();
        let script = parse_script(
            r#"Ads = type=http-response,pattern=^https://a\.com/,request-head="^(?=POST )",response-head=" 200\r\n",script-path=a.js"#,
            &resources,
            &host,
        )
        .unwrap();
        assert!(script.conditions.request.is_some() && script.conditions.response.is_some());
        let plain = parse_script(
            r"Ads = type=http-response,pattern=^https://a\.com/,script-path=a.js",
            &resources,
            &host,
        )
        .unwrap();
        assert!(plain.conditions.request.is_none() && plain.conditions.response.is_none());
    }

    #[test]
    fn script_lines_reject_what_they_cannot_run() {
        let (_home, resources, host) = setup();
        let cases = [
            (
                "DNS = type=dns,script-path=a.js",
                "dns scripts are not supported",
            ),
            ("rule Ad script-path=a.js", "rule scripts are not supported"),
            ("Cron = type=cron,script-path=a.js", "cronexp is missing"),
            (
                r#"Cron = type=cron,cronexp="0 9 * *",script-path=a.js"#,
                "has 4 fields",
            ),
            (
                "Event = type=event,script-path=a.js",
                "event-name is missing",
            ),
            (
                "Event = type=event,event-name=notification,script-path=a.js",
                "the notification event is not supported",
            ),
            (
                "X = type=quantum,pattern=a,script-path=a.js",
                r#"unknown type "quantum""#,
            ),
            ("X = type=http-request,pattern=a", "script-path is missing"),
            (
                "X = type=http-request,script-path=a.js",
                "pattern is missing",
            ),
            (
                "X = type=http-request,pattern=a,script-path=a.js,full-header-mode=true",
                "full-header-mode is not supported",
            ),
            (
                "X = type=http-request,pattern=a,script-path=a.js,max-size=-2",
                "invalid max-size",
            ),
            (
                "X = type=http-request,pattern=a,script-path=missing.js",
                "missing.js",
            ),
            (
                "X = type=http-request,pattern=a,script-path=../a.js",
                "not a file in the resources directory",
            ),
            (
                "X = type=http-request,pattern=a,script-path=broken.js",
                "SyntaxError",
            ),
            (
                r#"X = type=http-request,pattern=a,script-path=a.js,argument-json="{""#,
                "argument-json",
            ),
            (
                r#"X = type=http-request,pattern="a,script-path=a.js"#,
                "unclosed quote",
            ),
            ("no parameters", "expected name = parameters"),
            (
                "X = type=http-request,pattern=a,script-path=a.js,requires-body=sometimes",
                "invalid requires-body",
            ),
            (
                "X = type=http-request,pattern=a,script-path=a.js,response-head=200",
                "response-head needs an http-response rule",
            ),
            (
                r#"X = type=http-response,pattern=a,script-path=a.js,request-head="(""#,
                "parenthesis",
            ),
        ];
        for (line, want) in cases {
            let err = parse_script(line, &resources, &host).expect_err(line);
            assert!(err.contains(want), "{line}: {err}, want {want}");
        }
        host.set_runtime(None);
        assert!(
            parse_script(
                "X = type=http-request,pattern=a,script-path=a.js",
                &resources,
                &host
            )
            .is_err()
        );
    }

    #[test]
    fn script_params_keep_what_they_quote() {
        let params = script_params(
            r#"pattern="^https://a\.com/\"q\",x",argument=[{a},{b}],max=\d{1,3},class=[,],json="{\"k\":\"a\\"b\"}""#,
        )
        .unwrap();
        for (key, want) in [
            ("pattern", r#"^https://a\.com/"q",x"#),
            ("argument", "[{a},{b}]"),
            ("max", r"\d{1,3}"),
            ("class", "[,]"),
            ("json", r#"{"k":"a\"b"}"#),
        ] {
            assert_eq!(params.get(key).map(String::as_str), Some(want), "{key}");
        }
    }
}
