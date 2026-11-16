use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, DialEnv, FlowMeta, InboundInfo, InboundKind, Network,
    NodeDialer, Outbound, OutboundKind, PacketSession,
};
use concord_config::filter::{Matcher, compile_pattern};
use concord_config::group::{GroupDef, GroupKind, LbStrategy};
use concord_config::profile::Profile;
use futures_util::future::join_all;
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use crate::check::{Check, CheckParams, Source, Supervisor};
use crate::deps::{Builtin, GroupDeps};
use crate::error::GroupError;
use crate::first_write::FirstWrite;
use crate::group::{Emptiness, Group, GroupParts, Pick, Policy, Touch};
use crate::health::StatusRanges;
use crate::node::{Ghost, Item, Leaf, Node};
use crate::provider::{self, ProxyProvider};
use crate::selection::Probing;
use crate::shared::Shared;
use crate::strategy::Strategy;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const GLOBAL: &str = "GLOBAL";

pub(crate) enum Entry {
    Leaf(Arc<Leaf>),
    Group(Arc<Group>),
    Ghost(Arc<Ghost>),
}

pub(crate) enum Found {
    Node(Node),
    Ghost(Arc<Ghost>),
}

pub enum Resolved {
    Route {
        leaf: Arc<dyn Outbound>,
        chain: Box<[Arc<str>]>,
        provider_chain: Box<[Arc<str>]>,
        exit_group: Option<Arc<str>>,
        udp: bool,
    },
    Pass,
    PassRule,
    Rejected(Arc<str>),
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SelectOutcome {
    pub message: String,
    pub changed: bool,
}

pub struct Staged {
    target: Arc<Group>,
    proxy: String,
    before: String,
    probing: Option<Probing>,
}

pub fn load_balancer_exit(group: &str) -> String {
    format!("{group:?} LoadBalance ")
}

pub fn node_exit(info: &concord_common::OutboundInfo) -> String {
    format!(
        "{:?} {} {}",
        info.name.as_ref(),
        info.kind.wire_name(),
        info.addr
    )
}

pub struct Outbounds {
    pub(crate) shared: Arc<Shared>,
    env: ArcSwap<DialEnv>,
    me: Weak<Outbounds>,
    table: HashMap<Arc<str>, Entry>,
    groups: Vec<Arc<Group>>,
    builtin_global: bool,
    node_order: Vec<Arc<str>>,
    providers: Vec<Arc<ProxyProvider>>,
    checks: Vec<Arc<Check>>,
    supervisor: Mutex<Supervisor>,
    last_picks: Mutex<HashMap<Arc<str>, String>>,
    background: AtomicBool,
}

struct WeakNodes(Weak<Outbounds>);

#[async_trait]
impl NodeDialer for WeakNodes {
    async fn dial_via(&self, name: &str, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        match self.0.upgrade() {
            Some(outbounds) => outbounds.dial_via(name, cx, dst).await,
            None => Err(CoreError::UnknownNode(name.to_string()).into()),
        }
    }

    async fn associate_via(
        &self,
        name: &str,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        match self.0.upgrade() {
            Some(outbounds) => outbounds.associate_via(name, cx, hint).await,
            None => Err(CoreError::UnknownNode(name.to_string()).into()),
        }
    }
}

fn compile_parts(text: &str, sep: char) -> Result<Vec<Matcher>, GroupError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(sep)
        .map(|part| compile_pattern(part, false).map_err(|err| GroupError::Config(err.message)))
        .collect()
}

fn raw_interval_is_zero(raw: &concord_config::Map) -> bool {
    match raw.get("interval") {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.trim().parse::<u64>().is_ok_and(|n| n == 0),
        Some(value) => value.as_u64() == Some(0),
    }
}

pub(crate) fn dummy_flow(dst: Address, network: Network) -> FlowMeta {
    FlowMeta {
        dscp: 0,
        network,
        inbound: InboundInfo::new(InboundKind::Inner),
        src: SocketAddr::from(([0, 0, 0, 0], 0)),
        dst,
    }
}

type Dialed = (Arc<dyn Outbound>, Box<[Arc<str>]>, bool);

struct Builder<'a> {
    profile: &'a Profile,
    shared: &'a Arc<Shared>,
    table: HashMap<Arc<str>, Entry>,
    providers: &'a [Arc<ProxyProvider>],
    quarantined: Arc<HashSet<String>>,
    building: Vec<String>,
}

impl Builder<'_> {
    fn group(&mut self, name: &str) -> Result<Arc<Group>, GroupError> {
        if let Some(Entry::Group(group)) = self.table.get(name) {
            return Ok(group.clone());
        }
        if self.building.iter().any(|building| building == name) {
            return Err(GroupError::Cycle(self.building.clone()));
        }
        let profile = self.profile;
        let Some(def) = profile.groups.iter().find(|def| def.name == name) else {
            return Err(GroupError::Config(format!("proxy group {name} not found")));
        };
        self.building.push(name.to_string());
        let group = self.build_group(def)?;
        self.building.pop();
        self.table
            .insert(group.name().clone(), Entry::Group(group.clone()));
        Ok(group)
    }

    fn build_group(&mut self, def: &GroupDef) -> Result<Arc<Group>, GroupError> {
        let mut own: Vec<Item> = Vec::new();
        for name in &def.proxies {
            let node = match self.table.get(name.as_str()) {
                Some(Entry::Leaf(leaf)) => Node::Leaf(leaf.clone()),
                Some(Entry::Ghost(_)) => continue,
                Some(Entry::Group(group)) => Node::Group(group.clone()),
                None if self.profile.groups.iter().any(|group| &group.name == name) => {
                    Node::Group(self.group(name)?)
                }
                None => {
                    return Err(GroupError::NotFound {
                        group: def.name.clone(),
                        name: name.clone(),
                    });
                }
            };
            own.push(Item::Live(node));
        }
        let mut uses = Vec::with_capacity(def.use_providers.len());
        for name in &def.use_providers {
            let provider = self
                .providers
                .iter()
                .find(|provider| provider.name().as_ref() == name.as_str());
            uses.push(provider.cloned().ok_or_else(|| GroupError::NotFound {
                group: def.name.clone(),
                name: name.clone(),
            })?);
        }
        if !def.proxies.is_empty()
            && self
                .providers
                .iter()
                .any(|provider| provider.name().as_ref() == def.name.as_str())
        {
            return Err(GroupError::DuplicateProvider {
                group: def.name.clone(),
            });
        }

        let shared = self.shared.clone();
        let raw_text = |key: &str| {
            def.raw
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        };
        let explicit_url = raw_text("url");
        let url = if !explicit_url.is_empty() {
            explicit_url.clone()
        } else {
            uses.iter()
                .map(|provider| provider.health_check_url().to_string())
                .find(|url| !url.is_empty())
                .unwrap_or_else(|| shared.default_url())
        };
        let expected = StatusRanges::parse(&def.expected_status).unwrap_or_default();

        let fallback_leaf = match self.table.get(def.empty_fallback.as_str()) {
            Some(Entry::Leaf(leaf)) => Some(leaf.clone()),
            _ => None,
        };
        let explicit_fallback = !raw_text("empty-fallback").is_empty() && fallback_leaf.is_some();
        let empty_fallback = match fallback_leaf {
            Some(leaf) => leaf,
            None => match self.table.get("COMPATIBLE") {
                Some(Entry::Leaf(leaf)) => leaf.clone(),
                _ => return Err(GroupError::Config("COMPATIBLE is missing".into())),
            },
        };

        let policy = match def.kind {
            GroupKind::Select => Policy::Select {
                default_selected: Arc::from(def.default_selected.as_str()),
            },
            GroupKind::UrlTest => Policy::UrlTest {
                tolerance: def.tolerance,
            },
            GroupKind::Fallback => Policy::Fallback,
            GroupKind::LoadBalance => {
                let in_user = def.hash_key == "in-user";
                Policy::LoadBalance(match def.strategy {
                    LbStrategy::ConsistentHashing => Strategy::ConsistentHashing { in_user },
                    LbStrategy::RoundRobin => Strategy::RoundRobin(Mutex::new(0)),
                    LbStrategy::StickySessions => Strategy::StickySessions {
                        in_user,
                        cache: Mutex::new(Default::default()),
                    },
                })
            }
        };

        let own_check = if own.is_empty() {
            None
        } else {
            let nodes = own
                .iter()
                .filter_map(|item| match item {
                    Item::Live(node) => Some(node.clone()),
                    Item::Ghost(_) => None,
                })
                .collect();
            Some(Check::new(
                CheckParams {
                    id: format!("group:{}", def.name),
                    url: url.clone(),
                    timeout_ms: def.timeout,
                    interval_secs: def.interval,
                    lazy: def.lazy,
                    expected: expected.clone(),
                },
                Source::Static(nodes),
            ))
        };
        if !uses.is_empty() && !explicit_url.is_empty() {
            let interval = if !own.is_empty()
                && def.kind != GroupKind::Select
                && raw_interval_is_zero(&def.raw)
            {
                0
            } else {
                def.interval
            };
            for provider in &uses {
                provider
                    .check()
                    .register_extra(&explicit_url, &expected, &def.filter, interval);
            }
        }

        Ok(Group::new(GroupParts {
            name: Arc::from(def.name.as_str()),
            policy,
            url,
            expected_text: def.expected_status.clone(),
            expected,
            disable_udp: def.disable_udp,
            hidden: def.hidden,
            icon: def.icon.clone(),
            empty_fallback,
            explicit_fallback,
            refused: self.profile.refused_groups.contains(&def.name),
            quarantined: self.quarantined.clone(),
            own,
            uses,
            use_position: def.use_position.clone(),
            filter: compile_parts(&def.filter, '`')?,
            exclude_filter: compile_parts(&def.exclude_filter, '`')?,
            exclude_type: if def.exclude_type.is_empty() {
                Vec::new()
            } else {
                def.exclude_type.split('|').map(str::to_string).collect()
            },
            own_check,
            test_timeout: Duration::from_millis(if def.timeout > 0 {
                u64::from(def.timeout)
            } else {
                5000
            }),
            max_failed: if def.max_failed_times > 0 {
                def.max_failed_times
            } else {
                5
            },
            shared,
        }))
    }
}

impl Outbounds {
    /// Takes the proxy definitions out of `profile`, freeing each as its node is built.
    pub fn build(profile: &mut Profile, deps: GroupDeps) -> Result<Arc<Outbounds>, GroupError> {
        let shared = Shared::new(&deps);
        let factory = deps.factory.clone();
        let mut table: HashMap<Arc<str>, Entry> = HashMap::new();
        let mut node_order: Vec<Arc<str>> = Vec::new();
        for (name, which) in [
            ("DIRECT", Builtin::Direct),
            ("REJECT", Builtin::Reject),
            ("REJECT-DROP", Builtin::RejectDrop),
            ("COMPATIBLE", Builtin::Compatible),
            ("PASS", Builtin::Pass),
            ("PASS-RULE", Builtin::PassRule),
        ] {
            let name: Arc<str> = Arc::from(name);
            table.insert(
                name.clone(),
                Entry::Leaf(Leaf::new(factory.builtin(which), None)),
            );
            node_order.push(name);
        }
        for def in std::mem::take(&mut profile.proxies) {
            let name: Arc<str> = Arc::from(def.name.as_str());
            if table.contains_key(&name) {
                return Err(GroupError::Config(format!(
                    "proxy {} is the duplicate name",
                    def.name
                )));
            }
            match factory.build_def(&def) {
                Ok(outbound) => {
                    table.insert(name.clone(), Entry::Leaf(Leaf::new(outbound, None)));
                }
                Err(failure) => {
                    let message = format!("{}: {}", def.name, failure.message);
                    profile
                        .report
                        .warn("proxy_quarantined", format!("proxies.{name}"), message);
                    table.insert(
                        name.clone(),
                        Entry::Ghost(ghost(&def.name, def.kind.type_name(), &failure.message)),
                    );
                }
            }
            node_order.push(name);
        }
        let profile: &Profile = profile;
        for item in profile
            .quarantined
            .iter()
            .filter(|item| item.provider.is_none())
        {
            let name: Arc<str> = Arc::from(item.name.as_str());
            table.insert(
                name,
                Entry::Ghost(ghost(&item.name, &item.kind, &item.reason)),
            );
        }

        let mut providers = Vec::with_capacity(profile.proxy_providers.len());
        for def in &profile.proxy_providers {
            providers.push(ProxyProvider::new(def, shared.clone())?);
        }

        let mut builder = Builder {
            profile,
            shared: &shared,
            table,
            providers: &providers,
            quarantined: Arc::new(profile.quarantined_names.clone()),
            building: Vec::new(),
        };
        let mut groups = Vec::with_capacity(profile.groups.len());
        for def in &profile.groups {
            groups.push(builder.group(&def.name)?);
        }
        let table = builder.table;
        let builtin_global = profile
            .groups
            .iter()
            .any(|def| def.name == GLOBAL && def.raw.is_empty());

        let mut checks: Vec<Arc<Check>> = Vec::new();
        for group in &groups {
            checks.extend(group.own_check().cloned());
        }
        checks.extend(providers.iter().map(|provider| provider.check().clone()));

        let outbounds = Arc::new_cyclic(|weak: &Weak<Outbounds>| {
            let nodes: Arc<dyn NodeDialer> = Arc::new(WeakNodes(weak.clone()));
            Outbounds {
                env: ArcSwap::from_pointee((deps.env)(nodes)),
                me: weak.clone(),
                shared,
                table,
                groups,
                builtin_global,
                node_order,
                providers,
                checks,
                supervisor: Mutex::new(Supervisor::default()),
                last_picks: Mutex::new(HashMap::new()),
                background: AtomicBool::new(false),
            }
        });
        *lock(&outbounds.last_picks) = outbounds.pick_snapshot();
        Ok(outbounds)
    }

    pub fn env(&self) -> Arc<DialEnv> {
        self.env.load_full()
    }

    /// `config.update` changes these without a rebuild; a dial under way keeps
    /// what it started with.
    pub fn set_dial_flags(&self, tcp_concurrent: bool, ipv6: bool) {
        let mut env = (*self.env.load_full()).clone();
        env.tcp_concurrent = tcp_concurrent;
        env.ipv6 = ipv6;
        self.env.store(Arc::new(env));
    }

    pub(crate) fn node_order(&self) -> &[Arc<str>] {
        &self.node_order
    }

    pub(crate) fn table(&self) -> &HashMap<Arc<str>, Entry> {
        &self.table
    }

    pub(crate) fn builtin_global(&self) -> bool {
        self.builtin_global
    }

    pub fn groups(&self) -> &[Arc<Group>] {
        &self.groups
    }

    pub fn providers(&self) -> Vec<Arc<ProxyProvider>> {
        self.providers.clone()
    }

    pub fn provider(&self, name: &str) -> Option<Arc<ProxyProvider>> {
        self.providers
            .iter()
            .find(|provider| provider.name().as_ref() == name)
            .cloned()
    }

    pub(crate) fn checks(&self) -> &[Arc<Check>] {
        &self.checks
    }

    /// Provider nodes shadow the profile's own on a name clash.
    pub(crate) fn lookup(&self, name: &str) -> Option<Found> {
        for provider in &self.providers {
            let snapshot = provider.nodes();
            if let Some(leaf) = snapshot.get(name) {
                return Some(Found::Node(Node::Leaf(leaf.clone())));
            }
            if let Some(ghost) = snapshot.ghost(name) {
                return Some(Found::Ghost(ghost.clone()));
            }
        }
        match self.table.get(name)? {
            Entry::Leaf(leaf) => Some(Found::Node(Node::Leaf(leaf.clone()))),
            Entry::Group(group) => Some(Found::Node(Node::Group(group.clone()))),
            Entry::Ghost(ghost) => Some(Found::Ghost(ghost.clone())),
        }
    }

    pub fn node(&self, name: &str) -> Option<Node> {
        match self.lookup(name)? {
            Found::Node(node) => Some(node),
            Found::Ghost(_) => None,
        }
    }

    pub fn group(&self, name: &str) -> Option<Arc<Group>> {
        match self.lookup(name)? {
            Found::Node(Node::Group(group)) => Some(group),
            _ => None,
        }
    }

    pub fn resolve(
        &self,
        name: &str,
        flow: &FlowMeta,
        host: Option<&str>,
        touch: Touch,
    ) -> Resolved {
        match self.lookup(name) {
            Some(Found::Node(node)) => self.walk(node, flow, host, touch),
            Some(Found::Ghost(ghost)) => Resolved::Rejected(Arc::from(format!(
                "proxy {} is not supported by this core: {}",
                ghost.name, ghost.reason
            ))),
            None => Resolved::Unknown,
        }
    }

    pub(crate) fn walk(
        &self,
        start: Node,
        flow: &FlowMeta,
        host: Option<&str>,
        touch: Touch,
    ) -> Resolved {
        let mut path: Vec<Arc<str>> = Vec::new();
        let mut exit_group = None;
        let (mut udp, mut decided) = (true, false);
        let mut node = start;
        // Cycles are refused at load, as mihomo does, so a walk visits each entry at most once.
        for _ in 0..=self.table.len() {
            match node {
                Node::Leaf(leaf) => {
                    match leaf.info().kind {
                        OutboundKind::Pass => return Resolved::Pass,
                        OutboundKind::PassRule => return Resolved::PassRule,
                        _ => {}
                    }
                    if !decided {
                        udp = leaf.info().udp;
                    }
                    let mut chain = vec![leaf.name().clone()];
                    let mut provider_chain =
                        vec![leaf.provider().cloned().unwrap_or_else(|| Arc::from(""))];
                    for group in path.iter().rev() {
                        chain.push(group.clone());
                        provider_chain.push(Arc::from(""));
                    }
                    return Resolved::Route {
                        leaf: leaf.outbound().clone(),
                        chain: chain.into(),
                        provider_chain: provider_chain.into(),
                        exit_group,
                        udp,
                    };
                }
                Node::Group(group) => {
                    path.push(group.name().clone());
                    if !decided {
                        if group.blocks_udp() {
                            udp = false;
                            decided = true;
                        } else if group.is_load_balance() {
                            decided = true;
                        }
                    }
                    if group.is_load_balance() {
                        exit_group.get_or_insert_with(|| group.name().clone());
                    }
                    match group.pick(flow, host, touch) {
                        Pick::Node(next) => node = next,
                        Pick::Rejected { reason, .. } => return Resolved::Rejected(reason),
                    }
                }
            }
        }
        Resolved::Rejected(Arc::from("proxy groups are nested too deep"))
    }

    /// `"name" Type addr`, the identity a probe reports as the exit. A load
    /// balancer stands for its members, so it is the exit itself.
    pub fn exit_identity(&self, resolved: &Resolved) -> Option<String> {
        let Resolved::Route {
            leaf,
            chain,
            exit_group,
            ..
        } = resolved
        else {
            return None;
        };
        let _ = chain;
        Some(match exit_group {
            Some(group) => load_balancer_exit(group),
            None => node_exit(leaf.info()),
        })
    }

    /// `exitOfChains`: chains run from the hop that dialed out to the outermost
    /// group, so they are read from the end to meet the balancer a route stops at.
    pub fn exit_of_chains(&self, chains: &[String]) -> Option<String> {
        for name in chains.iter().skip(1).rev() {
            if let Some(group) = self.group(name)
                && matches!(group.policy(), Policy::LoadBalance(_))
            {
                return Some(load_balancer_exit(name));
            }
        }
        match self.node(chains.first()?)? {
            Node::Leaf(leaf) => Some(node_exit(leaf.info())),
            Node::Group(group) => Some(format!(
                "{:?} {} ",
                group.name().as_ref(),
                group.type_name()
            )),
        }
    }

    pub(crate) fn pick_snapshot(&self) -> HashMap<Arc<str>, String> {
        let flow = dummy_flow(Address::new("", 0), Network::Tcp);
        self.groups
            .iter()
            .filter(|group| group.is_selectable())
            .map(|group| (group.name().clone(), group.now(&flow)))
            .collect()
    }

    /// Counts a Moved when any pick differs from the last one seen.
    pub fn refresh_picks(&self) {
        let picks = self.pick_snapshot();
        let changed = {
            let mut last = lock(&self.last_picks);
            let changed = *last != picks;
            *last = picks;
            changed
        };
        if changed {
            self.shared.route.moved();
        }
    }

    pub fn selections(&self) -> Vec<(String, String)> {
        self.shared.selections.entries()
    }

    /// The saved pick of `group`, empty when it has none.
    pub fn selection(&self, group: &str) -> String {
        self.shared
            .selections
            .get(group)
            .map(|proxy| proxy.to_string())
            .unwrap_or_default()
    }

    pub async fn select(&self, group: &str, proxy: &str) -> SelectOutcome {
        match self.stage_selection(group, proxy) {
            Ok(staged) => {
                self.probe_selection(&staged).await;
                self.settle_selection(staged)
            }
            Err(failed) => failed,
        }
    }

    /// Stores the pick, as mihomo's `Set` does before it tests a fallback
    /// member (`fallback.go:139-145`); `settle_selection` tells whether routing
    /// moved once `probe_selection` has run. A fallback member believed dead is
    /// marked under test before it is stored, so routing in between cannot drop
    /// the pick before the test decides.
    pub fn stage_selection(&self, group: &str, proxy: &str) -> Result<Staged, SelectOutcome> {
        let fail = |message: &str| SelectOutcome {
            message: message.to_string(),
            changed: false,
        };
        let target = match self.lookup(group) {
            Some(Found::Node(Node::Group(target))) => target,
            Some(_) => return Err(fail("Group is not selectable")),
            None => return Err(fail("Not found group")),
        };
        if !target.is_selectable() {
            return Err(fail("Group is not selectable"));
        }
        let before = target.now(&dummy_flow(Address::new("", 0), Network::Tcp));
        let store = &self.shared.selections;
        let mut probing = None;
        if proxy.is_empty() {
            if matches!(target.policy(), Policy::Select { .. }) {
                store.set(group, "");
            } else {
                store.remove(group);
            }
        } else {
            let members = target.members();
            let listed = members.find(proxy).is_some()
                || (members.emptiness() == Emptiness::Fallback
                    && target.empty_fallback().name().as_ref() == proxy);
            if !listed {
                return Err(fail("proxy not exist"));
            }
            if matches!(target.policy(), Policy::Fallback)
                && members
                    .find(proxy)
                    .is_some_and(|node| !node.health().alive_for(target.url()))
            {
                probing = Some(store.probing(target.name()));
            }
            store.set(group, proxy);
        }
        Ok(Staged {
            target,
            proxy: proxy.to_string(),
            before,
            probing,
        })
    }

    /// A fallback member believed dead is tested before traffic is routed to
    /// it. Holds no lock, so a slow probe never delays another change.
    pub async fn probe_selection(&self, staged: &Staged) {
        let target = &staged.target;
        if staged.probing.is_some()
            && let Some(node) = target.members().find(&staged.proxy)
        {
            self.url_test_node(node, target.url(), target.expected(), PROBE_TIMEOUT)
                .await;
        }
    }

    pub fn settle_selection(&self, staged: Staged) -> SelectOutcome {
        let Staged {
            target,
            before,
            probing,
            ..
        } = staged;
        drop(probing);
        let changed = target.now(&dummy_flow(Address::new("", 0), Network::Tcp)) != before;
        self.refresh_picks();
        SelectOutcome {
            message: String::new(),
            changed,
        }
    }

    pub fn reset_sessions(&self) {
        for entry in self.table.values() {
            if let Entry::Leaf(leaf) = entry {
                leaf.outbound().reset_sessions();
            }
        }
        for provider in &self.providers {
            for item in provider.nodes().items() {
                if let Item::Live(Node::Leaf(leaf)) = item {
                    leaf.outbound().reset_sessions();
                }
            }
        }
    }

    /// The mapping a provider node was built from. Nodes of the profile itself
    /// are the engine's to read from `config.yaml`.
    pub async fn definition(&self, name: &str) -> Option<Map<String, Value>> {
        let provider = match self.lookup(name)? {
            Found::Node(Node::Leaf(leaf)) => leaf.provider().cloned()?,
            Found::Ghost(ghost) => ghost.provider.clone()?,
            Found::Node(Node::Group(_)) => return None,
        };
        self.provider(&provider)?
            .definition(name)
            .await
            .ok()
            .flatten()
    }

    /// `answered` holds back the outcome of each provider's first load; see
    /// `provider::run`.
    pub fn start_background(
        self: &Arc<Self>,
        stop: CancellationToken,
        answered: CancellationToken,
    ) {
        if self.background.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(self);
        let refresher_stop = stop.child_token();
        let refresher_owner = weak.clone();
        tokio::spawn(async move {
            loop {
                let Some(outbounds) = refresher_owner.upgrade() else {
                    return;
                };
                let notified = outbounds.shared.clone();
                drop(outbounds);
                tokio::select! {
                    _ = refresher_stop.cancelled() => return,
                    _ = notified.refresh.notified() => {}
                }
                match refresher_owner.upgrade() {
                    Some(outbounds) => outbounds.refresh_picks(),
                    None => return,
                }
            }
        });
        for provider in &self.providers {
            tokio::spawn(provider::run(
                Arc::downgrade(provider),
                stop.child_token(),
                answered.clone(),
            ));
        }
        lock(&self.supervisor).reconcile(&self.checks, &weak, &stop);
    }

    pub fn reconcile_checks(self: &Arc<Self>, stop: &CancellationToken) {
        lock(&self.supervisor).reconcile(&self.checks, &Arc::downgrade(self), stop);
    }

    /// Counts a failed dial against the groups it went through, which test
    /// their members after enough failures. A fallback or load balancer only
    /// counts TCP, as mihomo's `ListenPacketContext` of those never reports.
    pub fn note_dial_failed(
        &self,
        chain: &[Arc<str>],
        leaf_kind: OutboundKind,
        network: Network,
        err: &io::Error,
    ) {
        for (position, name) in chain.iter().enumerate().skip(1) {
            let Some(Entry::Group(group)) = self.table.get(name) else {
                continue;
            };
            let counts = match group.policy() {
                Policy::UrlTest { .. } => true,
                Policy::Fallback | Policy::LoadBalance(_) => network == Network::Tcp,
                _ => false,
            };
            if !counts {
                continue;
            }
            let child = (position == 1).then_some(leaf_kind);
            if group.dial_failed(child, err)
                && let Some(outbounds) = self.me.upgrade()
            {
                let group = group.clone();
                tokio::spawn(async move {
                    join_all(group.checks().map(|check| check.check(&outbounds))).await;
                    group.finish_checking();
                });
            }
        }
    }

    /// Counts a dialed stream's first write for the groups it went through,
    /// once, when the stream still holds its protocol header back: a success
    /// clears their failure count, a failure counts like a failed dial.
    pub fn watch_first_write(
        &self,
        chain: &[Arc<str>],
        leaf_kind: OutboundKind,
        stream: BoxStream,
    ) -> BoxStream {
        let counted = chain.iter().skip(1).any(|name| {
            matches!(
                self.table.get(name),
                Some(Entry::Group(group)) if matches!(
                    group.policy(),
                    Policy::UrlTest { .. } | Policy::Fallback | Policy::LoadBalance(_)
                )
            )
        });
        if !counted || !stream.needs_handshake() {
            return stream;
        }
        let me = self.me.clone();
        let chain = chain.to_vec();
        Box::new(FirstWrite::new(
            stream,
            Box::new(move |result| {
                let Some(outbounds) = me.upgrade() else {
                    return;
                };
                match result {
                    Ok(()) => outbounds.note_dial_succeeded(&chain),
                    Err(err) => outbounds.note_dial_failed(&chain, leaf_kind, Network::Tcp, err),
                }
            }),
        ))
    }

    pub(crate) fn note_dial_succeeded(&self, chain: &[Arc<str>]) {
        for name in chain.iter().skip(1) {
            if let Some(Entry::Group(group)) = self.table.get(name) {
                group.dial_succeeded();
            }
        }
    }

    fn dial_target(
        &self,
        name: &str,
        cx: &DialCx<'_>,
        dst: &Address,
        network: Network,
    ) -> io::Result<Dialed> {
        let flow = dummy_flow(dst.clone(), network);
        match self.resolve(name, &flow, dst.domain(), Touch::Yes) {
            Resolved::Route {
                leaf, chain, udp, ..
            } => {
                let leaf_name = leaf.info().name.clone();
                if cx.enter(&leaf_name).is_err() {
                    self.shared.report_loop(&leaf_name);
                    return Err(CoreError::DialerLoop(leaf_name.to_string()).into());
                }
                Ok((leaf, chain, udp))
            }
            Resolved::Pass | Resolved::PassRule => {
                Err(io::Error::other(format!("{name} cannot be dialed")))
            }
            Resolved::Rejected(_) => Err(CoreError::QuarantinedNode(name.to_string()).into()),
            Resolved::Unknown => Err(CoreError::UnknownNode(name.to_string()).into()),
        }
    }

    fn report_if_loop(&self, err: &io::Error) {
        if let Some(CoreError::DialerLoop(name)) = CoreError::of(err) {
            self.shared.report_loop(&Arc::from(name.as_str()));
        }
    }
}

fn ghost(name: &str, kind: &str, reason: &str) -> Arc<Ghost> {
    Arc::new(Ghost {
        name: Arc::from(name),
        kind: Arc::from(kind),
        reason: Arc::from(reason),
        provider: None,
    })
}

#[async_trait]
impl NodeDialer for Outbounds {
    async fn dial_via(&self, name: &str, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let (leaf, chain, _) = self.dial_target(name, cx, dst, Network::Tcp)?;
        let kind = leaf.info().kind;
        match leaf.connect(cx, dst).await {
            Ok(stream) => Ok(self.watch_first_write(&chain, kind, stream)),
            Err(err) => {
                self.report_if_loop(&err);
                self.note_dial_failed(&chain, kind, Network::Tcp, &err);
                Err(err)
            }
        }
    }

    async fn associate_via(
        &self,
        name: &str,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let (leaf, chain, udp) = self.dial_target(name, cx, hint, Network::Udp)?;
        if !udp {
            return Err(CoreError::UdpUnsupported(name.to_string()).into());
        }
        let result = leaf.associate(cx, hint).await;
        if let Err(err) = &result {
            self.report_if_loop(err);
            self.note_dial_failed(&chain, leaf.info().kind, Network::Udp, err);
        }
        result
    }
}
