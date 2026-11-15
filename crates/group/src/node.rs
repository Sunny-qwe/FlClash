use std::sync::Arc;

use concord_common::{Outbound, OutboundInfo};

use crate::group::Group;
use crate::health::NodeHealth;

/// A proxy the core builds a connection from, with the results of its tests.
pub struct Leaf {
    outbound: Arc<dyn Outbound>,
    provider: Option<Arc<str>>,
    health: NodeHealth,
}

impl Leaf {
    pub fn new(outbound: Arc<dyn Outbound>, provider: Option<Arc<str>>) -> Arc<Leaf> {
        Arc::new(Leaf {
            outbound,
            provider,
            health: NodeHealth::default(),
        })
    }

    pub fn outbound(&self) -> &Arc<dyn Outbound> {
        &self.outbound
    }

    pub fn info(&self) -> &OutboundInfo {
        self.outbound.info()
    }

    pub fn name(&self) -> &Arc<str> {
        &self.outbound.info().name
    }

    pub fn provider(&self) -> Option<&Arc<str>> {
        self.provider.as_ref()
    }

    pub fn health(&self) -> &NodeHealth {
        &self.health
    }
}

/// A node the core dropped as unsupported. It keeps its name so that anything
/// still pointing at it is refused, and so that a group knows it lost a member.
#[derive(Debug)]
pub struct Ghost {
    pub name: Arc<str>,
    pub kind: Arc<str>,
    pub reason: Arc<str>,
    pub provider: Option<Arc<str>>,
}

/// A place in a member list: a node that works or one the core dropped.
#[derive(Clone)]
pub enum Item {
    Live(Node),
    Ghost(Arc<Ghost>),
}

impl Item {
    pub fn name(&self) -> &Arc<str> {
        match self {
            Item::Live(node) => node.name(),
            Item::Ghost(ghost) => &ghost.name,
        }
    }

    pub fn type_name(&self) -> &str {
        match self {
            Item::Live(node) => node.type_name(),
            Item::Ghost(ghost) => &ghost.kind,
        }
    }
}

#[derive(Clone)]
pub enum Node {
    Leaf(Arc<Leaf>),
    Group(Arc<Group>),
}

impl Node {
    pub fn name(&self) -> &Arc<str> {
        match self {
            Node::Leaf(leaf) => leaf.name(),
            Node::Group(group) => group.name(),
        }
    }

    /// The spelling the host compares: `Shadowsocks`, `Selector` and so on.
    pub fn type_name(&self) -> &'static str {
        match self {
            Node::Leaf(leaf) => leaf.info().kind.wire_name(),
            Node::Group(group) => group.type_name(),
        }
    }

    pub fn health(&self) -> &NodeHealth {
        match self {
            Node::Leaf(leaf) => leaf.health(),
            Node::Group(group) => group.health(),
        }
    }

    pub fn same(&self, other: &Node) -> bool {
        match (self, other) {
            (Node::Leaf(a), Node::Leaf(b)) => Arc::ptr_eq(a, b),
            (Node::Group(a), Node::Group(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    pub fn provider(&self) -> Option<&Arc<str>> {
        match self {
            Node::Leaf(leaf) => leaf.provider(),
            Node::Group(_) => None,
        }
    }
}
