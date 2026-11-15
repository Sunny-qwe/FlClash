use std::collections::HashMap;
use std::sync::Arc;

use crate::node::{Ghost, Item, Leaf, Node};

/// What a provider holds right now. A new content gives a new value with the
/// next version, so a reader never sees half of an update.
pub struct ProviderNodes {
    version: u32,
    items: Vec<Item>,
    live: HashMap<Arc<str>, Arc<Leaf>>,
    ghosts: HashMap<Arc<str>, Arc<Ghost>>,
}

impl ProviderNodes {
    pub fn new(version: u32, items: Vec<Item>) -> Self {
        let mut live = HashMap::new();
        let mut ghosts = HashMap::new();
        for item in &items {
            match item {
                Item::Live(Node::Leaf(leaf)) => {
                    live.entry(leaf.name().clone())
                        .or_insert_with(|| leaf.clone());
                }
                Item::Live(Node::Group(_)) => {}
                Item::Ghost(ghost) => {
                    ghosts
                        .entry(ghost.name.clone())
                        .or_insert_with(|| ghost.clone());
                }
            }
        }
        ProviderNodes {
            version,
            items,
            live,
            ghosts,
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&Arc<Leaf>> {
        self.live.get(name)
    }

    pub fn ghost(&self, name: &str) -> Option<&Arc<Ghost>> {
        self.ghosts.get(name)
    }

    pub fn ghosts(&self) -> impl Iterator<Item = &Arc<Ghost>> {
        self.items.iter().filter_map(|item| match item {
            Item::Ghost(ghost) => Some(ghost),
            Item::Live(_) => None,
        })
    }
}
