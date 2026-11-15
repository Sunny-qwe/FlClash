use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

const NIL: usize = usize::MAX;

struct Node<K, V> {
    key: K,
    value: Option<V>,
    list: usize,
    prev: usize,
    next: usize,
}

fn get<const N: usize>(array: &[usize; N], index: usize) -> usize {
    array.get(index).copied().unwrap_or(NIL)
}

fn set<const N: usize>(array: &mut [usize; N], index: usize, value: usize) {
    if let Some(slot) = array.get_mut(index) {
        *slot = value;
    }
}

/// Several intrusive lists over one slab; front is most recent.
struct Lists<K, V, const N: usize> {
    nodes: Vec<Node<K, V>>,
    free: Vec<usize>,
    head: [usize; N],
    tail: [usize; N],
    len: [usize; N],
}

impl<K, V, const N: usize> Lists<K, V, N> {
    fn new() -> Self {
        Lists {
            nodes: Vec::new(),
            free: Vec::new(),
            head: [NIL; N],
            tail: [NIL; N],
            len: [0; N],
        }
    }

    fn node(&self, idx: usize) -> Option<&Node<K, V>> {
        self.nodes.get(idx)
    }

    fn node_mut(&mut self, idx: usize) -> Option<&mut Node<K, V>> {
        self.nodes.get_mut(idx)
    }

    fn alloc(&mut self, key: K, value: Option<V>) -> usize {
        let node = Node {
            key,
            value,
            list: N,
            prev: NIL,
            next: NIL,
        };
        match self.free.pop() {
            Some(idx) => {
                if let Some(slot) = self.nodes.get_mut(idx) {
                    *slot = node;
                }
                idx
            }
            None => {
                self.nodes.push(node);
                self.nodes.len() - 1
            }
        }
    }

    fn unlink(&mut self, idx: usize) {
        let Some(node) = self.node(idx) else { return };
        let (list, prev, next) = (node.list, node.prev, node.next);
        if list >= N {
            return;
        }
        match self.node_mut(prev) {
            Some(p) => p.next = next,
            None => set(&mut self.head, list, next),
        }
        match self.node_mut(next) {
            Some(n) => n.prev = prev,
            None => set(&mut self.tail, list, prev),
        }
        let len = get(&self.len, list).saturating_sub(1);
        set(&mut self.len, list, len);
        if let Some(node) = self.node_mut(idx) {
            node.list = N;
            node.prev = NIL;
            node.next = NIL;
        }
    }

    fn push_front(&mut self, list: usize, idx: usize) {
        self.unlink(idx);
        let old = get(&self.head, list);
        if let Some(node) = self.node_mut(idx) {
            node.list = list;
            node.prev = NIL;
            node.next = old;
        }
        match self.node_mut(old) {
            Some(o) => o.prev = idx,
            None => set(&mut self.tail, list, idx),
        }
        set(&mut self.head, list, idx);
        let len = get(&self.len, list) + 1;
        set(&mut self.len, list, len);
    }

    fn release(&mut self, idx: usize) -> Option<(K, Option<V>)>
    where
        K: Clone,
    {
        self.unlink(idx);
        let node = self.node_mut(idx)?;
        let key = node.key.clone();
        let value = node.value.take();
        self.free.push(idx);
        Some((key, value))
    }

    fn back(&self, list: usize) -> Option<usize> {
        Some(get(&self.tail, list)).filter(|idx| *idx != NIL)
    }

    fn clear(&mut self) {
        self.nodes.clear();
        self.free.clear();
        self.head = [NIL; N];
        self.tail = [NIL; N];
        self.len = [0; N];
    }
}

pub struct LruCache<K, V> {
    index: HashMap<K, usize>,
    lists: Lists<K, V, 1>,
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V> LruCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        LruCache {
            index: HashMap::new(),
            lists: Lists::new(),
            capacity,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = *self.index.get(key)?;
        self.lists.push_front(0, idx);
        self.lists.node(idx)?.value.as_ref()
    }

    #[cfg(test)]
    pub fn peek(&self, key: &K) -> Option<&V> {
        let idx = *self.index.get(key)?;
        self.lists.node(idx)?.value.as_ref()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.index.contains_key(key)
    }

    pub fn insert(&mut self, key: K, value: V) {
        if let Some(&idx) = self.index.get(&key) {
            if let Some(node) = self.lists.node_mut(idx) {
                node.value = Some(value);
            }
            self.lists.push_front(0, idx);
            return;
        }
        let idx = self.lists.alloc(key.clone(), Some(value));
        self.lists.push_front(0, idx);
        self.index.insert(key, idx);
        if self.capacity > 0
            && self.index.len() > self.capacity
            && let Some(old) = self.lists.back(0)
        {
            self.evict(old);
        }
    }

    fn evict(&mut self, idx: usize) {
        if let Some((key, _)) = self.lists.release(idx) {
            self.index.remove(&key);
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.index.remove(key)?;
        self.lists.release(idx)?.1
    }

    pub fn clear(&mut self) {
        self.index.clear();
        self.lists.clear();
    }

    pub fn entries_oldest_first(&self) -> Vec<(K, &V)> {
        let mut out = Vec::with_capacity(self.index.len());
        let mut cursor = self.lists.back(0);
        while let Some(idx) = cursor {
            let Some(node) = self.lists.node(idx) else {
                break;
            };
            if let Some(value) = node.value.as_ref() {
                out.push((node.key.clone(), value));
            }
            cursor = Some(node.prev).filter(|prev| *prev != NIL);
        }
        out
    }
}

const T1: usize = 0;
const B1: usize = 1;
const T2: usize = 2;
const B2: usize = 3;

/// Adaptive Replacement Cache; a ghost entry is a key without a value.
pub struct ArcCache<K, V> {
    index: HashMap<K, usize>,
    lists: Lists<K, V, 4>,
    capacity: usize,
    target: usize,
}

impl<K: Hash + Eq + Clone, V> ArcCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        ArcCache {
            index: HashMap::new(),
            lists: Lists::new(),
            capacity: capacity.max(1),
            target: 0,
        }
    }

    pub fn clear(&mut self) {
        self.index.clear();
        self.lists.clear();
        self.target = 0;
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lists.len[T1] + self.lists.len[T2]
    }

    pub fn get<Q>(&mut self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let idx = *self.index.get(key)?;
        self.lists.node(idx)?.value.as_ref()?;
        self.request(idx);
        self.lists.node(idx)?.value.as_ref()
    }

    pub fn insert(&mut self, key: K, value: V) {
        match self.index.get(&key).copied() {
            Some(idx) => {
                if let Some(node) = self.lists.node_mut(idx) {
                    node.value = Some(value);
                }
                self.request(idx);
            }
            None => {
                let idx = self.lists.alloc(key.clone(), Some(value));
                self.index.insert(key, idx);
                self.request(idx);
            }
        }
    }

    fn list_of(&self, idx: usize) -> usize {
        self.lists.node(idx).map(|node| node.list).unwrap_or(4)
    }

    fn drop_back(&mut self, list: usize) {
        if let Some(idx) = self.lists.back(list)
            && let Some((key, _)) = self.lists.release(idx)
        {
            self.index.remove(&key);
        }
    }

    fn demote(&mut self, from: usize, ghost: usize) {
        if let Some(idx) = self.lists.back(from) {
            if let Some(node) = self.lists.node_mut(idx) {
                node.value = None;
            }
            self.lists.push_front(ghost, idx);
        }
    }

    fn replace(&mut self, in_b2: bool) {
        let t1 = self.lists.len[T1];
        if t1 > 0 && (t1 > self.target || (in_b2 && t1 == self.target)) {
            self.demote(T1, B1);
        } else {
            self.demote(T2, B2);
        }
    }

    fn request(&mut self, idx: usize) {
        let [t1, b1, t2, b2] = self.lists.len;
        match self.list_of(idx) {
            T1 | T2 => self.lists.push_front(T2, idx),
            B1 => {
                let delta = if b1 >= b2 { 1 } else { b2 / b1.max(1) };
                self.target = (self.target + delta).min(self.capacity);
                self.replace(false);
                self.lists.push_front(T2, idx);
            }
            B2 => {
                let delta = if b2 >= b1 { 1 } else { b1 / b2.max(1) };
                self.target = self.target.saturating_sub(delta);
                self.replace(true);
                self.lists.push_front(T2, idx);
            }
            _ if t1 + b1 == self.capacity => {
                if t1 < self.capacity {
                    self.drop_back(B1);
                    self.replace(false);
                } else {
                    self.drop_back(T1);
                }
                self.lists.push_front(T1, idx);
            }
            _ if t1 + b1 < self.capacity => {
                let total = t1 + t2 + b1 + b2;
                if total >= self.capacity {
                    if total == 2 * self.capacity {
                        self.drop_back(B2);
                    }
                    self.replace(false);
                }
                self.lists.push_front(T1, idx);
            }
            _ => self.lists.push_front(T1, idx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_the_least_recently_used() {
        let mut cache = LruCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        assert_eq!(cache.get(&"a"), Some(&1));
        cache.insert("c", 3);
        assert!(cache.get(&"b").is_none());
        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"c"), Some(&3));
        assert_eq!(cache.remove(&"a"), Some(1));
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
        cache.insert("d", 4);
        assert_eq!(cache.peek(&"d"), Some(&4));
    }

    #[test]
    fn lru_peek_does_not_promote() {
        let mut cache = LruCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        assert_eq!(cache.peek(&"a"), Some(&1));
        cache.insert("c", 3);
        assert!(!cache.contains(&"a"));
    }

    #[test]
    fn arc_keeps_frequent_entries_over_a_scan() {
        let mut cache = ArcCache::new(4);
        for key in 0..2 {
            cache.insert(key, key);
            assert_eq!(cache.get(&key), Some(&key));
        }
        for key in 10..30 {
            cache.insert(key, key);
        }
        assert_eq!(cache.get(&0), Some(&0));
        assert_eq!(cache.get(&1), Some(&1));
        assert!(cache.len() <= 4);
    }

    #[test]
    fn arc_never_holds_more_than_its_capacity() {
        let mut cache = ArcCache::new(8);
        for round in 0..200u32 {
            let key = (round * 7) % 23;
            if cache.get(&key).is_none() {
                cache.insert(key, round);
            }
            assert!(cache.len() <= 8, "len {} at round {round}", cache.len());
        }
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
