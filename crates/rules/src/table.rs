use crate::kind::RuleKind;

/// Per-rule columns of one rule list. Payload text lives in a single arena.
#[derive(Default)]
pub(crate) struct RuleTable {
    kinds: Box<[RuleKind]>,
    targets: Box<[u16]>,
    offsets: Box<[u32]>,
    arena: Box<str>,
}

impl RuleTable {
    pub(crate) fn len(&self) -> usize {
        self.kinds.len()
    }

    pub(crate) fn kind(&self, idx: u32) -> Option<RuleKind> {
        self.kinds.get(idx as usize).copied()
    }

    pub(crate) fn target(&self, idx: u32) -> Option<u16> {
        self.targets.get(idx as usize).copied()
    }

    pub(crate) fn payload(&self, idx: u32) -> Option<&str> {
        let at = idx as usize;
        let start = *self.offsets.get(at)? as usize;
        let end = *self.offsets.get(at + 1)? as usize;
        self.arena.get(start..end)
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.kinds.len() + self.targets.len() * 2 + self.offsets.len() * 4 + self.arena.len()
    }
}

#[derive(Default)]
pub(crate) struct TableBuilder {
    kinds: Vec<RuleKind>,
    targets: Vec<u16>,
    offsets: Vec<u32>,
    arena: String,
}

impl TableBuilder {
    pub(crate) fn payload(&self, idx: u32) -> Option<&str> {
        let at = idx as usize;
        let start = *self.offsets.get(at)? as usize;
        let end = *self.offsets.get(at + 1)? as usize;
        self.arena.get(start..end)
    }

    pub(crate) fn push(&mut self, kind: RuleKind, target: u16, payload: &str) {
        if self.offsets.is_empty() {
            self.offsets.push(0);
        }
        self.kinds.push(kind);
        self.targets.push(target);
        self.arena.push_str(payload);
        self.offsets.push(self.arena.len() as u32);
    }

    pub(crate) fn finish(mut self) -> RuleTable {
        if self.offsets.is_empty() {
            self.offsets.push(0);
        }
        RuleTable {
            kinds: self.kinds.into_boxed_slice(),
            targets: self.targets.into_boxed_slice(),
            offsets: self.offsets.into_boxed_slice(),
            arena: self.arena.into_boxed_str(),
        }
    }
}
