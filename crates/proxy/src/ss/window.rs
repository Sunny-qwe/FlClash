/// Blocks of 64 ids in the ring; the window behind the newest id is one block short of it.
const RING_BLOCKS: usize = 128;

/// The packet ids of one Shadowsocks 2022 server session that were accepted, as
/// sing-shadowsocks2 `shadowaead_2022/slidingwindow.go` keeps them: each id passes once, and
/// none further behind the newest than the window.
pub(crate) struct SlidingWindow {
    last: u64,
    ring: [u64; RING_BLOCKS],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        SlidingWindow {
            last: 0,
            ring: [0; RING_BLOCKS],
        }
    }
}

fn block_of(id: u64) -> u64 {
    id / u64::from(u64::BITS)
}

fn bit_of(id: u64) -> u64 {
    1 << (id % u64::from(u64::BITS))
}

fn slot(block: u64) -> usize {
    (block % RING_BLOCKS as u64) as usize
}

fn window() -> u64 {
    (RING_BLOCKS as u64 - 1) * u64::from(u64::BITS)
}

impl SlidingWindow {
    pub(crate) fn check(&self, id: u64) -> bool {
        if id > self.last {
            return true;
        }
        if self.last - id > window() {
            return false;
        }
        self.ring
            .get(slot(block_of(id)))
            .is_some_and(|bits| bits & bit_of(id) == 0)
    }

    /// Records `id`, which [`check`](Self::check) accepted.
    pub(crate) fn add(&mut self, id: u64) {
        let block = block_of(id);
        if id > self.last {
            let last = block_of(self.last);
            for passed in last + 1..=block.min(last + RING_BLOCKS as u64) {
                if let Some(bits) = self.ring.get_mut(slot(passed)) {
                    *bits = 0;
                }
            }
            self.last = id;
        }
        if let Some(bits) = self.ring.get_mut(slot(block)) {
            *bits |= bit_of(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(window: &mut SlidingWindow, id: u64) -> bool {
        let fresh = window.check(id);
        if fresh {
            window.add(id);
        }
        fresh
    }

    #[test]
    fn each_id_passes_once_in_any_order() {
        let mut window = SlidingWindow::default();
        for id in [0, 2, 1, 5, 3] {
            assert!(accept(&mut window, id), "{id}");
        }
        for id in [0, 1, 2, 3, 5] {
            assert!(!accept(&mut window, id), "{id}");
        }
        assert!(accept(&mut window, 4));
    }

    #[test]
    fn an_id_older_than_the_window_is_refused() {
        let mut window = SlidingWindow::default();
        assert!(accept(&mut window, super::window() + 10));
        assert!(!accept(&mut window, 9));
        assert!(accept(&mut window, 10));
    }

    #[test]
    fn a_jump_ahead_forgets_the_blocks_it_passes() {
        let mut window = SlidingWindow::default();
        assert!(accept(&mut window, 64));
        let far = 64 + RING_BLOCKS as u64 * 64;
        assert!(accept(&mut window, far));
        assert!(!accept(&mut window, far));
        assert!(accept(&mut window, far - 1));
    }
}
