#[derive(Default)]
pub(super) struct Bitmap {
    words: Vec<u64>,
}

impl Bitmap {
    /// Sets every bit in `[start, end)`; an empty or inverted range is ignored.
    pub(super) fn set_range(&mut self, start: usize, end: usize) {
        if end <= start {
            return;
        }
        let word_count = (end - 1) / 64 + 1;
        if word_count > self.words.len() {
            self.words.resize(word_count.next_power_of_two(), 0);
        }

        let first_word = start / 64;
        let last_word = (end - 1) / 64;
        let first_mask = u64::MAX << (start % 64);
        let last_mask = match end % 64 {
            0 => u64::MAX,
            end_bit => (1u64 << end_bit) - 1,
        };
        if first_word == last_word {
            if let Some(word) = self.words.get_mut(first_word) {
                *word |= first_mask & last_mask;
            }
            return;
        }
        if let Some(word) = self.words.get_mut(first_word) {
            *word |= first_mask;
        }
        if let Some(middle) = self.words.get_mut(first_word + 1..last_word) {
            middle.fill(u64::MAX);
        }
        if let Some(word) = self.words.get_mut(last_word) {
            *word |= last_mask;
        }
    }

    /// The first unset bit in `[start, end)`, or `end` when all of them are set.
    pub(super) fn first_unset(&self, start: usize, end: usize) -> usize {
        if end <= start {
            return end.max(start);
        }
        let mut index = start / 64;
        let Some(&first) = self.words.get(index) else {
            return start;
        };
        let mut word = first | ((1u64 << (start % 64)) - 1);
        loop {
            if word != u64::MAX {
                let unset = index * 64 + (!word).trailing_zeros() as usize;
                return unset.min(end);
            }
            index += 1;
            if index * 64 >= end {
                return end;
            }
            match self.words.get(index) {
                Some(&next) => word = next,
                None => return index * 64,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_value() {
        let coverage = Bitmap::default();
        assert_eq!(coverage.first_unset(0, 128), 0);
        assert_eq!(coverage.first_unset(0, 0), 0);
    }

    #[test]
    fn single_word() {
        let mut coverage = Bitmap::default();
        coverage.set_range(1, 5);
        assert_eq!(coverage.first_unset(0, 5), 0);
        assert_eq!(coverage.first_unset(1, 5), 5);
        assert_eq!(coverage.first_unset(1, 6), 5);
    }

    #[test]
    fn cross_word() {
        let mut coverage = Bitmap::default();
        coverage.set_range(1, 130);
        assert_eq!(coverage.first_unset(1, 130), 130);
        assert_eq!(coverage.first_unset(1, 131), 130);
    }

    #[test]
    fn one_bit_gap() {
        let mut coverage = Bitmap::default();
        coverage.set_range(0, 64);
        coverage.set_range(65, 130);
        assert_eq!(coverage.first_unset(0, 130), 64);
    }

    #[test]
    fn overlap_survives_growth() {
        let mut coverage = Bitmap::default();
        coverage.set_range(0, 10);
        coverage.set_range(64, 70);
        coverage.set_range(8, 65);
        assert_eq!(coverage.first_unset(0, 71), 70);
    }

    #[test]
    fn inverted_ranges_are_ignored_instead_of_panicking() {
        let mut coverage = Bitmap::default();
        coverage.set_range(1, 0);
        coverage.set_range(5, 5);
        assert_eq!(coverage.first_unset(0, 8), 0);
        assert_eq!(coverage.first_unset(4, 2), 4);
    }

    #[test]
    fn full_words_are_skipped() {
        let mut coverage = Bitmap::default();
        coverage.set_range(0, 64 * 40);
        assert_eq!(coverage.first_unset(0, 64 * 41), 64 * 40);
        assert_eq!(coverage.first_unset(3, 64 * 40), 64 * 40);
    }
}
