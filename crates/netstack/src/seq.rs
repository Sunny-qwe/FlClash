use std::ops::{Add, Sub};

/// A TCP sequence number, compared modulo 2^32.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Seq(pub u32);

impl Seq {
    pub fn lt(self, other: Seq) -> bool {
        (self.0.wrapping_sub(other.0) as i32) < 0
    }

    pub fn le(self, other: Seq) -> bool {
        (self.0.wrapping_sub(other.0) as i32) <= 0
    }

    pub fn gt(self, other: Seq) -> bool {
        other.lt(self)
    }

    pub fn ge(self, other: Seq) -> bool {
        other.le(self)
    }

    pub fn max(self, other: Seq) -> Seq {
        if self.lt(other) { other } else { self }
    }

    pub fn min(self, other: Seq) -> Seq {
        if self.lt(other) { self } else { other }
    }

    /// Distance from `earlier` to `self`, zero when `self` is not after it.
    pub fn since(self, earlier: Seq) -> u32 {
        if self.le(earlier) {
            0
        } else {
            self.0.wrapping_sub(earlier.0)
        }
    }
}

impl Add<u32> for Seq {
    type Output = Seq;

    fn add(self, rhs: u32) -> Seq {
        Seq(self.0.wrapping_add(rhs))
    }
}

impl Sub<u32> for Seq {
    type Output = Seq;

    fn sub(self, rhs: u32) -> Seq {
        Seq(self.0.wrapping_sub(rhs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons_wrap() {
        let near_end = Seq(u32::MAX - 10);
        let wrapped = near_end + 20;
        assert!(near_end.lt(wrapped));
        assert!(wrapped.gt(near_end));
        assert_eq!(wrapped.since(near_end), 20);
        assert_eq!(near_end.since(wrapped), 0);
        assert_eq!(near_end.max(wrapped), wrapped);
    }
}
