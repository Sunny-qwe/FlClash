use std::io;

use crate::error::invalid_data;

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if len > self.data.len() {
            return Err(invalid_data("truncated tls message"));
        }
        let (head, tail) = self.data.split_at(len);
        self.data = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> io::Result<u8> {
        match self.take(1)? {
            [value] => Ok(*value),
            _ => Err(invalid_data("truncated tls message")),
        }
    }

    pub(crate) fn u16(&mut self) -> io::Result<u16> {
        match self.take(2)? {
            [hi, lo] => Ok(u16::from_be_bytes([*hi, *lo])),
            _ => Err(invalid_data("truncated tls message")),
        }
    }

    pub(crate) fn u24(&mut self) -> io::Result<usize> {
        match self.take(3)? {
            [a, b, c] => Ok((usize::from(*a) << 16) | (usize::from(*b) << 8) | usize::from(*c)),
            _ => Err(invalid_data("truncated tls message")),
        }
    }

    pub(crate) fn vec8(&mut self) -> io::Result<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    pub(crate) fn vec16(&mut self) -> io::Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    pub(crate) fn vec24(&mut self) -> io::Result<&'a [u8]> {
        let len = self.u24()?;
        self.take(len)
    }
}

pub(crate) fn put_u24(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&[
        u8::try_from((value >> 16) & 0xff).unwrap_or(0),
        u8::try_from((value >> 8) & 0xff).unwrap_or(0),
        u8::try_from(value & 0xff).unwrap_or(0),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_refuses_to_overrun() {
        let mut cursor = Cursor::new(&[1, 0, 2, 0, 0, 3, 9, 9, 9]);
        assert_eq!(cursor.u8().unwrap(), 1);
        assert_eq!(cursor.u16().unwrap(), 2);
        assert_eq!(cursor.vec24().unwrap(), &[9, 9, 9]);
        assert!(cursor.is_empty());
        assert!(cursor.u8().is_err());
        assert!(Cursor::new(&[0, 0, 9, 1]).vec24().is_err());
    }
}
