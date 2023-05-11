use core::panic;
use std::ops::{Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo, RangeToInclusive};

use num_bigint::BigUint;
use num_traits::Zero;

#[derive(Clone)]
pub struct SSHBuffer {
    data: Vec<u8>,
    pos: usize,
    len: usize,
}

impl SSHBuffer {
    pub fn new(size: usize) -> Self {
        let data = vec![0u8; size];
        Self {
            data,
            pos: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn size(&self) -> usize {
        self.data.capacity()
    }

    pub fn resize(&mut self, size: usize) {
        self.data.resize(size, 0);
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    pub fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn incr_pos(&mut self, incr: usize) {
        if self.pos + incr > self.len {
            panic!("sshbuffer: bad pos increase");
        }
        self.pos += incr;
    }

    pub fn incr_write_pos(&mut self, incr: usize) {
        if self.pos + incr > self.size() {
            panic!("sshbuffer: bad incrwritepos");
        }
        self.pos += incr;
        if self.pos > self.len {
            self.len = self.pos;
        }
    }

    pub fn incr_len(&mut self, incr: usize) {
        if self.len + incr > self.size() {
            panic!("Buffer: bad increase");
        }
        self.len += incr
    }

    pub fn put_byte(&mut self, val: u8) {
        if self.pos >= self.len {
            self.incr_len(1);
        }
        self.data[self.pos] = val;
        self.pos += 1;
    }

    pub fn get_byte(&mut self) -> u8 {
        if self.pos >= self.len {
            panic!("Buffer: bad getbyte");
        }
        let val = self.data[self.pos];
        self.pos += 1;
        val
    }

    pub fn put_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.put_byte(*byte);
        }
    }

    pub fn get_bytes(&mut self, length: usize) -> &[u8] {
        let bytes = &self.data[self.pos..(self.pos + length)];
        self.pos += length;
        bytes
    }

    pub fn put_bool(&mut self, val: bool) {
        self.put_byte(val as u8);
    }

    pub fn get_bool(&mut self) -> bool {
        self.get_byte() != 0
    }

    pub fn put_int(&mut self, val: u32) {
        self.put_bytes(&val.to_be_bytes());
    }

    pub fn get_int(&mut self) -> u32 {
        let val = u32::from_be_bytes(self.data[self.pos..(self.pos + 4)].try_into().unwrap());
        self.pos += 4;
        val
    }

    pub fn put_string(&mut self, val: &[u8], len: usize) {
        self.put_int(len as u32);
        self.put_bytes(val);
    }

    pub fn get_string(&mut self) -> (Vec<u8>, usize) {
        let length = self.get_int();
        // TODO: check for max len string
        let bytes = self.get_bytes(length as usize);
        let mut string = Vec::new();
        string.extend_from_slice(bytes);
        (string, length as usize)
    }

    pub fn put_mpint(&mut self, value: &BigUint) {
        let value_bytes = value.to_bytes_be();
        let mut value_len = value_bytes.len();
        let zero: BigUint = Zero::zero();
        if *value == zero {
            self.put_string("".as_bytes(), 0);
            return;
        }

        if value_bytes.first().unwrap() & 0x80 != 0 {
            value_len += 1;
            self.put_int(value_len as u32);
            self.put_byte(0);
            self.put_bytes(&value_bytes);
        } else {
            self.put_string(&value_bytes, value_len);
        }
    }

    pub fn get_mpint(&mut self) -> BigUint {
        let (val, len) = self.get_string();
        if len == 0 {
            return Zero::zero();
        }

        if *val.first().unwrap() == 0xFF {
            panic!("Unexpected negative value");
        }

        BigUint::from_bytes_be(&val)
    }
}

impl std::fmt::Debug for SSHBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.data)
    }
}

impl Index<RangeFull> for SSHBuffer {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &Self::Output {
        &self.data[self.pos..self.len]
    }
}

impl Index<RangeTo<usize>> for SSHBuffer {
    type Output = [u8];
    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        if index.end > self.len {
            panic!("SSHBuffer: Out of bounds read");
        }
        &self.data[self.pos..self.pos + index.end]
    }
}

impl Index<RangeToInclusive<usize>> for SSHBuffer {
    type Output = [u8];
    fn index(&self, index: RangeToInclusive<usize>) -> &Self::Output {
        if index.end >= self.len {
            panic!("SSHBuffer: Out of bounds read");
        }
        &self.data[self.pos..=self.pos + index.end]
    }
}

impl Index<Range<usize>> for SSHBuffer {
    type Output = [u8];
    fn index(&self, index: Range<usize>) -> &Self::Output {
        if index.start >= self.len || index.end > self.len {
            panic!("SSHBuffer: Out of bounds read");
        }
        &self.data[index]
    }
}

impl Index<RangeFrom<usize>> for SSHBuffer {
    type Output = [u8];
    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        if index.start > self.len {
            panic!("SSHBuffer: Out of bounds read")
        }
        &self.data[index.start..self.pos + self.len]
    }
}

impl IndexMut<RangeFull> for SSHBuffer {
    fn index_mut(&mut self, _index: RangeFull) -> &mut Self::Output {
        &mut self.data[self.pos..self.len]
    }
}

impl IndexMut<RangeTo<usize>> for SSHBuffer {
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut Self::Output {
        if index.end > self.size() {
            panic!("SSHBuffer: Out of bounds write");
        }
        &mut self.data[self.pos..self.pos + index.end]
    }
}

impl IndexMut<RangeToInclusive<usize>> for SSHBuffer {
    fn index_mut(&mut self, index: RangeToInclusive<usize>) -> &mut Self::Output {
        if index.end >= self.size() {
            panic!("SSHBuffer: Out of bounds write");
        }
        &mut self.data[self.pos..=self.pos + index.end]
    }
}

impl IndexMut<Range<usize>> for SSHBuffer {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        if index.start >= self.size() || index.end > self.size() {
            panic!("SSHBuffer: Out of bounds write");
        }
        &mut self.data[index]
    }
}

impl IndexMut<RangeFrom<usize>> for SSHBuffer {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut Self::Output {
        if index.start > self.size() {
            panic!("SSHBuffer: Out of bounds read")
        }
        &mut self.data[index.start..self.pos + self.len]
    }
}
