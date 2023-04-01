pub struct Buffer {
    data: Vec<u8>,
    pos: usize,
    len: usize,
}

impl Buffer {
    pub fn new(size: usize) -> Buffer {
        let data = Vec::with_capacity(size);
        Buffer {
            data,
            pos: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn size(&self) -> usize {
        self.data.capacity()
    }

    pub fn incrlen(&mut self, incr: usize) {
        if self.len + incr >= self.size() {
            panic!("Buffer: bad increase");
        }
        self.len += incr
    }

    pub fn putbyte(&mut self, val: u8) {
        if self.pos >= self.len {
            self.data.push(val);
            self.incrlen(1);
        } else {
            self.data[self.pos] = val;
        }
        self.pos += 1;
    }

    pub fn getbyte(&mut self) -> u8 {
        if self.pos >= self.len {
            panic!("Buffer: bad getbyte");
        }
        let val = self.data[self.pos];
        self.pos += 1;
        val
    }

    pub fn putbytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.putbyte(*byte);
        }
    }

    pub fn putbool(&mut self, val: bool) {
        self.putbyte(val as u8);
    }

    pub fn getbool(&mut self) -> bool {
        self.getbyte() != 0
    }

    pub fn putint(&mut self, val: u32) {
        self.putbytes(&val.to_be_bytes());
    }

    pub fn getint(&mut self) -> u32 {
        unimplemented!();
    }

    pub fn putstring(&mut self, val: String) {
        unimplemented!();
    }

    pub fn getstring(&mut self) -> String {
        unimplemented!();
    }
}
