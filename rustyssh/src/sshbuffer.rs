pub struct SSHBuffer {
    data: Vec<u8>,
    pos: usize,
    len: usize,
}

impl SSHBuffer {
    pub fn new(size: usize) -> Self {
        let data = Vec::with_capacity(size);
        Self {
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

    pub fn pos(&self) -> usize {
        self.pos
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

    pub fn incr_len(&mut self, incr: usize) {
        if self.len + incr > self.size() {
            panic!("Buffer: bad increase");
        }
        self.len += incr
    }

    pub fn get_slice(&mut self) -> &[u8] {
        &self.data[self.pos..]
    }

    pub fn put_byte(&mut self, val: u8) {
        if self.pos >= self.len {
            self.data.push(val);
            self.incr_len(1);
        } else {
            self.data[self.pos] = val;
        }
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
        string.push(0x00);
        (string, length as usize)
    }
}
