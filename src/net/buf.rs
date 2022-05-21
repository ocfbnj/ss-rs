pub struct OwnedReadBuf {
    buf: Vec<u8>,
    offset: usize,
}

impl OwnedReadBuf {
    pub fn new(len: usize) -> Self {
        OwnedReadBuf {
            buf: vec![0; len],
            offset: 0,
        }
    }

    pub fn zero() -> Self {
        OwnedReadBuf::new(0)
    }

    pub fn is_full(&self) -> bool {
        self.buf.len() == self.offset
    }

    pub fn get(&self) -> &[u8] {
        &self.buf[..self.offset]
    }

    pub fn get_remaining_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..]
    }

    pub fn advance(&mut self, n: usize) {
        self.offset += n;
    }
}
