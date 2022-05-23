/// The owned read buffer for internal uses.
pub struct OwnedReadBuf {
    buf: Vec<u8>,
    offset: usize,
}

impl OwnedReadBuf {
    /// Creates a new read buffer with the given size.
    pub fn new(len: usize) -> Self {
        OwnedReadBuf {
            buf: vec![0; len],
            offset: 0,
        }
    }

    /// Creates a new read buffer with zero buffer size.
    pub fn zero() -> Self {
        OwnedReadBuf::new(0)
    }

    /// Returns true if the read buffer is full.
    pub fn is_full(&self) -> bool {
        self.buf.len() == self.offset
    }

    /// Returns the filled buffer.
    pub fn get_filled(&self) -> &[u8] {
        &self.buf[..self.offset]
    }

    /// Returns the unfilled buffer.
    pub fn get_unfilled(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..]
    }

    /// Advances the read buffer by the given amount of bytes.
    pub fn advance(&mut self, n: usize) {
        self.offset += n;
    }
}
