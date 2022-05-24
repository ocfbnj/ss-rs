/// The owned read buffer for internal uses.
pub(crate) struct OwnedReadBuf {
    buf: Vec<u8>,
    offset: usize,
    capacity: usize,
}

impl OwnedReadBuf {
    /// Creates a new read buffer with zero buffer size.
    pub fn new() -> Self {
        OwnedReadBuf {
            buf: Vec::new(),
            offset: 0,
            capacity: 0,
        }
    }

    /// Returns true if the read buffer is full.
    pub fn is_full(&self) -> bool {
        self.offset == self.capacity
    }

    /// Returns the capacity of the read buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the remaining size of the read buffer.
    pub fn remaining(&self) -> usize {
        self.capacity - self.offset
    }

    /// Returns the filled buffer.
    pub fn filled(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr(), self.offset) }
    }

    /// Returns the uninitialized buffer.
    pub fn uninitialized_mut(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self.buf.as_mut_ptr().add(self.offset),
                self.remaining(),
            )
        }
    }

    /// Advances the filled buffer by the given amount of bytes.
    pub fn add_filled(&mut self, n: usize) {
        self.offset += n;
    }

    /// Requests a brand new unfilled buffer with the given amount of bytes.
    pub fn require(&mut self, n: usize) {
        assert!(self.buf.is_empty());

        self.buf.reserve(n);
        self.offset = 0;
        self.capacity = n;
    }
}
