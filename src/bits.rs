use std::marker::PhantomData;

/// The bit order.
/// It represents if the most significant bit or the least significant bit is 0.
pub trait BitOrder {}

/// Indicates the most significant bit is 0.
pub struct Msb0;

impl BitOrder for Msb0 {}

/// Indicates the least significant bit is 0.
pub struct Lsb0;

impl BitOrder for Lsb0 {}

/// Represents a bit array.
pub struct Bits<'a, O: BitOrder> {
    data: &'a [u8],
    max_len: usize,
    _byte_order: PhantomData<O>,
}

impl<'a, O: BitOrder> Bits<'a, O> {
    pub fn with_max_len(data: &'a [u8], max_len: usize) -> Self {
        Bits {
            data,
            max_len,
            _byte_order: PhantomData,
        }
    }

    /// Returns an iterator over the bits.
    pub fn iter(&self) -> BitsIter<O> {
        BitsIter {
            bits: self,
            cur: 0,
            end: self.max_len,
        }
    }
}

impl<'a> Bits<'a, Msb0> {
    /// Get the bit in the bits.
    ///
    /// Returns true if the bit is 1, otherwise returns false.
    pub fn get(&self, n: usize) -> bool {
        assert!(n < self.max_len);

        let bank_size = u8::BITS as usize;
        let bank = n / bank_size;
        let offset = n % bank_size;

        ((self.data[bank] >> (bank_size - 1 - offset)) & 1) == 1
    }
}

impl<'a> Bits<'a, Lsb0> {
    /// Get the bit in the bits.
    ///
    /// Returns true if the bit is 1, otherwise returns false.
    pub fn get(&self, n: usize) -> bool {
        assert!(n < self.max_len);

        let bank_size = u8::BITS as usize;
        let bank = n / bank_size;
        let offset = n % bank_size;

        ((self.data[bank] >> offset) & 1) == 1
    }
}

impl<'a, O: BitOrder> From<&'a [u8]> for Bits<'a, O> {
    fn from(data: &'a [u8]) -> Self {
        Bits {
            data,
            max_len: u8::BITS as usize * data.len(),
            _byte_order: PhantomData,
        }
    }
}

/// An iterator over the Bits.
pub struct BitsIter<'a, O: BitOrder> {
    bits: &'a Bits<'a, O>,
    cur: usize,
    end: usize,
}

impl<'a> Iterator for BitsIter<'a, Msb0> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == self.end {
            None
        } else {
            let ret = Some(self.bits.get(self.cur));
            self.cur += 1;

            ret
        }
    }
}

impl<'a> Iterator for BitsIter<'a, Lsb0> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == self.end {
            None
        } else {
            let ret = Some(self.bits.get(self.cur));
            self.cur += 1;

            ret
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_msb0() {
        let array: [u8; 3] = [0b0000_1111, 0b1110_0101, 0b1111_0000];
        let expected = [
            false, false, false, false, true, true, true, true, true, true, true, false, false,
            true, false, true, true, true, true, true, false, false, false, false,
        ];

        let bits = Bits::<Msb0>::from(array.as_slice());
        for i in 0..array.len() * u8::BITS as usize {
            assert_eq!(bits.get(i), expected[i]);
        }
    }

    #[test]
    fn test_bits_lsb0() {
        let array: [u8; 3] = [0b0000_1111, 0b1110_0101, 0b1111_0000];
        let expected = [
            true, true, true, true, false, false, false, false, true, false, true, false, false,
            true, true, true, false, false, false, false, true, true, true, true,
        ];

        let bits = Bits::<Lsb0>::from(array.as_slice());
        for i in 0..array.len() * u8::BITS as usize {
            assert_eq!(bits.get(i), expected[i]);
        }
    }

    #[test]
    fn test_bits_iter() {
        let array: [u8; 1] = [0b1011_0101];
        let bits = Bits::<Msb0>::from(array.as_slice());

        let expected = [true, false, true, true, false, true, false, true];

        for (i, b) in bits.iter().enumerate() {
            assert_eq!(b, expected[i]);
        }
    }
}
