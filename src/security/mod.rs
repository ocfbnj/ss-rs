use bloom::{BloomFilter, ASMS};
use spin::Mutex;

const EXPECTED_NUM_ITEMS: u32 = 1_000_000;

struct Bloom {
    filters: [BloomFilter; 2],
    current: usize,
    count: u32,
}

impl Bloom {
    fn new() -> Self {
        Bloom {
            filters: [
                BloomFilter::with_rate(1e-6, EXPECTED_NUM_ITEMS),
                BloomFilter::with_rate(1e-6, EXPECTED_NUM_ITEMS),
            ],
            current: 0,
            count: 0,
        }
    }

    fn check_and_insert(&mut self, element: &[u8]) -> bool {
        if self.filters.iter().any(|x| x.contains(&element)) {
            return false;
        }

        let filter = &mut self.filters[self.current];
        filter.insert(&element);

        self.count += 1;
        if self.count == EXPECTED_NUM_ITEMS {
            self.current = (self.current + 1) % 2;
            self.filters[self.current].clear();
        }

        true
    }
}

pub struct ReplayProtection {
    bloom: Mutex<Bloom>,
}

impl ReplayProtection {
    pub fn new() -> Self {
        ReplayProtection {
            bloom: Mutex::new(Bloom::new()),
        }
    }

    pub fn check_and_insert(&self, element: &[u8]) -> bool {
        self.bloom.lock().check_and_insert(&element)
    }
}
