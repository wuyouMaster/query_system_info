use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

/// Fixed-capacity ring buffer with concurrent read/write support.
///
/// When full, the oldest entry is overwritten. Reads acquire a read lock
/// (no contention with other readers). Writes acquire a write lock briefly.
pub struct RingBuffer<T: Clone> {
    buf: RwLock<Vec<Option<T>>>,
    capacity: usize,
    write_pos: AtomicUsize,
    count: AtomicUsize,
}

impl<T: Clone> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "RingBuffer capacity must be > 0");
        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, || None);
        Self {
            buf: RwLock::new(buf),
            capacity,
            write_pos: AtomicUsize::new(0),
            count: AtomicUsize::new(0),
        }
    }

    /// Push a new item, overwriting the oldest if full.
    pub fn push(&self, item: T) {
        let pos = self.write_pos.fetch_add(1, Ordering::Relaxed) % self.capacity;
        {
            let mut guard = self.buf.write().unwrap();
            guard[pos] = Some(item);
        }
        let prev = self.count.fetch_add(1, Ordering::Relaxed);
        if prev >= self.capacity {
            self.count.store(self.capacity, Ordering::Relaxed);
        }
    }

    /// Get the most recent item.
    pub fn latest(&self) -> Option<T> {
        let guard = self.buf.read().unwrap();
        let c = self.count.load(Ordering::Relaxed);
        if c == 0 {
            return None;
        }
        let last_write =
            (self.write_pos.load(Ordering::Relaxed) + self.capacity - 1) % self.capacity;
        guard[last_write].clone()
    }

    /// Get the last `n` items in chronological order.
    pub fn last_n(&self, n: usize) -> Vec<T> {
        let guard = self.buf.read().unwrap();
        let c = self.count.load(Ordering::Relaxed);
        let take = n.min(c);
        if take == 0 {
            return Vec::new();
        }
        let wp = self.write_pos.load(Ordering::Relaxed);
        let start = if c < self.capacity {
            // Not yet full — data is at indices 0..c
            c.saturating_sub(take)
        } else {
            // Full — oldest element is at write_pos % capacity
            let oldest = wp % self.capacity;
            (oldest + self.capacity - take) % self.capacity
        };
        let mut result = Vec::with_capacity(take);
        for i in 0..take {
            let idx = (start + i) % self.capacity;
            if let Some(ref item) = guard[idx] {
                result.push(item.clone());
            }
        }
        result
    }

    /// Number of items currently stored (0..=capacity).
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed).min(self.capacity)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_and_latest() {
        let rb = RingBuffer::new(3);
        assert!(rb.latest().is_none());
        rb.push(10);
        assert_eq!(rb.latest(), Some(10));
        rb.push(20);
        assert_eq!(rb.latest(), Some(20));
    }

    #[test]
    fn test_wrap_around() {
        let rb = RingBuffer::new(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        assert_eq!(rb.latest(), Some(3));
        rb.push(4);
        assert_eq!(rb.latest(), Some(4));
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.last_n(3), vec![2, 3, 4]);
    }

    #[test]
    fn test_last_n_partial() {
        let rb = RingBuffer::new(5);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        assert_eq!(rb.last_n(2), vec![2, 3]);
        assert_eq!(rb.last_n(10), vec![1, 2, 3]);
    }

    #[test]
    fn test_last_n_after_wrap() {
        let rb = RingBuffer::new(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        rb.push(4);
        rb.push(5);
        assert_eq!(rb.last_n(3), vec![3, 4, 5]);
    }
}
