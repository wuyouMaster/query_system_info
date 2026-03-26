use std::sync::Arc;
use std::time::Duration;
use tokio::task;

use super::ring::RingBuffer;

pub struct CpuUsageCache {
    pub samples: RingBuffer<Vec<f64>>,
}

impl CpuUsageCache {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            samples: RingBuffer::new(capacity),
        })
    }

    /// Spawn a background task that samples CPU usage every `interval_ms` milliseconds.
    pub fn start_sampling(self: &Arc<Self>, interval_ms: u64) {
        let cache = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
                let c = cache.clone();
                task::spawn_blocking(move || {
                    let sample_dur = Duration::from_millis(200);
                    if let Ok(usage) = query_system_info::cpu::get_cpu_usage(sample_dur) {
                        c.samples.push(usage);
                    }
                });
            }
        });
    }
}
