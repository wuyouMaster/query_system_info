use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, watch, RwLock};
use tokio::task;

use super::ring::RingBuffer;

#[derive(Clone, serde::Serialize)]
pub struct MemorySample {
    pub pid: u32,
    pub timestamp: String,
    pub memory_bytes: u64,
}

#[derive(Clone, serde::Serialize)]
pub struct IoSample {
    pub pid: u32,
    pub timestamp: String,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Clone, serde::Serialize)]
pub struct CpuSample {
    pub pid: u32,
    pub timestamp: String,
    pub cpu_percent: f64,
}

pub struct TraceEntry {
    pub memory_samples: RingBuffer<MemorySample>,
    pub io_samples: RingBuffer<IoSample>,
    pub cpu_samples: RingBuffer<CpuSample>,
    pub subscribers: AtomicUsize,
    pub tracking: AtomicBool,
    pub cancel_tx: watch::Sender<bool>,
    pub event_tx: broadcast::Sender<TraceEvent>,
}

#[derive(Clone, serde::Serialize)]
pub struct TraceEvent {
    pub memory_sample: Option<MemorySample>,
    pub io_sample: Option<IoSample>,
    pub cpu_sample: Option<CpuSample>,
}

pub struct ProcessTraceCache {
    entries: RwLock<HashMap<u32, Arc<TraceEntry>>>,
    ring_capacity: usize,
}

impl ProcessTraceCache {
    pub fn new(ring_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
            ring_capacity,
        })
    }

    /// Get or create a TraceEntry for the given PID. Increments subscriber count.
    pub async fn get_or_subscribe(self: &Arc<Self>, pid: u32) -> Arc<TraceEntry> {
        {
            let entries = self.entries.read().await;
            if let Some(entry) = entries.get(&pid) {
                entry.subscribers.fetch_add(1, Ordering::Relaxed);
                return entry.clone();
            }
        }

        // Create new entry
        let mut entries = self.entries.write().await;
        // Double-check after acquiring write lock
        if let Some(entry) = entries.get(&pid) {
            entry.subscribers.fetch_add(1, Ordering::Relaxed);
            return entry.clone();
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (event_tx, _) = broadcast::channel(64);
        let entry = Arc::new(TraceEntry {
            memory_samples: RingBuffer::new(self.ring_capacity),
            io_samples: RingBuffer::new(self.ring_capacity),
            cpu_samples: RingBuffer::new(self.ring_capacity),
            subscribers: AtomicUsize::new(1),
            tracking: AtomicBool::new(false),
            cancel_tx,
            event_tx,
        });
        entries.insert(pid, entry.clone());
        drop(entries);

        // Start background tracking
        start_trace_task(pid, entry.clone(), cancel_rx);
        entry.tracking.store(true, Ordering::Relaxed);
        entry
    }

    /// Decrement subscriber count. If zero, stop tracking and remove entry.
    pub async fn unsubscribe(self: &Arc<Self>, pid: u32) {
        let should_remove = {
            let entries = self.entries.read().await;
            if let Some(entry) = entries.get(&pid) {
                let prev = entry.subscribers.fetch_sub(1, Ordering::Relaxed);
                prev <= 1 // was 1, now 0
            } else {
                false
            }
        };
        if should_remove {
            let mut entries = self.entries.write().await;
            if let Some(entry) = entries.remove(&pid) {
                let _ = entry.cancel_tx.send(true);
                entry.tracking.store(false, Ordering::Relaxed);
            }
        }
    }
}

fn start_trace_task(pid: u32, entry: Arc<TraceEntry>, mut cancel_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_rx.changed() => {
                    if *cancel_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(3)) => {}
            }
            if *cancel_rx.borrow() {
                break;
            }

            let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
            let entry_c = entry.clone();
            let ts_c = timestamp.clone();

            // Memory sample
            if let Ok(Ok(procs)) = task::spawn_blocking(query_system_info::process::list_processes)
                .await
            {
                if let Some(proc_info) = procs.into_iter().find(|p| p.pid == pid) {
                    let mem = MemorySample {
                        pid,
                        timestamp: ts_c.clone(),
                        memory_bytes: proc_info.memory_bytes,
                    };
                    entry_c.memory_samples.push(mem.clone());
                    let _ = entry_c.event_tx.send(TraceEvent {
                        memory_sample: Some(mem),
                        io_sample: None,
                        cpu_sample: None,
                    });
                }
            }

            // IO sample
            let entry_c2 = entry.clone();
            let ts_c2 = timestamp.clone();
            if let Ok(Ok(io)) =
                task::spawn_blocking(move || query_system_info::process::get_process_io(pid)).await
            {
                let sample = IoSample {
                    pid,
                    timestamp: ts_c2,
                    read_bytes: io.read_bytes,
                    write_bytes: io.write_bytes,
                };
                entry_c2.io_samples.push(sample.clone());
                let _ = entry_c2.event_tx.send(TraceEvent {
                    memory_sample: None,
                    io_sample: Some(sample),
                    cpu_sample: None,
                });
            }

            // CPU sample
            let entry_c3 = entry.clone();
            let ts_c3 = timestamp.clone();
            if let Ok(Ok(cpu)) = task::spawn_blocking(move || {
                query_system_info::process::get_process_cpu_usage(pid, Duration::from_millis(200))
            })
            .await
            {
                let sample = CpuSample {
                    pid,
                    timestamp: ts_c3,
                    cpu_percent: cpu,
                };
                entry_c3.cpu_samples.push(sample.clone());
                let _ = entry_c3.event_tx.send(TraceEvent {
                    memory_sample: None,
                    io_sample: None,
                    cpu_sample: Some(sample),
                });
            }
        }
    });
}
