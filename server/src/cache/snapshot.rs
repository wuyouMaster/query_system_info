use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::task;

use super::ring::RingBuffer;
use crate::api::snapshot::{
    ConnectionResponse, CpuInfoResponse, DiskResponse, MemoryResponse, ProcessResponse,
    SocketSummaryResponse,
};

pub struct SnapshotCache {
    pub memory: RingBuffer<MemoryResponse>,
    pub cpu_info: RwLock<Option<CpuInfoResponse>>,
    pub disks: RingBuffer<Vec<DiskResponse>>,
    pub processes: RingBuffer<Vec<ProcessResponse>>,
    pub sockets: RingBuffer<SocketSummaryResponse>,
    pub connections: RingBuffer<Vec<ConnectionResponse>>,
}

impl SnapshotCache {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            memory: RingBuffer::new(capacity),
            cpu_info: RwLock::new(None),
            disks: RingBuffer::new(capacity),
            processes: RingBuffer::new(capacity),
            sockets: RingBuffer::new(capacity),
            connections: RingBuffer::new(capacity),
        })
    }

    /// Spawn background tasks that periodically refresh all snapshot data.
    pub fn start_refresh(self: &Arc<Self>, interval_ms: u64) {
        let cache = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;

                let c = cache.clone();
                task::spawn_blocking(move || {
                    if let Ok(mem) = query_system_info::memory::get_memory_info() {
                        c.memory.push(MemoryResponse {
                            total: mem.total,
                            available: mem.available,
                            used: mem.used,
                            free: mem.free,
                            usage_percent: mem.usage_percent,
                            swap_total: mem.swap_total,
                            swap_used: mem.swap_used,
                            swap_free: mem.swap_free,
                            cached: mem.cached,
                            buffers: mem.buffers,
                        });
                    }
                });

                let c = cache.clone();
                task::spawn_blocking(move || {
                    if let Ok(disks) = query_system_info::disk::get_disks() {
                        let resp: Vec<DiskResponse> = disks
                            .into_iter()
                            .map(|d| DiskResponse {
                                device: d.device,
                                mount_point: d.mount_point,
                                fs_type: d.fs_type,
                                total_bytes: d.total_bytes,
                                used_bytes: d.used_bytes,
                                available_bytes: d.available_bytes,
                                usage_percent: d.usage_percent,
                            })
                            .collect();
                        c.disks.push(resp);
                    }
                });

                let c = cache.clone();
                task::spawn_blocking(move || {
                    if let Ok(procs) = query_system_info::process::list_processes() {
                        let resp: Vec<ProcessResponse> = procs
                            .into_iter()
                            .map(|p| ProcessResponse {
                                pid: p.pid,
                                ppid: p.ppid,
                                name: p.name,
                                exe_path: p.exe_path,
                                cmdline: p.cmdline,
                                state: p.state.to_string(),
                                memory_bytes: p.memory_bytes,
                                virtual_memory: p.virtual_memory,
                                cpu_percent: p.cpu_percent,
                                threads: p.threads,
                                start_time: p.start_time,
                                username: p.username,
                            })
                            .collect();
                        c.processes.push(resp);
                    }
                });

                let c = cache.clone();
                task::spawn_blocking(move || {
                    if let Ok(summary) = query_system_info::socket::get_socket_summary() {
                        c.sockets.push(SocketSummaryResponse {
                            total: summary.total,
                            established: summary.established,
                            listen: summary.listen,
                            time_wait: summary.time_wait,
                            close_wait: summary.close_wait,
                        });
                    }
                });

                let c = cache.clone();
                task::spawn_blocking(move || {
                    if let Ok(all) = query_system_info::socket::get_all_connections() {
                        let mut result: Vec<ConnectionResponse> = all
                            .values()
                            .flatten()
                            .map(|c| ConnectionResponse {
                                protocol: c.protocol.to_string(),
                                local_addr: c.local_addr.to_string(),
                                remote_addr: c.remote_addr.map(|a| a.to_string()),
                                state: c.state.to_string(),
                                pid: c.pid,
                                inode: c.inode,
                            })
                            .collect();
                        result.truncate(50);
                        c.connections.push(result);
                    }
                });
            }
        });
    }
}
