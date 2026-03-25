use axum::extract::{Path, Json, Query};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::task;

#[derive(Serialize)]
pub struct MemoryResponse {
    pub total: u64,
    pub available: u64,
    pub used: u64,
    pub free: u64,
    pub usage_percent: f64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub swap_free: u64,
    pub cached: u64,
    pub buffers: u64,
}

#[derive(Serialize)]
pub struct CpuInfoResponse {
    pub physical_cores: u32,
    pub logical_cores: u32,
    pub model_name: String,
    pub vendor: String,
    pub frequency_mhz: u64,
}

#[derive(Serialize)]
pub struct DiskResponse {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Serialize)]
pub struct ProcessResponse {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmdline: Vec<String>,
    pub state: String,
    pub memory_bytes: u64,
    pub virtual_memory: u64,
    pub cpu_percent: f64,
    pub threads: u32,
    pub start_time: u64,
    pub username: String,
}

#[derive(Serialize)]
pub struct SocketSummaryResponse {
    pub total: usize,
    pub established: usize,
    pub listen: usize,
    pub time_wait: usize,
    pub close_wait: usize,
}

pub async fn memory() -> Result<Json<MemoryResponse>, (StatusCode, String)> {
    task::spawn_blocking(|| {
        let mem = query_system_info::memory::get_memory_info()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(Json(MemoryResponse {
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
        }))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub async fn cpu_info() -> Result<Json<CpuInfoResponse>, (StatusCode, String)> {
    task::spawn_blocking(|| {
        let cpu = query_system_info::cpu::get_cpu_info()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(Json(CpuInfoResponse {
            physical_cores: cpu.physical_cores,
            logical_cores: cpu.logical_cores,
            model_name: cpu.model_name,
            vendor: cpu.vendor,
            frequency_mhz: cpu.frequency_mhz,
        }))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub async fn disks() -> Result<Json<Vec<DiskResponse>>, (StatusCode, String)> {
    task::spawn_blocking(|| {
        let disks = query_system_info::disk::get_disks()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let response: Vec<DiskResponse> = disks
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

        Ok(Json(response))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub async fn processes() -> Result<Json<Vec<ProcessResponse>>, (StatusCode, String)> {
    task::spawn_blocking(|| {
        let processes = query_system_info::process::list_processes()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let response: Vec<ProcessResponse> = processes
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

        Ok(Json(response))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub async fn process_by_pid(
    Path(pid): Path<u32>,
) -> Result<Json<ProcessResponse>, (StatusCode, String)> {
    task::spawn_blocking(move || {
        let processes = query_system_info::process::list_processes()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let process = processes
            .into_iter()
            .find(|p| p.pid == pid)
            .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Process {} not found", pid)))?;

        Ok(Json(ProcessResponse {
            pid: process.pid,
            ppid: process.ppid,
            name: process.name,
            exe_path: process.exe_path,
            cmdline: process.cmdline,
            state: process.state.to_string(),
            memory_bytes: process.memory_bytes,
            virtual_memory: process.virtual_memory,
            cpu_percent: process.cpu_percent,
            threads: process.threads,
            start_time: process.start_time,
            username: process.username,
        }))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

pub async fn socket_summary() -> Result<Json<SocketSummaryResponse>, (StatusCode, String)> {
    task::spawn_blocking(|| {
        let summary = query_system_info::socket::get_socket_summary()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Ok(Json(SocketSummaryResponse {
            total: summary.total,
            established: summary.established,
            listen: summary.listen,
            time_wait: summary.time_wait,
            close_wait: summary.close_wait,
        }))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

#[derive(Serialize)]
pub struct KillResponse {
    pub pid: u32,
    pub success: bool,
    pub message: String,
}

pub async fn kill_process(
    Path(pid): Path<u32>,
) -> (StatusCode, Json<KillResponse>) {
    let result = task::spawn_blocking(move || {
        query_system_info::process::kill_process(pid)
    })
    .await;

    match result {
        Ok(Ok(_)) => (
            StatusCode::OK,
            Json(KillResponse {
                pid,
                success: true,
                message: format!("Process {} terminated", pid),
            }),
        ),
        Ok(Err(e)) => {
            let status = match &e {
                query_system_info::SysInfoError::ProcessNotFound(_) => StatusCode::NOT_FOUND,
                query_system_info::SysInfoError::PermissionDenied(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(KillResponse {
                    pid,
                    success: false,
                    message: e.to_string(),
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(KillResponse {
                pid,
                success: false,
                message: e.to_string(),
            }),
        ),
    }
}

// ---------------------------------------------------------------------------
// New endpoints for system-monitor remote mode
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListDirQuery {
    pub path: String,
}

#[derive(Serialize)]
pub struct DirEntryResponse {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

pub async fn list_dir(
    Query(params): Query<ListDirQuery>,
) -> Result<Json<Vec<DirEntryResponse>>, (StatusCode, String)> {
    let dir_path = params.path.clone();
    task::spawn_blocking(move || {
        let entries = std::fs::read_dir(&dir_path)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("list_dir({}): {}", dir_path, e)))?;

        let mut result = Vec::new();
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let name = entry.file_name().to_string_lossy().to_string();
            let full_path = entry.path().to_string_lossy().to_string();
            let is_dir = meta.is_dir();
            let size = if is_dir { 0 } else { meta.len() };
            result.push(DirEntryResponse {
                name,
                path: full_path,
                is_dir,
                size,
            });
        }
        result.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
        Ok(Json(result))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: Option<String>,
    pub state: String,
    pub pid: Option<u32>,
    pub inode: u64,
}

pub async fn connections() -> Result<Json<Vec<ConnectionResponse>>, (StatusCode, String)> {
    task::spawn_blocking(|| {
        let all = query_system_info::socket::get_all_connections()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
        Ok(Json(result))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

#[derive(Serialize)]
pub struct SocketStatsResponse {
    pub pid: u32,
    pub fd: u32,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub async fn process_socket_stats(
    Path(pid): Path<u32>,
) -> Result<Json<Vec<SocketStatsResponse>>, (StatusCode, String)> {
    task::spawn_blocking(move || {
        let stats = query_system_info::socket::get_process_socket_stats(pid)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let response: Vec<SocketStatsResponse> = stats
            .into_iter()
            .map(|s| SocketStatsResponse {
                pid: s.pid,
                fd: s.fd,
                protocol: s.protocol.to_string(),
                local_addr: s.local_addr.to_string(),
                remote_addr: s.remote_addr.map(|a| a.to_string()),
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
            })
            .collect();

        Ok(Json(response))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

#[derive(Serialize)]
pub struct SocketQueueResponse {
    pub pid: u32,
    pub fd: u32,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: Option<String>,
    pub state: String,
    pub recv_queue_bytes: u32,
    pub recv_queue_hiwat: u32,
    pub send_queue_bytes: u32,
    pub send_queue_hiwat: u32,
}

pub async fn process_socket_queues(
    Path(pid): Path<u32>,
) -> Result<Json<Vec<SocketQueueResponse>>, (StatusCode, String)> {
    task::spawn_blocking(move || {
        let queues = query_system_info::socket::get_process_socket_queues(pid)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let response: Vec<SocketQueueResponse> = queues
            .into_iter()
            .map(|q| SocketQueueResponse {
                pid: q.pid,
                fd: q.fd,
                protocol: q.protocol.to_string(),
                local_addr: q.local_addr.to_string(),
                remote_addr: q.remote_addr.map(|a| a.to_string()),
                state: q.state.to_string(),
                recv_queue_bytes: q.recv_queue_bytes,
                recv_queue_hiwat: q.recv_queue_hiwat,
                send_queue_bytes: q.send_queue_bytes,
                send_queue_hiwat: q.send_queue_hiwat,
            })
            .collect();

        Ok(Json(response))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}
