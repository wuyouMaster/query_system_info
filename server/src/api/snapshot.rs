use axum::extract::{Path, Json, Query};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::task;

use crate::state::AppState;

#[derive(Serialize, Clone)]
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

#[derive(Serialize, Clone)]
pub struct CpuInfoResponse {
    pub physical_cores: u32,
    pub logical_cores: u32,
    pub model_name: String,
    pub vendor: String,
    pub frequency_mhz: u64,
}

#[derive(Serialize, Clone)]
pub struct DiskResponse {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Serialize, Clone)]
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

#[derive(Serialize, Clone)]
pub struct SocketSummaryResponse {
    pub total: usize,
    pub established: usize,
    pub listen: usize,
    pub time_wait: usize,
    pub close_wait: usize,
}

// ---------------------------------------------------------------------------
// Cached handlers — read from SnapshotCache instead of direct system calls
// ---------------------------------------------------------------------------

pub async fn memory(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<MemoryResponse> {
    match state.snapshot_cache.memory.latest() {
        Some(m) => Json(m),
        None => Json(MemoryResponse {
            total: 0,
            available: 0,
            used: 0,
            free: 0,
            usage_percent: 0.0,
            swap_total: 0,
            swap_used: 0,
            swap_free: 0,
            cached: 0,
            buffers: 0,
        }),
    }
}

pub async fn cpu_info(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<CpuInfoResponse> {
    let guard = state.snapshot_cache.cpu_info.read().unwrap();
    match guard.as_ref() {
        Some(info) => Json(info.clone()),
        None => Json(CpuInfoResponse {
            physical_cores: 0,
            logical_cores: 0,
            model_name: String::new(),
            vendor: String::new(),
            frequency_mhz: 0,
        }),
    }
}

pub async fn disks(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<Vec<DiskResponse>> {
    Json(state.snapshot_cache.disks.latest().unwrap_or_default())
}

pub async fn processes(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<Vec<ProcessResponse>> {
    Json(
        state
            .snapshot_cache
            .processes
            .latest()
            .unwrap_or_default(),
    )
}

pub async fn process_by_pid(
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(pid): Path<u32>,
) -> Result<Json<ProcessResponse>, (StatusCode, String)> {
    let procs = state.snapshot_cache.processes.latest().unwrap_or_default();
    procs
        .into_iter()
        .find(|p| p.pid == pid)
        .map(Json)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Process {} not found", pid)))
}

pub async fn socket_summary(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<SocketSummaryResponse> {
    match state.snapshot_cache.sockets.latest() {
        Some(s) => Json(s),
        None => Json(SocketSummaryResponse {
            total: 0,
            established: 0,
            listen: 0,
            time_wait: 0,
            close_wait: 0,
        }),
    }
}

#[derive(Serialize, Clone)]
pub struct ConnectionResponse {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: Option<String>,
    pub state: String,
    pub pid: Option<u32>,
    pub inode: u64,
}

pub async fn connections(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Json<Vec<ConnectionResponse>> {
    Json(
        state
            .snapshot_cache
            .connections
            .latest()
            .unwrap_or_default(),
    )
}

// ---------------------------------------------------------------------------
// Non-cached handlers — direct system calls (writes, per-PID, file system)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct KillResponse {
    pub pid: u32,
    pub success: bool,
    pub message: String,
}

pub async fn kill_process(Path(pid): Path<u32>) -> (StatusCode, Json<KillResponse>) {
    let result = task::spawn_blocking(move || query_system_info::process::kill_process(pid)).await;

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

#[derive(Serialize)]
pub struct ProcessIoResponse {
    pub pid: u32,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

pub async fn process_io(
    Path(pid): Path<u32>,
) -> Result<Json<ProcessIoResponse>, (StatusCode, String)> {
    task::spawn_blocking(move || {
        match query_system_info::process::get_process_io(pid) {
            Ok(io) => Ok(Json(ProcessIoResponse {
                pid,
                read_bytes: io.read_bytes,
                write_bytes: io.write_bytes,
            })),
            Err(_) => Ok(Json(ProcessIoResponse {
                pid,
                read_bytes: 0,
                write_bytes: 0,
            })),
        }
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

#[derive(Serialize)]
pub struct ProcessCpuUsageResponse {
    pub pid: u32,
    pub cpu_percent: f64,
}

pub async fn process_cpu_usage(
    Path(pid): Path<u32>,
) -> Result<Json<ProcessCpuUsageResponse>, (StatusCode, String)> {
    task::spawn_blocking(move || {
        let cpu_percent =
            query_system_info::process::get_process_cpu_usage(pid, Duration::from_millis(200))
                .unwrap_or(0.0);
        Ok(Json(ProcessCpuUsageResponse { pid, cpu_percent }))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}
