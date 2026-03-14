use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use query_system_info::cpu::{get_cpu_info, get_cpu_usage};
use query_system_info::disk::get_disks;
use query_system_info::memory::get_memory_info;
use query_system_info::process::{ProcessTracker, list_processes};
use query_system_info::socket::{get_all_connections, get_socket_summary};
use query_system_info::types::SocketState;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[napi(object)]
#[derive(Clone)]
pub struct JsMemoryInfo {
    pub total: f64,
    pub available: f64,
    pub used: f64,
    pub free: f64,
    pub usage_percent: f64,
}

#[napi(object)]
#[derive(Clone)]
pub struct JsCpuInfo {
    pub physical_cores: u32,
    pub logical_cores: u32,
    pub model_name: String,
    pub vendor: String,
    pub frequency_mhz: f64,
}

#[napi(object)]
#[derive(Clone)]
pub struct JsDiskInfo {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_bytes: f64,
    pub used_bytes: f64,
    pub available_bytes: f64,
    pub usage_percent: f64,
}

#[napi(object)]
#[derive(Clone)]
pub struct JsSocketStateSummary {
    pub total: f64,
    pub established: f64,
    pub listen: f64,
    pub time_wait: f64,
    pub close_wait: f64,
}

#[napi(object)]
#[derive(Clone)]
pub struct JsProcessInfo {
    pub pid: f64,
    pub name: String,
    pub command: String,
    pub status: String,
    pub memory_usage: f64,
}

#[napi(object)]
#[derive(Clone)]
pub struct JsSocketConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: f64,
    pub inode: f64,
}

#[napi(object)]
#[derive(Clone)]
pub struct JsChildProcessEvent {
    pub pid: f64,
    pub ppid: f64,
    pub name: String,
    pub cmdline: Vec<String>,
    pub exe_path: String,
    pub start_time: f64,
}

#[napi]
pub struct JsProcessTracker {
    tracker: Arc<Mutex<Option<ProcessTracker>>>,
}

#[napi]
#[derive(Clone)]
pub struct JsSystemSummary {
    memory: JsMemoryInfo,
    cpu: JsCpuInfo,
    disks: Vec<JsDiskInfo>,
    socket_summary: JsSocketStateSummary,
    connections: Vec<JsSocketConnection>,
    processes: Vec<JsProcessInfo>,
    process_count: f64,
    cpu_usage: Vec<f64>,
}

fn into_napi_result<T, E>(result: std::result::Result<T, E>, context: &str) -> napi::Result<T>
where
    E: std::fmt::Display,
{
    result.map_err(|error| napi::Error::from_reason(format!("{context}: {error}")))
}

fn to_js_process_info(process: &query_system_info::types::ProcessInfo) -> JsProcessInfo {
    JsProcessInfo {
        pid: process.pid as f64,
        name: process.name.clone(),
        command: process.cmdline.join(" "),
        status: process.state.to_string(),
        memory_usage: process.memory_bytes as f64,
    }
}

#[napi]
impl JsSystemSummary {
    #[napi(constructor)]
    pub fn new(duration: Option<f64>) -> napi::Result<Self> {
        let memory = into_napi_result(get_memory_info(), "get_memory_info failed")?;
        let cpu = into_napi_result(get_cpu_info(), "get_cpu_info failed")?;
        let disks = into_napi_result(get_disks(), "get_disks failed")?;
        let socket_summary = into_napi_result(get_socket_summary(), "get_socket_summary failed")?;
        let connections = into_napi_result(get_all_connections(), "get_all_connections failed")?;
        let processes = into_napi_result(list_processes(), "list_processes failed")?;
        let process_count = processes.len();
        let use_duration = duration.unwrap_or(500.0 as f64);
        let cpu_usage = into_napi_result(
            get_cpu_usage(Duration::from_millis(use_duration as u64)),
            "get_cpu_usage failed",
        )?;
        Ok(Self {
            memory: JsMemoryInfo {
                total: memory.total as f64,
                available: memory.available as f64,
                used: memory.used as f64,
                free: memory.free as f64,
                usage_percent: memory.usage_percent as f64,
            },
            cpu: JsCpuInfo {
                physical_cores: cpu.physical_cores,
                logical_cores: cpu.logical_cores,
                model_name: cpu.model_name,
                vendor: cpu.vendor,
                frequency_mhz: cpu.frequency_mhz as f64,
            },
            disks: disks
                .iter()
                .map(|d| JsDiskInfo {
                    device: d.device.clone(),
                    mount_point: d.mount_point.clone(),
                    fs_type: d.fs_type.clone(),
                    total_bytes: d.total_bytes as f64,
                    used_bytes: d.used_bytes as f64,
                    available_bytes: d.available_bytes as f64,
                    usage_percent: d.usage_percent as f64,
                })
                .collect(),
            socket_summary: JsSocketStateSummary {
                total: socket_summary.total as f64,
                established: socket_summary.established as f64,
                listen: socket_summary.listen as f64,
                time_wait: socket_summary.time_wait as f64,
                close_wait: socket_summary.close_wait as f64,
            },
            connections: connections
                .values()
                .flatten()
                .map(|c| JsSocketConnection {
                    protocol: c.protocol.to_string(),
                    local_addr: c.local_addr.to_string(),
                    remote_addr: c
                        .remote_addr
                        .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                        .to_string(),
                    state: c.state.to_string(),
                    pid: c.pid.unwrap_or(0) as f64,
                    inode: c.inode as f64,
                })
                .collect(),
            processes: processes.iter().map(to_js_process_info).collect(),
            process_count: process_count as f64,
            cpu_usage: cpu_usage,
        })
    }

    #[napi]
    pub fn get_connections(&self) -> Vec<JsSocketConnection> {
        self.connections.clone()
    }

    #[napi]
    pub fn get_processes(&self) -> Vec<JsProcessInfo> {
        self.processes.clone()
    }

    #[napi]
    pub fn get_process_count(&self) -> f64 {
        self.process_count
    }

    #[napi]
    pub fn get_cpu_usage(&self) -> Vec<f64> {
        self.cpu_usage.clone()
    }

    #[napi]
    pub fn get_connection_by_pid(&self, pid: f64) -> Option<JsSocketConnection> {
        self.connections.iter().find(|c| c.pid == pid).cloned()
    }

    #[napi]
    pub fn get_connection_by_inode(&self, inode: f64) -> Option<JsSocketConnection> {
        self.connections.iter().find(|c| c.inode == inode).cloned()
    }

    #[napi]
    pub fn get_connection_by_local_addr(&self, local_addr: String) -> Option<JsSocketConnection> {
        self.connections
            .iter()
            .find(|c| c.local_addr == local_addr)
            .cloned()
    }

    #[napi]
    pub fn get_connection_by_remote_addr(&self, remote_addr: String) -> Option<JsSocketConnection> {
        self.connections
            .iter()
            .find(|c| c.remote_addr == remote_addr)
            .cloned()
    }

    #[napi]
    pub fn get_connection_by_state(&self, state: String) -> Vec<JsSocketConnection> {
        self.connections
            .iter()
            .filter(|c| c.state == state)
            .map(|c| c.clone())
            .collect()
    }

    #[napi]
    pub fn get_cpu_info(&self) -> JsCpuInfo {
        self.cpu.clone()
    }

    #[napi]
    pub fn get_memory_info(&self) -> JsMemoryInfo {
        self.memory.clone()
    }

    #[napi]
    pub fn get_disks(&self) -> Vec<JsDiskInfo> {
        self.disks.clone()
    }

    #[napi]
    pub fn get_socket_summary(&self) -> JsSocketStateSummary {
        self.socket_summary.clone()
    }
}

#[napi]
pub fn js_get_cpu_usage(duration: Option<f64>) -> napi::Result<Vec<f64>> {
    into_napi_result(
        get_cpu_usage(Duration::from_millis(duration.unwrap_or(500.0) as u64)),
        "get_cpu_usage failed",
    )
}

#[napi]
pub fn js_get_cpu_info() -> napi::Result<JsCpuInfo> {
    let cpu_info = into_napi_result(get_cpu_info(), "get_cpu_info failed")?;
    Ok(JsCpuInfo {
        physical_cores: cpu_info.physical_cores,
        logical_cores: cpu_info.logical_cores,
        model_name: cpu_info.model_name,
        vendor: cpu_info.vendor,
        frequency_mhz: cpu_info.frequency_mhz as f64,
    })
}

#[napi]
pub fn js_get_memory_info() -> napi::Result<JsMemoryInfo> {
    let memory_info = into_napi_result(get_memory_info(), "get_memory_info failed")?;
    Ok(JsMemoryInfo {
        total: memory_info.total as f64,
        available: memory_info.available as f64,
        used: memory_info.used as f64,
        free: memory_info.free as f64,
        usage_percent: memory_info.usage_percent as f64,
    })
}

#[napi]
pub fn js_get_disks() -> napi::Result<Vec<JsDiskInfo>> {
    let disks = into_napi_result(get_disks(), "get_disks failed")?;
    Ok(disks
        .iter()
        .map(|d| JsDiskInfo {
            device: d.device.clone(),
            mount_point: d.mount_point.clone(),
            fs_type: d.fs_type.clone(),
            total_bytes: d.total_bytes as f64,
            used_bytes: d.used_bytes as f64,
            available_bytes: d.available_bytes as f64,
            usage_percent: d.usage_percent as f64,
        })
        .collect())
}

#[napi]
pub fn js_get_socket_summary() -> napi::Result<JsSocketStateSummary> {
    let socket_summary = into_napi_result(get_socket_summary(), "get_socket_summary failed")?;
    Ok(JsSocketStateSummary {
        total: socket_summary.total as f64,
        established: socket_summary.established as f64,
        listen: socket_summary.listen as f64,
        time_wait: socket_summary.time_wait as f64,
        close_wait: socket_summary.close_wait as f64,
    })
}

#[napi]
pub fn get_connections() -> napi::Result<Vec<JsSocketConnection>> {
    let connections = into_napi_result(get_all_connections(), "get_all_connections failed")?;
    Ok(connections
        .values()
        .flatten()
        .map(|c| JsSocketConnection {
            protocol: c.protocol.to_string(),
            local_addr: c.local_addr.to_string(),
            remote_addr: c
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: c.state.to_string(),
            pid: c.pid.unwrap_or(0) as f64,
            inode: c.inode as f64,
        })
        .collect())
}

#[napi]
pub fn get_processes() -> napi::Result<Vec<JsProcessInfo>> {
    let processes = into_napi_result(list_processes(), "list_processes failed")?;
    Ok(processes.iter().map(to_js_process_info).collect())
}

#[napi]
pub fn get_process_count() -> napi::Result<f64> {
    let processes = into_napi_result(list_processes(), "list_processes failed")?;
    Ok(processes.len() as f64)
}

#[napi]
pub fn get_process_by_pid(pid: f64) -> Option<JsProcessInfo> {
    let processes = list_processes().ok()?;
    let result = processes.iter().find(|p| p.pid == pid as u32)?.clone();
    Some(to_js_process_info(&result))
}

#[napi]
pub fn get_connection_by_pid(pid: u32) -> napi::Result<Option<JsSocketConnection>> {
    let connections = into_napi_result(get_all_connections(), "get_all_connections failed")?;
    let result = connections
        .values()
        .flatten()
        .find(|c| c.pid == Some(pid as u32))
        .cloned();
    Ok(result.map(|r| JsSocketConnection {
        protocol: r.protocol.to_string(),
        local_addr: r.local_addr.to_string(),
        remote_addr: r
            .remote_addr
            .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .to_string(),
        state: r.state.to_string(),
        pid: r.pid.unwrap_or(0) as f64,
        inode: r.inode as f64,
    }))
}

#[napi]
pub fn get_connection_by_inode(inode: f64) -> napi::Result<Option<JsSocketConnection>> {
    let connections = into_napi_result(get_all_connections(), "get_all_connections failed")?;
    let result = connections
        .values()
        .flatten()
        .find(|c| c.inode == inode as u64)
        .cloned();
    Ok(result.map(|r| JsSocketConnection {
        protocol: r.protocol.to_string(),
        local_addr: r.local_addr.to_string(),
        remote_addr: r
            .remote_addr
            .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .to_string(),
        state: r.state.to_string(),
        pid: r.pid.unwrap_or(0) as f64,
        inode: r.inode as f64,
    }))
}

#[napi]
pub fn get_connection_by_local_addr(
    local_addr: String,
) -> napi::Result<Option<JsSocketConnection>> {
    let parsed: SocketAddr = local_addr
        .parse()
        .map_err(|e| napi::Error::from_reason(format!("invalid local_addr: {e}")))?;
    let connections = into_napi_result(get_all_connections(), "get_all_connections failed")?;
    let result = connections
        .values()
        .flatten()
        .find(|c| c.local_addr == parsed)
        .cloned();
    Ok(result.map(|r| JsSocketConnection {
        protocol: r.protocol.to_string(),
        local_addr: r.local_addr.to_string(),
        remote_addr: r
            .remote_addr
            .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .to_string(),
        state: r.state.to_string(),
        pid: r.pid.unwrap_or(0) as f64,
        inode: r.inode as f64,
    }))
}

#[napi]
pub fn get_connection_by_remote_addr(
    remote_addr: String,
) -> napi::Result<Option<JsSocketConnection>> {
    let parsed: SocketAddr = remote_addr
        .parse()
        .map_err(|e| napi::Error::from_reason(format!("invalid remote_addr: {e}")))?;
    let connections = into_napi_result(get_all_connections(), "get_all_connections failed")?;
    let result = connections
        .values()
        .flatten()
        .find(|c| c.remote_addr == Some(parsed))
        .cloned();
    Ok(result.map(|r| JsSocketConnection {
        protocol: r.protocol.to_string(),
        local_addr: r.local_addr.to_string(),
        remote_addr: r
            .remote_addr
            .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .to_string(),
        state: r.state.to_string(),
        pid: r.pid.unwrap_or(0) as f64,
        inode: r.inode as f64,
    }))
}

#[napi]
pub fn get_connection_by_state(state: String) -> napi::Result<Vec<JsSocketConnection>> {
    let socket_state = SocketState::try_from(state.as_str())
        .map_err(|_| napi::Error::from_reason(format!("invalid state: {state}")))?;
    let connections = into_napi_result(get_all_connections(), "get_all_connections failed")?;
    let result = connections.get(&socket_state).cloned().unwrap_or_default();
    Ok(result
        .iter()
        .map(|c| JsSocketConnection {
            protocol: c.protocol.to_string(),
            local_addr: c.local_addr.to_string(),
            remote_addr: c
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: c.state.to_string(),
            pid: c.pid.unwrap_or(0) as f64,
            inode: c.inode as f64,
        })
        .collect())
}

#[napi]
impl JsProcessTracker {
    #[napi]
    pub fn stop(&self) {
        if let Ok(mut tracker) = self.tracker.lock() {
            if let Some(t) = tracker.take() {
                t.stop();
            }
        }
    }
}

#[napi]
pub fn start_tracking_children(
    pid: f64,
    callback: ThreadsafeFunction<JsChildProcessEvent>,
) -> napi::Result<JsProcessTracker> {
    let tracker = into_napi_result(
        query_system_info::process::start_tracking_children(pid as u32, move |event| {
            let js_event = JsChildProcessEvent {
                pid: event.pid as f64,
                ppid: event.ppid as f64,
                name: event.name,
                cmdline: event.cmdline,
                exe_path: event.exe_path,
                start_time: event.start_time as f64,
            };
            callback.call(Ok(js_event), ThreadsafeFunctionCallMode::NonBlocking);
        }),
        "start_tracking_children failed",
    )?;

    Ok(JsProcessTracker {
        tracker: Arc::new(Mutex::new(Some(tracker))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_connections() {
        let connections = get_connections();
        assert!(!connections.is_empty());
        for connection in connections {
            println!(
                "protocol: {}, local_addr: {}, remote_addr: {}, state: {}, pid: {}, inode: {}",
                connection.protocol,
                connection.local_addr,
                connection.remote_addr,
                connection.state,
                connection.pid,
                connection.inode
            );
        }
    }
    #[test]
    fn test_get_processes() {
        let processes = get_processes();
        assert!(!processes.is_empty());
    }
}
