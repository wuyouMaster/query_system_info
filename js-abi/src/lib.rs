use query_system_info::socket::{get_all_connections, get_socket_summary};
use query_system_info::cpu::{get_cpu_info, get_cpu_usage};
use query_system_info::disk::get_disks;
use query_system_info::memory::get_memory_info;
use query_system_info::process::list_processes;
use query_system_info::types::SocketState;
use std::time::Duration;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};

use napi_derive::napi;

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

#[napi]
impl JsSystemSummary {
    #[napi(constructor)]
    pub fn new(duration: Option<f64>) -> Self {
        let memory = get_memory_info().unwrap();
        let cpu = get_cpu_info().unwrap();
        let disks = get_disks().unwrap();
        let socket_summary = get_socket_summary().unwrap();
        let connections = get_all_connections().unwrap();
        let processes = list_processes().unwrap();
        let process_count = processes.len();
        let use_duration = duration.unwrap_or(1 as f64);
        let cpu_usage = get_cpu_usage(Duration::from_secs(use_duration as u64)).unwrap();
        Self {
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
            disks: disks.iter().map(|d| JsDiskInfo {
                device: d.device.clone(),
                mount_point: d.mount_point.clone(),
                fs_type: d.fs_type.clone(),
                total_bytes: d.total_bytes as f64,
                used_bytes: d.used_bytes as f64,
                available_bytes: d.available_bytes as f64,
                usage_percent: d.usage_percent as f64,
            }).collect(),
            socket_summary: JsSocketStateSummary {
                total: socket_summary.total as f64,
                established: socket_summary.established as f64,
                listen: socket_summary.listen as f64,
                time_wait: socket_summary.time_wait as f64,
                close_wait: socket_summary.close_wait as f64,
            },
            connections: connections.values().flatten().map(|c| JsSocketConnection {
                protocol: c.protocol.to_string(),
                local_addr: c.local_addr.to_string(),
                remote_addr: c.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
                state: c.state.to_string(),
                pid: c.pid.unwrap_or(0) as f64,
                inode: c.inode as f64,
            }).collect(),
            processes: processes.iter().map(|p| JsProcessInfo {
                pid: p.pid as f64,
                name: p.name.clone(),
                command: p.cmdline.join(" "),
                status: p.state.to_string(),
                memory_usage: p.memory_bytes as f64,
            }).collect(),
            process_count: process_count as f64,
            cpu_usage: cpu_usage,
        }
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
    pub fn get_connection_by_pid(&self, pid: f64) -> JsSocketConnection {
        self.connections.iter().find(|c| c.pid == pid).unwrap().clone()
    }

    #[napi]
    pub fn get_connection_by_inode(&self, inode: f64) -> JsSocketConnection {
        self.connections.iter().find(|c| c.inode == inode).unwrap().clone()
    }

    #[napi]
    pub fn get_connection_by_local_addr(&self, local_addr: String) -> JsSocketConnection {
        self.connections.iter().find(|c| c.local_addr == local_addr).unwrap().clone()
    }

    #[napi]
    pub fn get_connection_by_remote_addr(&self, remote_addr: String) -> JsSocketConnection {
        self.connections.iter().find(|c| c.remote_addr == remote_addr).unwrap().clone()
    }

    #[napi]
    pub fn get_connection_by_state(&self, state: String) -> Vec<JsSocketConnection> {
        self.connections.iter().filter(|c| c.state == state).map(|c| c.clone()).collect()
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
pub fn js_get_cpu_usage(duration: Option<f64>) -> Vec<f64> {
    get_cpu_usage(Duration::from_secs(duration.unwrap_or(1.0) as u64)).unwrap()
}

#[napi]
pub fn js_get_cpu_info() -> JsCpuInfo {
    let cpu_info = get_cpu_info().unwrap();
    JsCpuInfo {
        physical_cores: cpu_info.physical_cores,
        logical_cores: cpu_info.logical_cores,
        model_name: cpu_info.model_name,
        vendor: cpu_info.vendor,
        frequency_mhz: cpu_info.frequency_mhz as f64,
    }
}

#[napi]
pub fn js_get_memory_info() -> JsMemoryInfo {
    let memory_info = get_memory_info().unwrap();
    JsMemoryInfo {
        total: memory_info.total as f64,
        available: memory_info.available as f64,
        used: memory_info.used as f64,
        free: memory_info.free as f64,
        usage_percent: memory_info.usage_percent as f64,
    }
}

#[napi]
pub fn js_get_disks() -> Vec<JsDiskInfo> {
    let disks = get_disks().unwrap();
    disks.iter().map(|d| JsDiskInfo {
        device: d.device.clone(),
        mount_point: d.mount_point.clone(),
        fs_type: d.fs_type.clone(),
        total_bytes: d.total_bytes as f64,
        used_bytes: d.used_bytes as f64,
        available_bytes: d.available_bytes as f64,
        usage_percent: d.usage_percent as f64,
    }).collect()
}

#[napi]
pub fn js_get_socket_summary() -> JsSocketStateSummary {
    let socket_summary = get_socket_summary().unwrap();
    JsSocketStateSummary {
        total: socket_summary.total as f64,
        established: socket_summary.established as f64,
        listen: socket_summary.listen as f64,
        time_wait: socket_summary.time_wait as f64,
        close_wait: socket_summary.close_wait as f64,
    }
}

#[napi]
pub fn get_connections() -> Vec<JsSocketConnection> {
    let connections = get_all_connections().unwrap();
    connections.values().flatten().map(|c| JsSocketConnection {
        protocol: c.protocol.to_string(),
        local_addr: c.local_addr.to_string(),
        remote_addr: c.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
        state: c.state.to_string(),
        pid: c.pid.unwrap_or(0) as f64,
        inode: c.inode as f64,
    }).collect()
}

#[napi]
pub fn get_processes() -> Vec<JsProcessInfo> {
    let processes = list_processes().unwrap();
    processes.iter().map(|p| JsProcessInfo {
        pid: p.pid as f64,
        name: p.name.clone(),
        command: p.cmdline.join(" "),
        status: p.state.to_string(),
        memory_usage: p.memory_bytes as f64,
    }).collect()
}

#[napi]
pub fn get_process_count() -> f64 {
    let processes = list_processes().unwrap();
    processes.len() as f64
}

#[napi]
pub fn get_process_by_pid(pid: f64) -> JsProcessInfo {
    let processes = list_processes().unwrap();
    let result = processes.iter().find(|p| p.pid == pid as u32).unwrap().clone();
    JsProcessInfo {
        pid: result.pid as f64,
        name: result.name.clone(),
        command: result.cmdline.join(" "),
        status: result.state.to_string(),
        memory_usage: result.memory_bytes as f64,
    }
}

#[napi]
pub fn get_connection_by_pid(pid: u32) -> JsSocketConnection {
    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.pid == Some(pid as u32)).unwrap().clone();
    JsSocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap_or(0) as f64,
        inode: result.inode as f64,
    }
}

#[napi]
pub fn get_connection_by_inode(inode: f64) -> JsSocketConnection {
    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.inode == inode as u64).unwrap().clone();
    JsSocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap_or(0) as f64,
        inode: result.inode as f64,
    }
}

#[napi]
pub fn get_connection_by_local_addr(local_addr: String) -> JsSocketConnection {
    let ip_parts = local_addr.split('.').collect::<Vec<&str>>();
    let use_addr: SocketAddr;
    if ip_parts.len() == 4 {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u8>().unwrap()).collect::<Vec<u8>>();
        use_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3])), 0);
    } else {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u16>().unwrap()).collect::<Vec<u16>>();
        use_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3], use_ip_parts[4], use_ip_parts[5], use_ip_parts[6], use_ip_parts[7])), 0);
    }
    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.local_addr == use_addr).unwrap().clone();
    JsSocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap_or(0) as f64,
        inode: result.inode as f64,
    }
}

#[napi]
pub fn get_connection_by_remote_addr(remote_addr: String) -> JsSocketConnection {
    let ip_parts = remote_addr.split('.').collect::<Vec<&str>>();
    let use_addr: SocketAddr;
    if ip_parts.len() == 4 {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u8>().unwrap()).collect::<Vec<u8>>();
        use_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3])), 0);
    } else {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u16>().unwrap()).collect::<Vec<u16>>();
        use_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3], use_ip_parts[4], use_ip_parts[5], use_ip_parts[6], use_ip_parts[7])), 0);
    }
    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.remote_addr == Some(use_addr)).unwrap().clone();
    JsSocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap_or(0) as f64,
        inode: result.inode as f64,
    }
}

#[napi]
pub fn get_connection_by_state(state: String) -> Vec<JsSocketConnection> {
    let state = SocketState::try_from(state.as_str()).unwrap();
    let connections = get_all_connections().unwrap();
    connections.get(&state).unwrap().clone().iter().map(|c| JsSocketConnection {
        protocol: c.protocol.to_string(),
        local_addr: c.local_addr.to_string(),
        remote_addr: c.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
        state: c.state.to_string(),
        pid: c.pid.unwrap_or(0) as f64,
        inode: c.inode as f64,
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_connections() {
        let connections = get_connections();
        assert!(!connections.is_empty());
        for connection in connections {
            println!("protocol: {}, local_addr: {}, remote_addr: {}, state: {}, pid: {}, inode: {}", connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode);
        }
    }
    #[test]
    fn test_get_processes() {
        let processes = get_processes();
        assert!(!processes.is_empty());
    }
}
