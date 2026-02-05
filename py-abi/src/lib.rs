use pyo3::prelude::*;

use query_system_info::socket::{get_all_connections, get_socket_summary};
use query_system_info::cpu::{get_cpu_info, get_cpu_usage};
use query_system_info::disk::get_disks;
use query_system_info::memory::get_memory_info;
use query_system_info::process::list_processes;
use query_system_info::types::SocketState;
use std::time::Duration;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct PyMemoryInfo {
    #[pyo3(get)]
    pub total: u64,
    #[pyo3(get)]
    pub available: u64,
    #[pyo3(get)]
    pub used: u64,
    #[pyo3(get)]
    pub free: u64,
    #[pyo3(get)]
    pub usage_percent: f64,
}


#[pyclass(skip_from_py_object)] 
#[derive(Clone)]
pub struct PyCpuInfo {
    #[pyo3(get)]
    pub physical_cores: u32,
    #[pyo3(get)]
    pub logical_cores: u32,
    #[pyo3(get)]
    pub model_name: String,
    #[pyo3(get)]
    pub vendor: String,
    #[pyo3(get)]
    pub frequency_mhz: u64,
}

#[pyclass(skip_from_py_object)] 
#[derive(Clone)]
pub struct PyDiskInfo {
    #[pyo3(get)]
    pub device: String,
    #[pyo3(get)]
    pub mount_point: String,
    #[pyo3(get)]
    pub fs_type: String,
    #[pyo3(get)]
    pub total_bytes: u64,
    #[pyo3(get)]
    pub used_bytes: u64,
    #[pyo3(get)]
    pub available_bytes: u64,
    #[pyo3(get)]
    pub usage_percent: f64,
}

#[pyclass(skip_from_py_object)] 
#[derive(Clone)]
pub struct PySocketStateSummary {
    #[pyo3(get)]
    pub total: usize,
    #[pyo3(get)]
    pub established: usize,
    #[pyo3(get)]
    pub listen: usize,
    #[pyo3(get)]
    pub time_wait: usize,
    #[pyo3(get)]
    pub close_wait: usize,
}

#[pyclass(skip_from_py_object)] 
#[derive(Clone)]
pub struct PyProcessInfo {
    #[pyo3(get)]
    pub pid: u32,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub command: String,
    #[pyo3(get)]
    pub status: String,
    #[pyo3(get)]
    pub memory_usage: u64,
}

#[pyclass(skip_from_py_object)] 
#[derive(Clone)]
pub struct PySocketConnection {
    #[pyo3(get)]
    pub protocol: String,
    #[pyo3(get)]
    pub local_addr: String,
    #[pyo3(get)]
    pub remote_addr: String,
    #[pyo3(get)]
    pub state: String,
    #[pyo3(get)]
    pub pid: u32,
    #[pyo3(get)]
    pub inode: u64,
}

#[pyclass(skip_from_py_object)] 
#[derive(Clone)]
pub struct PySystemSummary {
    #[pyo3(get)]
    pub memory: PyMemoryInfo,
    #[pyo3(get)]
    pub cpu: PyCpuInfo,
    #[pyo3(get)]
    pub disks: Vec<PyDiskInfo>,  
    #[pyo3(get)]
    pub socket_summary: PySocketStateSummary,
    #[pyo3(get)]
    pub connections: Vec<PySocketConnection>,
    #[pyo3(get)]
    pub process_count: usize,
    #[pyo3(get)]
    pub processes: Vec<PyProcessInfo>,
    #[pyo3(get)]
    pub cpu_usage: Vec<f64>,
}

#[pymethods]
impl PySystemSummary {
    #[new]
    fn new(sample_duration: Option<u64>) -> Self {
        let memory_info = get_memory_info().unwrap();
        let cpu_info = get_cpu_info().unwrap();
        let disks = get_disks().unwrap();
        let socket_summary = get_socket_summary().unwrap();
        let connections = get_all_connections().unwrap();
        let processes = list_processes().unwrap();
        let cpu_usage = get_cpu_usage(Duration::from_secs(sample_duration.unwrap_or(1))).unwrap();
        
        Self {
            memory: PyMemoryInfo {
                total: memory_info.total,
                available: memory_info.available,
                used: memory_info.used,
                free: memory_info.free,
                usage_percent: memory_info.usage_percent,
            },
            cpu: PyCpuInfo {
                physical_cores: cpu_info.physical_cores,
                logical_cores: cpu_info.logical_cores,
                model_name: cpu_info.model_name,
                vendor: cpu_info.vendor,
                frequency_mhz: cpu_info.frequency_mhz,
            },
            disks: disks.iter().map(|d| PyDiskInfo {
                device: d.device.clone(),
                mount_point: d.mount_point.clone(),
                fs_type: d.fs_type.clone(),
                total_bytes: d.total_bytes,
                used_bytes: d.used_bytes,
                available_bytes: d.available_bytes,
                usage_percent: d.usage_percent,
            }).collect(),
            socket_summary: PySocketStateSummary {
                total: get_socket_summary().unwrap().total,
                established: socket_summary.established,
                listen: socket_summary.listen,
                time_wait: socket_summary.time_wait,
                close_wait: socket_summary.close_wait,
            },
            connections: connections.values().flatten().map(|c| PySocketConnection {
                protocol: c.protocol.to_string(),
                local_addr: c.local_addr.to_string(),
                remote_addr: c.remote_addr.unwrap().to_string(),
                state: c.state.to_string(),
                pid: c.pid.unwrap(),
                inode: c.inode,
            }).collect(),
            processes: processes.iter().map(|p| PyProcessInfo {
                pid: p.pid,
                name: p.name.clone(),
                command: p.cmdline.join(" "),
                status: p.state.to_string(),
                memory_usage: p.memory_bytes as u64,
            }).collect(),
            process_count: processes.len(),
            cpu_usage: cpu_usage,
        }
    }

    pub fn get_connections(&self) -> Vec<PySocketConnection> {
        self.connections.clone()
    }
    pub fn get_processes(&self) -> Vec<PyProcessInfo> {
        self.processes.clone()
    }
    pub fn get_process_count(&self) -> usize {
        self.process_count
    }
    pub fn get_process_by_pid(&self, pid: u32) -> PyProcessInfo {
        self.processes.iter().find(|p| p.pid == pid).unwrap().clone()
    }
    pub fn get_connection_by_pid(&self, pid: u32) -> PySocketConnection {
        self.connections.iter().find(|c| c.pid == pid).unwrap().clone()
    }
    pub fn get_connection_by_inode(&self, inode: u64) -> PySocketConnection {
        self.connections.iter().find(|c| c.inode == inode).unwrap().clone()
    }
    pub fn get_connection_by_local_addr(&self, local_addr: String) -> PySocketConnection {
        self.connections.iter().find(|c| c.local_addr == local_addr).unwrap().clone()
    }
    pub fn get_connection_by_remote_addr(&self, remote_addr: String) -> PySocketConnection {
        self.connections.iter().find(|c| c.remote_addr == remote_addr).unwrap().clone()
    }
    pub fn get_connection_by_state(&self, state: String) -> PySocketConnection {
        self.connections.iter().find(|c| c.state == state).unwrap().clone()
    }
}

#[pyfunction]
pub fn get_connections() -> Vec<PySocketConnection> {
    let connections = get_all_connections().unwrap();
    connections.values().flatten().map(|c| PySocketConnection {
        protocol: c.protocol.to_string(),
        local_addr: c.local_addr.to_string(),
        remote_addr: c.remote_addr.unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).to_string(),
        state: c.state.to_string(),
        pid: c.pid.unwrap_or(0),
        inode: c.inode,
    }).collect()
}

#[pyfunction]
pub fn get_processes() -> Vec<PyProcessInfo> {
    let processes = list_processes().unwrap_or_default();
    processes.iter().map(|p| PyProcessInfo {
        pid: p.pid,
        name: p.name.clone(),
        command: p.cmdline.join(" "),
        status: p.state.to_string(),
        memory_usage: p.memory_bytes as u64,
    }).collect()
}

#[pyfunction]
pub fn get_process_count() -> usize {
    let processes = list_processes().unwrap_or_default();
    processes.len()
}

#[pyfunction]
pub fn get_process_by_pid(pid: u32) -> PyProcessInfo {
    let processes = list_processes().unwrap_or_default();
    let result = processes.iter().find(|p| p.pid == pid).unwrap().clone();
    PyProcessInfo {
        pid: result.pid,
        name: result.name.clone(),
        command: result.cmdline.join(" "),
        status: result.state.to_string(),
        memory_usage: result.memory_bytes as u64,
    }
}

#[pyfunction]
pub fn get_connection_by_pid(pid: u32) -> PySocketConnection {
    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.pid == Some(pid)).unwrap().clone();
    PySocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap().to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap(),
        inode: result.inode,
    }
}


#[pyfunction]
pub fn get_connection_by_inode(inode: u64) -> PySocketConnection {
    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.inode == inode).unwrap().clone();
    PySocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap().to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap(),
        inode: result.inode,
    }
}

#[pyfunction]
pub fn get_connection_by_local_addr(local_addr: String) -> PySocketConnection {
    let use_addr: SocketAddr;
    let ip_parts = local_addr.split('.').collect::<Vec<&str>>();
    if ip_parts.len() == 4 {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u8>().unwrap()).collect::<Vec<u8>>();
        use_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3])), 0);
    } else {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u16>().unwrap()).collect::<Vec<u16>>();
        use_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3], use_ip_parts[4], use_ip_parts[5], use_ip_parts[6], use_ip_parts[7])), 0);
    }

    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.local_addr == use_addr).unwrap().clone();
    PySocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap().to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap(),
        inode: result.inode,
    }
}

#[pyfunction]
pub fn get_connection_by_remote_addr(remote_addr: String) -> PySocketConnection {
    let use_addr: SocketAddr;
    let ip_parts = remote_addr.split('.').collect::<Vec<&str>>();
    if ip_parts.len() == 4 {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u8>().unwrap()).collect::<Vec<u8>>();
        use_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3])), 0);
    } else {
        let use_ip_parts = ip_parts.iter().map(|p| p.parse::<u16>().unwrap()).collect::<Vec<u16>>();
        use_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(use_ip_parts[0], use_ip_parts[1], use_ip_parts[2], use_ip_parts[3], use_ip_parts[4], use_ip_parts[5], use_ip_parts[6], use_ip_parts[7])), 0);
    }
    let connections = get_all_connections().unwrap();
    let result = connections.values().flatten().find(|c| c.remote_addr == Some(use_addr)).unwrap().clone();
    PySocketConnection {
        protocol: result.protocol.to_string(),
        local_addr: result.local_addr.to_string(),
        remote_addr: result.remote_addr.unwrap().to_string(),
        state: result.state.to_string(),
        pid: result.pid.unwrap(),
        inode: result.inode,
    }
}

#[pyfunction]
pub fn get_connection_by_state(state: String) -> Vec<PySocketConnection> {
    let connections = get_all_connections().unwrap();
    let state = SocketState::try_from(state.as_str()).unwrap();
    let result = connections.get(&state).unwrap().clone();
    result.iter().map(|c| PySocketConnection {
        protocol: c.protocol.to_string(),
        local_addr: c.local_addr.to_string(),
        remote_addr: c.remote_addr.unwrap().to_string(),
        state: c.state.to_string(),
        pid: c.pid.unwrap(),
        inode: c.inode,
    }).collect()
}

#[pymodule]
pub fn py_query_system_info(m: Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySystemSummary>()?;
    m.add_class::<PyMemoryInfo>()?;
    m.add_class::<PyCpuInfo>()?;
    m.add_class::<PyDiskInfo>()?;
    m.add_class::<PySocketStateSummary>()?;
    m.add_class::<PySocketConnection>()?;
    m.add_class::<PyProcessInfo>()?;
    m.add_function(wrap_pyfunction!(get_connections, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_processes, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_process_count, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_process_by_pid, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_pid, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_inode, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_local_addr, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_remote_addr, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_state, m.py())?)?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_connections() {
        let connections = get_connections();
        assert!(!connections.is_empty());
    }
    #[test]
    fn test_get_processes() {
        let processes = get_processes();
        assert!(!processes.is_empty());
    }
    #[test]
    fn test_get_process_count() {
        let process_count = get_process_count();
        assert!(process_count > 0);
    }
}
