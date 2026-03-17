use pyo3::prelude::*;
use pyo3::types::PyDict;

use query_system_info::cpu::{get_cpu_info, get_cpu_usage};
use query_system_info::disk::get_disks;
use query_system_info::memory::get_memory_info;
use query_system_info::process::{list_processes, ProcessTracker};
use query_system_info::socket::{get_all_connections, get_socket_summary};
use query_system_info::types::SocketState;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
pub struct PyDirEntry {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub is_dir: bool,
    #[pyo3(get)]
    pub size: u64,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct PyChildProcessEvent {
    #[pyo3(get)]
    pub pid: u32,
    #[pyo3(get)]
    pub ppid: u32,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub cmdline: Vec<String>,
    #[pyo3(get)]
    pub exe_path: String,
    #[pyo3(get)]
    pub start_time: u64,
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

#[pyclass]
pub struct PyProcessTracker {
    tracker: Arc<Mutex<Option<ProcessTracker>>>,
}

#[pymethods]
impl PyProcessTracker {
    pub fn stop(&self) {
        if let Ok(mut tracker) = self.tracker.lock() {
            if let Some(t) = tracker.take() {
                t.stop();
            }
        }
    }
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
        let cpu_usage =
            get_cpu_usage(Duration::from_millis(sample_duration.unwrap_or(500))).unwrap();

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
            disks: disks
                .iter()
                .map(|d| PyDiskInfo {
                    device: d.device.clone(),
                    mount_point: d.mount_point.clone(),
                    fs_type: d.fs_type.clone(),
                    total_bytes: d.total_bytes,
                    used_bytes: d.used_bytes,
                    available_bytes: d.available_bytes,
                    usage_percent: d.usage_percent,
                })
                .collect(),
            socket_summary: PySocketStateSummary {
                total: get_socket_summary().unwrap().total,
                established: socket_summary.established,
                listen: socket_summary.listen,
                time_wait: socket_summary.time_wait,
                close_wait: socket_summary.close_wait,
            },
            connections: connections
                .values()
                .flatten()
                .map(|c| PySocketConnection {
                    protocol: c.protocol.to_string(),
                    local_addr: c.local_addr.to_string(),
                    remote_addr: c.remote_addr.unwrap().to_string(),
                    state: c.state.to_string(),
                    pid: c.pid.unwrap(),
                    inode: c.inode,
                })
                .collect(),
            processes: processes
                .iter()
                .map(|p| PyProcessInfo {
                    pid: p.pid,
                    name: p.name.clone(),
                    command: p.cmdline.join(" "),
                    status: p.state.to_string(),
                    memory_usage: p.memory_bytes as u64,
                })
                .collect(),
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
    pub fn get_process_by_pid(&self, pid: u32) -> Option<PyProcessInfo> {
        self.processes.iter().find(|p| p.pid == pid).cloned()
    }
    pub fn get_connection_by_pid(&self, pid: u32) -> Option<PySocketConnection> {
        self.connections.iter().find(|c| c.pid == pid).cloned()
    }
    pub fn get_connection_by_inode(&self, inode: u64) -> Option<PySocketConnection> {
        self.connections.iter().find(|c| c.inode == inode).cloned()
    }
    pub fn get_connection_by_local_addr(&self, local_addr: String) -> Option<PySocketConnection> {
        self.connections
            .iter()
            .find(|c| c.local_addr == local_addr)
            .cloned()
    }
    pub fn get_connection_by_remote_addr(&self, remote_addr: String) -> Option<PySocketConnection> {
        self.connections
            .iter()
            .find(|c| c.remote_addr == remote_addr)
            .cloned()
    }
    pub fn get_connection_by_state(&self, state: String) -> Vec<PySocketConnection> {
        self.connections
            .iter()
            .filter(|c| c.state == state)
            .cloned()
            .collect()
    }
    pub fn get_cpu_usage(&self) -> Vec<f64> {
        self.cpu_usage.clone()
    }
    pub fn get_cpu_info(&self) -> PyCpuInfo {
        self.cpu.clone()
    }
    pub fn get_memory_info(&self) -> PyMemoryInfo {
        self.memory.clone()
    }
    pub fn get_disks(&self) -> Vec<PyDiskInfo> {
        self.disks.clone()
    }
    pub fn get_socket_summary(&self) -> PySocketStateSummary {
        self.socket_summary.clone()
    }
}

#[pyfunction]
pub fn get_system_summary(sample_duration: Option<u64>) -> PySystemSummary {
    PySystemSummary::new(sample_duration)
}

#[pyfunction]
pub fn py_get_cpu_usage(sample_duration: Option<u64>) -> Vec<f64> {
    get_cpu_usage(Duration::from_millis(sample_duration.unwrap_or(500))).unwrap()
}
#[pyfunction]
pub fn py_get_cpu_info() -> PyCpuInfo {
    let cpu_info = get_cpu_info().unwrap();
    PyCpuInfo {
        physical_cores: cpu_info.physical_cores,
        logical_cores: cpu_info.logical_cores,
        model_name: cpu_info.model_name,
        vendor: cpu_info.vendor,
        frequency_mhz: cpu_info.frequency_mhz,
    }
}
#[pyfunction]
pub fn py_get_memory_info() -> PyMemoryInfo {
    let memory_info = get_memory_info().unwrap();
    PyMemoryInfo {
        total: memory_info.total,
        available: memory_info.available,
        used: memory_info.used,
        free: memory_info.free,
        usage_percent: memory_info.usage_percent,
    }
}
#[pyfunction]
pub fn py_get_socket_summary() -> PyResult<PySocketStateSummary> {
    let socket_summary = get_socket_summary()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(PySocketStateSummary {
        total: socket_summary.total,
        established: socket_summary.established,
        listen: socket_summary.listen,
        time_wait: socket_summary.time_wait,
        close_wait: socket_summary.close_wait,
    })
}

#[pyfunction]
pub fn py_get_disks() -> PyResult<Vec<PyDiskInfo>> {
    let disks = get_disks()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(disks
        .iter()
        .map(|d| PyDiskInfo {
            device: d.device.clone(),
            mount_point: d.mount_point.clone(),
            fs_type: d.fs_type.clone(),
            total_bytes: d.total_bytes,
            used_bytes: d.used_bytes,
            available_bytes: d.available_bytes,
            usage_percent: d.usage_percent,
        })
        .collect())
}

#[pyfunction]
pub fn get_connections() -> PyResult<Vec<PySocketConnection>> {
    let connections = get_all_connections()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(connections
        .values()
        .flatten()
        .map(|c| PySocketConnection {
            protocol: c.protocol.to_string(),
            local_addr: c.local_addr.to_string(),
            remote_addr: c
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: c.state.to_string(),
            pid: c.pid.unwrap_or(0),
            inode: c.inode,
        })
        .collect())
}

#[pyfunction]
pub fn get_processes() -> PyResult<Vec<PyProcessInfo>> {
    let processes = list_processes()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(processes
        .iter()
        .map(|p| PyProcessInfo {
            pid: p.pid,
            name: p.name.clone(),
            command: p.cmdline.join(" "),
            status: p.state.to_string(),
            memory_usage: p.memory_bytes as u64,
        })
        .collect())
}

#[pyfunction]
pub fn get_process_count() -> PyResult<usize> {
    let processes = list_processes()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(processes.len())
}

#[pyfunction]
pub fn get_process_by_pid(pid: u32) -> PyResult<Option<PyProcessInfo>> {
    let processes = list_processes()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(processes
        .iter()
        .find(|p| p.pid == pid)
        .map(|p| PyProcessInfo {
            pid: p.pid,
            name: p.name.clone(),
            command: p.cmdline.join(" "),
            status: p.state.to_string(),
            memory_usage: p.memory_bytes as u64,
        }))
}

#[pyfunction]
pub fn get_connection_by_pid(pid: u32) -> PyResult<Option<PySocketConnection>> {
    let connections = get_all_connections()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(connections
        .values()
        .flatten()
        .find(|c| c.pid == Some(pid))
        .map(|r| PySocketConnection {
            protocol: r.protocol.to_string(),
            local_addr: r.local_addr.to_string(),
            remote_addr: r
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: r.state.to_string(),
            pid: r.pid.unwrap_or(0),
            inode: r.inode,
        }))
}

#[pyfunction]
pub fn get_connection_by_inode(inode: u64) -> PyResult<Option<PySocketConnection>> {
    let connections = get_all_connections()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(connections
        .values()
        .flatten()
        .find(|c| c.inode == inode)
        .map(|r| PySocketConnection {
            protocol: r.protocol.to_string(),
            local_addr: r.local_addr.to_string(),
            remote_addr: r
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: r.state.to_string(),
            pid: r.pid.unwrap_or(0),
            inode: r.inode,
        }))
}

#[pyfunction]
pub fn get_connection_by_local_addr(local_addr: String) -> PyResult<Option<PySocketConnection>> {
    let parsed: SocketAddr = local_addr.parse().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid local_addr: {e}"))
    })?;
    let connections = get_all_connections()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(connections
        .values()
        .flatten()
        .find(|c| c.local_addr == parsed)
        .map(|r| PySocketConnection {
            protocol: r.protocol.to_string(),
            local_addr: r.local_addr.to_string(),
            remote_addr: r
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: r.state.to_string(),
            pid: r.pid.unwrap_or(0),
            inode: r.inode,
        }))
}

#[pyfunction]
pub fn get_connection_by_remote_addr(remote_addr: String) -> PyResult<Option<PySocketConnection>> {
    let parsed: SocketAddr = remote_addr.parse().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid remote_addr: {e}"))
    })?;
    let connections = get_all_connections()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    Ok(connections
        .values()
        .flatten()
        .find(|c| c.remote_addr == Some(parsed))
        .map(|r| PySocketConnection {
            protocol: r.protocol.to_string(),
            local_addr: r.local_addr.to_string(),
            remote_addr: r
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: r.state.to_string(),
            pid: r.pid.unwrap_or(0),
            inode: r.inode,
        }))
}

#[pyfunction]
pub fn get_connection_by_state(state: String) -> PyResult<Vec<PySocketConnection>> {
    let socket_state = SocketState::try_from(state.as_str()).map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("invalid state: {state}"))
    })?;
    let connections = get_all_connections()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;
    let result = connections.get(&socket_state).cloned().unwrap_or_default();
    Ok(result
        .iter()
        .map(|c| PySocketConnection {
            protocol: c.protocol.to_string(),
            local_addr: c.local_addr.to_string(),
            remote_addr: c
                .remote_addr
                .unwrap_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .to_string(),
            state: c.state.to_string(),
            pid: c.pid.unwrap_or(0),
            inode: c.inode,
        })
        .collect())
}

#[pyfunction]
pub fn list_dir(path: String) -> PyResult<Vec<PyDirEntry>> {
    let entries = std::fs::read_dir(&path).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyOSError, _>(format!("list_dir({path}): {e}"))
    })?;
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
        result.push(PyDirEntry {
            name,
            path: full_path,
            is_dir,
            size,
        });
    }
    result.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
    Ok(result)
}

#[pyfunction]
pub fn kill_process(pid: u32) -> PyResult<()> {
    query_system_info::process::kill_process(pid).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("kill_process: {e}"))
    })
}

#[pyfunction]
pub fn start_tracking_children(pid: u32, callback: Py<PyAny>) -> PyResult<PyProcessTracker> {
    let tracker = query_system_info::process::start_tracking_children(pid, move |event| {
        if let Some(_py) = pyo3::Python::try_attach(|py| {
            let py_event = PyChildProcessEvent {
                pid: event.pid,
                ppid: event.ppid,
                name: event.name,
                cmdline: event.cmdline,
                exe_path: event.exe_path,
                start_time: event.start_time,
            };
            let dict = PyDict::new(py);
            let _ = dict.set_item("pid", py_event.pid);
            let _ = dict.set_item("ppid", py_event.ppid);
            let _ = dict.set_item("name", &py_event.name);
            let _ = dict.set_item("cmdline", &py_event.cmdline);
            let _ = dict.set_item("exe_path", &py_event.exe_path);
            let _ = dict.set_item("start_time", py_event.start_time);
            let _ = callback.call1(py, (dict,));
        }) {}
    })
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("{:?}", e)))?;

    Ok(PyProcessTracker {
        tracker: Arc::new(Mutex::new(Some(tracker))),
    })
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
    m.add_class::<PyDirEntry>()?;
    m.add_class::<PyChildProcessEvent>()?;
    m.add_class::<PyProcessTracker>()?;
    m.add_function(wrap_pyfunction!(py_get_cpu_usage, m.py())?)?;
    m.add_function(wrap_pyfunction!(py_get_cpu_info, m.py())?)?;
    m.add_function(wrap_pyfunction!(py_get_memory_info, m.py())?)?;
    m.add_function(wrap_pyfunction!(py_get_disks, m.py())?)?;
    m.add_function(wrap_pyfunction!(py_get_socket_summary, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connections, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_processes, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_process_count, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_process_by_pid, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_pid, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_inode, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_local_addr, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_remote_addr, m.py())?)?;
    m.add_function(wrap_pyfunction!(get_connection_by_state, m.py())?)?;
    m.add_function(wrap_pyfunction!(list_dir, m.py())?)?;
    m.add_function(wrap_pyfunction!(kill_process, m.py())?)?;
    m.add_function(wrap_pyfunction!(start_tracking_children, m.py())?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_connections() {
        let connections = get_connections().expect("get_connections failed");
        assert!(!connections.is_empty());
    }
    #[test]
    fn test_get_processes() {
        let processes = get_processes().expect("get_processes failed");
        assert!(!processes.is_empty());
    }
    #[test]
    fn test_get_process_count() {
        let process_count = get_process_count().expect("get_process_count failed");
        assert!(process_count > 0);
    }
}
