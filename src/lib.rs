//! # query_system_info
//!
//! A cross-platform library for querying system information including:
//! - Memory usage
//! - CPU information and usage
//! - Process information
//! - Disk space and I/O statistics
//! - Socket/network connection information
//!
//! ## Platform Support
//!
//! This library supports the following platforms with native implementations:
//!
//! | Feature | Linux | macOS | Windows |
//! |---------|-------|-------|---------|
//! | Memory | `/proc/meminfo` | `host_statistics64` | `GlobalMemoryStatusEx` |
//! | CPU | `/proc/cpuinfo`, `/proc/stat` | `sysctl`, `host_processor_info` | `GetSystemInfo`, `GetSystemTimes` |
//! | Process | `/proc/[pid]/` | `sysctl KERN_PROC` | `EnumProcesses`, `OpenProcess` |
//! | Disk | `/proc/mounts`, `statvfs` | `getfsstat` | `GetLogicalDriveStringsW` |
//! | Disk I/O | `/proc/diskstats` | `iostat` | WMI |
//! | Socket | **netlink** `SOCK_DIAG` | `netstat` syscalls | `GetExtendedTcpTable` |
//!
//! ## Example
//!
//! ```rust,no_run
//! use query_system_info::{memory, cpu, process, disk, socket};
//! use std::time::Duration;
//!
//! fn main() -> query_system_info::Result<()> {
//!     // Get memory information
//!     let mem = memory::get_memory_info()?;
//!     println!("Memory: {:.1}% used ({} / {} bytes)",
//!         mem.usage_percent, mem.used, mem.total);
//!
//!     // Get CPU information
//!     let cpu_info = cpu::get_cpu_info()?;
//!     println!("CPU: {} ({} cores)", cpu_info.model_name, cpu_info.logical_cores);
//!
//!     // Get CPU usage (requires sampling)
//!     let cpu_usage = cpu::get_cpu_usage(Duration::from_millis(500))?;
//!     println!("CPU Usage: {:.1}%", cpu_usage);
//!
//!     // List processes
//!     let processes = process::list_processes()?;
//!     println!("Running processes: {}", processes.len());
//!
//!     // Get disk information
//!     let disks = disk::get_disks()?;
//!     for d in &disks {
//!         println!("Disk {}: {:.1}% used", d.mount_point, d.usage_percent);
//!     }
//!
//!     // Get socket summary
//!     let summary = socket::get_socket_summary()?;
//!     println!("Sockets: {} total, {} established, {} listening",
//!         summary.total, summary.established, summary.listen);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Socket Information
//!
//! The socket module provides detailed information about network connections:
//!
//! - **Linux**: Uses the netlink `SOCK_DIAG` interface for efficient kernel-level
//!   socket enumeration without parsing `/proc/net/*` files.
//!
//! - **macOS**: Uses system calls and `netstat`-style parsing to gather connection
//!   information.
//!
//! - **Windows**: Uses the IP Helper API (`GetExtendedTcpTable`, `GetExtendedUdpTable`)
//!   from `iphlpapi.dll` via the `windows` crate.
//!
//! ```rust,no_run
//! use query_system_info::socket;
//!
//! fn main() -> query_system_info::Result<()> {
//!     // Get all TCP connections
//!     let tcp_conns = socket::get_tcp_connections()?;
//!     for conn in &tcp_conns {
//!         println!("{} {} -> {:?} [{}]",
//!             conn.protocol, conn.local_addr, conn.remote_addr, conn.state);
//!     }
//!
//!     // Get socket state summary
//!     let summary = socket::get_socket_summary()?;
//!     println!("Connection states:");
//!     println!("  ESTABLISHED: {}", summary.established);
//!     println!("  LISTEN: {}", summary.listen);
//!     println!("  TIME_WAIT: {}", summary.time_wait);
//!     println!("  CLOSE_WAIT: {}", summary.close_wait);
//!
//!     Ok(())
//! }
//! ```

pub mod cpu;
pub mod disk;
pub mod error;
pub mod memory;
pub mod process;
pub mod socket;
pub mod types;
pub mod util;

// Re-export commonly used types
pub use error::{Result, SysInfoError};
pub use types::*;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get a summary of all system information
pub fn get_system_summary() -> Result<SystemSummary> {
    Ok(SystemSummary {
        memory: memory::get_memory_info()?,
        cpu: cpu::get_cpu_info()?,
        disks: disk::get_disks()?,
        socket_summary: socket::get_socket_summary()?,
        process_count: process::list_processes()?.len(),
    })
}

/// Complete system summary
#[derive(Debug, Clone)]
pub struct SystemSummary {
    /// Memory information
    pub memory: MemoryInfo,
    /// CPU information
    pub cpu: CpuInfo,
    /// Disk information
    pub disks: Vec<DiskInfo>,
    /// Socket state summary
    pub socket_summary: SocketStateSummary,
    /// Number of running processes
    pub process_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_system_summary() {
        let summary = get_system_summary();
        assert!(summary.is_ok(), "Should be able to get system summary");

        let summary = summary.unwrap();
        assert!(summary.memory.total > 0);
        assert!(summary.cpu.logical_cores > 0);
        assert!(summary.process_count > 0);
    }
}
