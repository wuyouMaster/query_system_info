<div align="right">
  <strong>English</strong> | <a href="./README.md">简体中文</a>
</div>

# query_system_info

A cross-platform system information library written in Rust. Supports querying memory, CPU, process, disk, and network socket information, with a built-in CLI tool, Node.js bindings, and Python bindings.

---

## Table of Contents

- [Features](#features)
- [Platform Support](#platform-support)
- [Project Structure](#project-structure)
- [Module Overview](#module-overview)
- [Getting Started](#getting-started)
- [Usage Tutorial](#usage-tutorial)
  - [Rust Library](#rust-library)
  - [CLI Tool](#cli-tool)
  - [Node.js Bindings](#nodejs-bindings)
  - [Python Bindings](#python-bindings)
- [Cross Compilation](#cross-compilation)
- [API Reference](#api-reference)
- [License](#license)

---

## Features

| Feature | Description |
|---------|-------------|
| **Memory** | Total, used, available, free memory, usage percentage, swap space |
| **CPU** | Model, vendor, physical/logical core count, frequency, per-core real-time usage |
| **Process** | PID, PPID, name, executable path, command-line args, state, memory usage, thread count, start time, user |
| **Disk** | Device name, mount point, filesystem type, total/used/available capacity, usage percentage |
| **Disk I/O** | Per-device read/write operations, bytes transferred, elapsed time |
| **Network Sockets** | TCP/UDP connection list (IPv4/IPv6), state-grouped connections, state summary |
| **System Summary** | Single call to snapshot all system information at once |

---

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Memory | `/proc/meminfo` | `host_statistics64` | `GlobalMemoryStatusEx` |
| CPU | `/proc/cpuinfo`, `/proc/stat` | `sysctl`, `host_processor_info` | `GetSystemInfo`, `GetSystemTimes` |
| Process | `/proc/[pid]/` | `sysctl KERN_PROC` | `EnumProcesses`, `OpenProcess` |
| Disk | `/proc/mounts`, `statvfs` | `getfsstat` | `GetLogicalDriveStringsW` |
| Disk I/O | `/proc/diskstats` | `iostat` | WMI |
| Sockets | **Netlink** `SOCK_DIAG` | `netstat` syscalls | `GetExtendedTcpTable` |

> **Linux note**: The socket module uses the Netlink `SOCK_DIAG` interface to enumerate sockets directly from the kernel, which is more efficient than parsing `/proc/net/*` files.

---

## Project Structure

```
query_system_info/
├── Cargo.toml              # Workspace root configuration
├── Makefile                # Build scripts (including cross-compilation)
├── src/
│   ├── lib.rs              # Library entry point, re-exports all modules
│   ├── main.rs             # CLI binary entry point
│   ├── types.rs            # Shared data type definitions
│   ├── error.rs            # Error type definitions
│   ├── memory.rs           # Memory information module
│   ├── cpu.rs              # CPU information module
│   ├── process.rs          # Process information module
│   ├── disk.rs             # Disk information module
│   ├── socket.rs           # Network socket module
│   └── util.rs             # Utility functions
├── examples/
│   ├── basic_usage.rs      # Rust usage example
│   ├── basic_usage.js      # Node.js usage example
│   └── basic_usage.py      # Python usage example
├── js-abi/                 # Node.js NAPI-RS bindings crate
│   ├── Cargo.toml
│   ├── package.json
│   └── src/lib.rs
└── py-abi/                 # Python PyO3/maturin bindings crate
    ├── Cargo.toml
    ├── pyproject.toml
    └── src/lib.rs
```

---

## Module Overview

### `src/types.rs` — Shared Data Types

Defines all common data structures used across the library:

| Type | Description |
|------|-------------|
| `MemoryInfo` | Memory info: total, available, used, free, usage percentage, swap |
| `CpuInfo` | CPU info: physical/logical cores, model name, vendor, frequency, usage |
| `CpuTimes` | Per-core CPU time slices (user, system, idle, nice, iowait, etc.) |
| `ProcessInfo` | Process details: PID, name, path, cmdline, state, memory, thread count, etc. |
| `ProcessState` | Process state enum: Running / Sleeping / Stopped / Zombie / Idle / Unknown |
| `DiskInfo` | Disk partition info: device, mount point, filesystem type, capacity |
| `DiskIoStats` | Disk I/O stats: read/write ops count, bytes transferred, elapsed time |
| `SocketConnection` | Single socket connection: protocol, local/remote address, state, PID, inode |
| `SocketProtocol` | Protocol enum: TcpV4 / TcpV6 / UdpV4 / UdpV6 |
| `SocketState` | Connection state enum: 11 states including Established, Listen, TimeWait, CloseWait |
| `SocketStateSummary` | Aggregated connection count per state |

---

### `src/error.rs` — Error Types

Unified error enum `SysInfoError` built on `thiserror`:

| Variant | When it occurs |
|---------|----------------|
| `Io` | IO errors when reading system files or making syscalls |
| `Parse` | Failed to parse system file contents |
| `SysCall` | A system call returned an error code |
| `NotSupported` | Feature not supported on the current platform |
| `PermissionDenied` | Insufficient permissions (e.g. accessing another user's process) |
| `ProcessNotFound` | No process found with the given PID |
| `Netlink` | Linux Netlink communication error |
| `WindowsApi` | Windows API call failed |

---

### `src/memory.rs` — Memory Module

```rust
pub fn get_memory_info() -> Result<MemoryInfo>
```

Cross-platform memory query. Returns a `MemoryInfo` struct with total, available, used, free, usage_percent, and swap info.

---

### `src/cpu.rs` — CPU Module

```rust
pub fn get_cpu_info() -> Result<CpuInfo>
pub fn get_cpu_usage(sample_duration: Duration) -> Result<Vec<f64>>
pub fn get_cpu_times() -> Result<Vec<CpuTimes>>
```

- `get_cpu_info`: Static CPU information (model, core counts, frequency, etc.).
- `get_cpu_usage`: Calculates real-time per-core usage by taking two samples separated by `sample_duration` (blocks for that duration).
- `get_cpu_times`: Returns raw per-core time slice data for custom usage calculations.

---

### `src/process.rs` — Process Module

```rust
pub fn list_processes() -> Result<Vec<ProcessInfo>>
pub fn get_process_info(pid: u32) -> Result<ProcessInfo>
```

- `list_processes`: Enumerates all currently running processes.
- `get_process_info`: Queries details for a specific PID.

On Linux, reads from `/proc/[pid]/stat`, `/proc/[pid]/status`, `/proc/[pid]/cmdline`, and `/proc/[pid]/exe`. On macOS, uses `sysctl KERN_PROC`. On Windows, uses `EnumProcesses` + `OpenProcess`.

---

### `src/disk.rs` — Disk Module

```rust
pub fn get_disks() -> Result<Vec<DiskInfo>>
pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>>
```

- `get_disks`: Lists all mounted physical disk partitions and their space usage (automatically filters virtual filesystems like tmpfs, devfs).
- `get_disk_io_stats`: Retrieves device-level read/write statistics. Linux reads `/proc/diskstats`; macOS invokes `iostat`; Windows uses WMI.

---

### `src/socket.rs` — Network Socket Module

```rust
pub fn get_tcp_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_udp_sockets()     -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_all_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_socket_summary()  -> Result<SocketStateSummary>

// Fine-grained queries
pub fn get_tcp4_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_tcp6_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_udp4_sockets()     -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_udp6_sockets()     -> Result<HashMap<SocketState, Vec<SocketConnection>>>
```

Results are organized as a `HashMap` keyed by `SocketState` for fast filtering by connection state. `get_socket_summary` returns aggregate connection counts per state.

---

### `src/lib.rs` — Library Entry

Provides a single convenience function:

```rust
pub fn get_system_summary() -> Result<SystemSummary>
```

`SystemSummary` contains: `memory`, `cpu`, `disks`, `socket_summary`, `process_count`.

---

### `js-abi/` — Node.js Bindings

Built with [NAPI-RS](https://napi.rs/), wraps the core library as a native Node.js module (`.node` file). Provides:

- `JsSystemSummary` class: Collects all system information at construction time; use methods to retrieve individual sections.
- Standalone functions: `jsGetCpuUsage`, `jsGetCpuInfo`, `jsGetMemoryInfo`, `jsGetDisks`, `jsGetSocketSummary`, `getConnections`, `getProcesses`, etc.

All numeric values are exposed as `number` (`f64`) on the JavaScript side to avoid integer overflow issues.

---

### `py-abi/` — Python Bindings

Built with [PyO3](https://pyo3.rs/) + [maturin](https://www.maturin.rs/), packages the core library as a Python wheel (`py_query_system_info`). Provides:

- `PySystemSummary` class: Same as the JS binding — collects all system info in one shot.
- Standalone functions: `get_connections`, `get_processes`, `get_process_count`, `get_process_by_pid`, `get_connection_by_pid`, `get_connection_by_inode`, `get_connection_by_local_addr`, `get_connection_by_remote_addr`, `get_connection_by_state`, etc.

---

## Getting Started

### Prerequisites

- **Rust**: 1.85+ (`js-abi`/`py-abi` use Edition 2024)
- **Node.js bindings**: Node.js 16+, Yarn
- **Python bindings**: Python 3.8+, `python3-dev`, `maturin`

Update the Rust toolchain:

```bash
rustup update stable
```

---

### Build

```bash
# Check entire workspace
cargo check --workspace

# Debug build
cargo build --workspace

# Release build (outputs to dist/)
make build

# Run all tests (15 unit tests)
cargo test --workspace

# Lint
cargo clippy --workspace

# Format check
cargo fmt --check
```

---

## Usage Tutorial

### Rust Library

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
query_system_info = { path = "." }
```

#### Memory Information

```rust
use query_system_info::memory;

let mem = memory::get_memory_info()?;
println!("Total:     {} MB", mem.total / 1024 / 1024);
println!("Used:      {} MB ({:.1}%)", mem.used / 1024 / 1024, mem.usage_percent);
println!("Available: {} MB", mem.available / 1024 / 1024);
if mem.swap_total > 0 {
    println!("Swap: {}/{} MB", mem.swap_used / 1024 / 1024, mem.swap_total / 1024 / 1024);
}
```

#### CPU Information & Real-Time Usage

```rust
use query_system_info::cpu;
use std::time::Duration;

let info = cpu::get_cpu_info()?;
println!("Model:    {}", info.model_name);
println!("Cores:    {} physical, {} logical", info.physical_cores, info.logical_cores);

// Samples for 500ms, then returns per-core usage
let usage = cpu::get_cpu_usage(Duration::from_millis(500))?;
for (i, u) in usage.iter().enumerate() {
    println!("Core {}: {:.1}%", i, u);
}
```

#### Process Information

```rust
use query_system_info::process;

// List all processes
let processes = process::list_processes()?;
println!("Total processes: {}", processes.len());

// Sort by memory and show Top 10
let mut sorted = processes.clone();
sorted.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));
for p in sorted.iter().take(10) {
    println!("[{}] {} - {} MB ({})", p.pid, p.name, p.memory_bytes / 1024 / 1024, p.state);
}

// Query a specific PID
let pid = std::process::id();
let info = process::get_process_info(pid)?;
println!("Current process: {} ({})", info.name, info.exe_path);
```

#### Disk Information

```rust
use query_system_info::disk;

let disks = disk::get_disks()?;
for d in &disks {
    println!("{} ({}) - {}/{} GB ({:.1}%)",
        d.mount_point, d.fs_type,
        d.used_bytes / 1024 / 1024 / 1024,
        d.total_bytes / 1024 / 1024 / 1024,
        d.usage_percent
    );
}

// Disk I/O stats (precise on Linux; limited on other platforms)
match disk::get_disk_io_stats() {
    Ok(stats) => {
        for s in &stats {
            if s.bytes_read > 0 || s.bytes_written > 0 {
                println!("{}: read {} MB, written {} MB",
                    s.device,
                    s.bytes_read / 1024 / 1024,
                    s.bytes_written / 1024 / 1024
                );
            }
        }
    }
    Err(e) => eprintln!("Could not get disk I/O stats: {}", e),
}
```

#### Network Sockets

```rust
use query_system_info::socket;
use query_system_info::types::SocketState;

// Aggregate summary
let summary = socket::get_socket_summary()?;
println!("Total connections: {}", summary.total);
println!("ESTABLISHED: {}", summary.established);
println!("LISTEN:      {}", summary.listen);
println!("TIME_WAIT:   {}", summary.time_wait);

// TCP connections grouped by state (HashMap)
let tcp = socket::get_tcp_connections()?;

// List all listening ports
if let Some(listeners) = tcp.get(&SocketState::Listen) {
    println!("\nListening ({}):", listeners.len());
    for conn in listeners {
        println!("  {} -> {}", conn.protocol, conn.local_addr);
    }
}

// List established connections
if let Some(established) = tcp.get(&SocketState::Established) {
    for conn in established {
        println!("{} {} -> {:?}", conn.protocol, conn.local_addr, conn.remote_addr);
    }
}
```

#### Full System Snapshot

```rust
use query_system_info::get_system_summary;

let summary = get_system_summary()?;
println!("Memory usage:  {:.1}%", summary.memory.usage_percent);
println!("CPU model:     {}", summary.cpu.model_name);
println!("Disks:         {}", summary.disks.len());
println!("Processes:     {}", summary.process_count);
println!("Connections:   {}", summary.socket_summary.total);
```

---

### CLI Tool

Run the built-in CLI to print a complete system information report:

```bash
# Development mode
cargo run

# After building a release binary
make build
./dist/query_system_info
```

Sample output:

```
=== System Information Query ===

--- Memory Information ---
Total:         16384 MB
Used:           8192 MB (50.0%)
Available:      7680 MB
Free:            512 MB

--- CPU Information ---
Model:          Apple M2
Physical cores: 8
Logical cores:  8
CPU Usage:      Core 0: 12.3%  Core 1: 8.7% ...

--- Disk Information ---
/                    120 GB /   500 GB (24.0%) [apfs]

--- Process Information ---
Total processes: 312
Top 10 processes by memory:
     PID  Memory(MB)    State Name
    1234        1024  Sleeping chrome
    ...

--- Socket Information ---
Total connections: 148
  ESTABLISHED: 42
  LISTEN:      18
  TIME_WAIT:    5
```

---

### Node.js Bindings

#### Build

```bash
cd js-abi
yarn install
yarn build
# Output: ../dist/index.node
```

#### Usage

```javascript
const sysinfo = require('./dist/index.node');

// ---- Using JsSystemSummary (recommended — one snapshot, all data) ----
// Constructor argument: CPU sampling duration in seconds (default: 1)
const summary = new sysinfo.JsSystemSummary(1);

// Memory
const mem = summary.getMemoryInfo();
console.log(`Memory: ${mem.used / 1024**3} GB / ${mem.total / 1024**3} GB`);

// CPU
const cpu = summary.getCpuInfo();
console.log(`CPU: ${cpu.modelName}, ${cpu.logicalCores} cores`);
console.log('Per-core usage:', summary.getCpuUsage());

// Disks
summary.getDisks().forEach(d =>
    console.log(`${d.mountPoint}: ${d.usagePercent.toFixed(1)}%`)
);

// Processes
console.log('Process count:', summary.getProcessCount());
summary.getProcesses().forEach(p =>
    console.log(p.pid, p.name, p.memoryUsage)
);

// Socket summary
const sockSummary = summary.getSocketSummary();
console.log(`ESTABLISHED: ${sockSummary.established}, LISTEN: ${sockSummary.listen}`);

// All connections
summary.getConnections().forEach(c =>
    console.log(c.protocol, c.localAddr, c.remoteAddr, c.state)
);

// Filter connections by state
const established = summary.getConnectionByState('ESTABLISHED');
console.log(`ESTABLISHED count: ${established.length}`);

// ---- Standalone functions ----
const memInfo  = sysinfo.jsGetMemoryInfo();
const cpuInfo  = sysinfo.jsGetCpuInfo();
const allConns = sysinfo.getConnections();
const allProcs = sysinfo.getProcesses();
```

---

### Python Bindings

#### Build & Install

```bash
# Install maturin
pip install maturin

# Development mode (installs directly into the current environment)
# First remove the `query_system_info` dependency from py-abi/pyproject.toml
maturin develop --manifest-path py-abi/Cargo.toml

# Or build a wheel and install with --no-deps
maturin build --manifest-path py-abi/Cargo.toml
pip install --no-deps target/wheels/py_query_system_info-*.whl
```

#### Usage

```python
import py_query_system_info as sysinfo

# ---- Using PySystemSummary (recommended) ----
# Argument: CPU sampling duration in seconds (default: 1)
summary = sysinfo.PySystemSummary(1)

# Memory
mem = summary.memory
print(f"Memory: {mem.used // 1024**2} MB / {mem.total // 1024**2} MB ({mem.usage_percent:.1f}%)")

# CPU
cpu = summary.cpu
print(f"CPU: {cpu.model_name}, {cpu.logical_cores} cores")
print(f"Per-core usage: {summary.cpu_usage}")

# Disks
for disk in summary.disks:
    print(f"{disk.mount_point} ({disk.fs_type}): {disk.usage_percent:.1f}%")

# Processes
print(f"Process count: {summary.process_count}")
for p in summary.processes[:5]:
    print(f"  [{p.pid}] {p.name} - {p.memory_usage // 1024**2} MB ({p.status})")

# Socket summary
sock = summary.socket_summary
print(f"Total: {sock.total}, ESTABLISHED: {sock.established}, LISTEN: {sock.listen}")

# ---- Standalone query functions ----
connections = sysinfo.get_connections()
for c in connections:
    print(c.protocol, c.local_addr, c.remote_addr, c.state, c.pid)

# Filter by state
established = sysinfo.get_connection_by_state("ESTABLISHED")

# Lookup by PID
conn = sysinfo.get_connection_by_pid(1234)

# Lookup by inode (Linux)
conn = sysinfo.get_connection_by_inode(12345)

# Process queries
processes = sysinfo.get_processes()
proc      = sysinfo.get_process_by_pid(1)
count     = sysinfo.get_process_count()
```

---

## Cross Compilation

The `Makefile` supports cross-compiling for all major platforms, with output placed in `dist/`.

```bash
# Install required toolchain targets
make install-targets

# Build for the current platform (default)
make build

# Build for a specific platform
make build PLATFORM=linux-x64
make build PLATFORM=linux-arm64
make build PLATFORM=windows-x64
make build PLATFORM=macos-x64
make build PLATFORM=macos-arm64

# Build for all platforms at once
make all
```

Supported platforms and their Rust targets:

| PLATFORM | Rust Target |
|----------|-------------|
| `linux-x64` | `x86_64-unknown-linux-gnu` |
| `linux-arm64` | `aarch64-unknown-linux-gnu` |
| `windows-x64` | `x86_64-pc-windows-gnu` |
| `macos-x64` | `x86_64-apple-darwin` |
| `macos-arm64` | `aarch64-apple-darwin` |

---

## API Reference

### Core Library Quick Reference

#### `memory` module

| Function | Return Type | Description |
|----------|-------------|-------------|
| `get_memory_info()` | `Result<MemoryInfo>` | Get complete memory information |

#### `cpu` module

| Function | Return Type | Description |
|----------|-------------|-------------|
| `get_cpu_info()` | `Result<CpuInfo>` | Get static CPU information |
| `get_cpu_usage(duration)` | `Result<Vec<f64>>` | Sample for `duration`, return per-core usage (%) |
| `get_cpu_times()` | `Result<Vec<CpuTimes>>` | Get raw per-core time slices |

#### `process` module

| Function | Return Type | Description |
|----------|-------------|-------------|
| `list_processes()` | `Result<Vec<ProcessInfo>>` | List all running processes |
| `get_process_info(pid)` | `Result<ProcessInfo>` | Get info for a specific PID |

#### `disk` module

| Function | Return Type | Description |
|----------|-------------|-------------|
| `get_disks()` | `Result<Vec<DiskInfo>>` | List all physical disk partitions |
| `get_disk_io_stats()` | `Result<Vec<DiskIoStats>>` | Get disk I/O statistics |

#### `socket` module

| Function | Return Type | Description |
|----------|-------------|-------------|
| `get_tcp_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | All TCP connections (IPv4 + IPv6) |
| `get_udp_sockets()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | All UDP sockets (IPv4 + IPv6) |
| `get_all_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | All TCP + UDP sockets |
| `get_socket_summary()` | `Result<SocketStateSummary>` | Aggregate connection counts by state |
| `get_tcp4_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | TCP IPv4 only |
| `get_tcp6_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | TCP IPv6 only |
| `get_udp4_sockets()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | UDP IPv4 only |
| `get_udp6_sockets()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | UDP IPv6 only |

#### Top-level

| Function | Return Type | Description |
|----------|-------------|-------------|
| `get_system_summary()` | `Result<SystemSummary>` | Single-call full system snapshot |

---

## License

MIT License — see [LICENSE](./LICENSE).
