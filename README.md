# query_system_info

一个跨平台系统信息查询库，使用 Rust 编写，支持内存、CPU、进程、磁盘及网络套接字信息的采集，并提供 CLI 工具、Node.js 绑定和 Python 绑定。

---

## 目录

- [功能特性](#功能特性)
- [平台支持](#平台支持)
- [项目结构](#项目结构)
- [模块介绍](#模块介绍)
- [快速开始](#快速开始)
- [使用教程](#使用教程)
  - [Rust 库](#rust-库)
  - [CLI 工具](#cli-工具)
  - [Node.js 绑定](#nodejs-绑定)
  - [Python 绑定](#python-绑定)
- [交叉编译](#交叉编译)
- [API 参考](#api-参考)
- [许可证](#许可证)

---

## 功能特性

| 功能 | 说明 |
|------|------|
| **内存信息** | 总内存、已用、可用、空闲、使用率、交换分区 |
| **CPU 信息** | 型号、厂商、物理核心数、逻辑核心数、主频、各核心实时使用率 |
| **进程信息** | PID、父 PID、进程名、可执行路径、命令行参数、状态、内存占用、线程数、启动时间、用户 |
| **磁盘信息** | 设备名、挂载点、文件系统类型、总容量、已用、可用、使用率 |
| **磁盘 I/O** | 设备级读写次数、读写字节数、读写耗时 |
| **网络套接字** | TCP/UDP 连接列表（IPv4/IPv6）、连接状态分类、状态汇总 |
| **系统汇总** | 一次调用获取全部系统信息快照 |

---

## 平台支持

| 功能 | Linux | macOS | Windows |
|------|-------|-------|---------|
| 内存 | `/proc/meminfo` | `host_statistics64` | `GlobalMemoryStatusEx` |
| CPU | `/proc/cpuinfo`, `/proc/stat` | `sysctl`, `host_processor_info` | `GetSystemInfo`, `GetSystemTimes` |
| 进程 | `/proc/[pid]/` | `sysctl KERN_PROC` | `EnumProcesses`, `OpenProcess` |
| 磁盘 | `/proc/mounts`, `statvfs` | `getfsstat` | `GetLogicalDriveStringsW` |
| 磁盘 I/O | `/proc/diskstats` | `iostat` | WMI |
| 套接字 | **Netlink** `SOCK_DIAG` | `netstat` 系统调用 | `GetExtendedTcpTable` |

> **Linux 特别说明**：套接字模块使用 Netlink `SOCK_DIAG` 接口直接从内核枚举套接字，效率优于解析 `/proc/net/*` 文件。

---

## 项目结构

```
query_system_info/
├── Cargo.toml              # Workspace 根配置
├── Makefile                # 构建脚本（含交叉编译）
├── src/
│   ├── lib.rs              # 库入口，公开所有模块
│   ├── main.rs             # CLI 二进制入口
│   ├── types.rs            # 公共数据类型定义
│   ├── error.rs            # 错误类型定义
│   ├── memory.rs           # 内存信息模块
│   ├── cpu.rs              # CPU 信息模块
│   ├── process.rs          # 进程信息模块
│   ├── disk.rs             # 磁盘信息模块
│   ├── socket.rs           # 网络套接字模块
│   └── util.rs             # 工具函数
├── examples/
│   ├── basic_usage.rs      # Rust 用法示例
│   ├── basic_usage.js      # Node.js 用法示例
│   └── basic_usage.py      # Python 用法示例
├── js-abi/                 # Node.js NAPI-RS 绑定 crate
│   ├── Cargo.toml
│   ├── package.json
│   └── src/lib.rs
└── py-abi/                 # Python PyO3/maturin 绑定 crate
    ├── Cargo.toml
    ├── pyproject.toml
    └── src/lib.rs
```

---

## 模块介绍

### `src/types.rs` — 公共数据类型

定义全库共用的数据结构：

| 类型 | 说明 |
|------|------|
| `MemoryInfo` | 内存信息：总量、可用、已用、空闲、使用率、交换分区 |
| `CpuInfo` | CPU 信息：物理/逻辑核心数、型号、厂商、主频、使用率 |
| `CpuTimes` | CPU 各状态时间片（user、system、idle、nice、iowait 等） |
| `ProcessInfo` | 进程详情：PID、名称、路径、命令行、状态、内存、线程数等 |
| `ProcessState` | 进程状态枚举：Running / Sleeping / Stopped / Zombie / Idle / Unknown |
| `DiskInfo` | 磁盘分区信息：设备、挂载点、文件系统类型、容量 |
| `DiskIoStats` | 磁盘 I/O 统计：读写次数、读写字节数、耗时 |
| `SocketConnection` | 单条套接字连接：协议、本地地址、远端地址、状态、PID、inode |
| `SocketProtocol` | 协议类型枚举：TcpV4 / TcpV6 / UdpV4 / UdpV6 |
| `SocketState` | 连接状态枚举：Established / Listen / TimeWait / CloseWait 等 11 种状态 |
| `SocketStateSummary` | 各状态连接数的汇总统计 |

---

### `src/error.rs` — 错误类型

基于 `thiserror` 定义统一错误枚举 `SysInfoError`：

| 变体 | 触发场景 |
|------|----------|
| `Io` | 读取系统文件或执行系统调用时的 IO 错误 |
| `Parse` | 解析系统文件内容失败 |
| `SysCall` | 系统调用返回错误码 |
| `NotSupported` | 当前平台不支持该功能 |
| `PermissionDenied` | 权限不足（如访问其他用户的进程） |
| `ProcessNotFound` | 指定 PID 的进程不存在 |
| `Netlink` | Linux Netlink 通信错误 |
| `WindowsApi` | Windows API 调用失败 |

---

### `src/memory.rs` — 内存模块

```rust
pub fn get_memory_info() -> Result<MemoryInfo>
```

跨平台获取内存信息。返回包含 total、available、used、free、usage_percent 以及交换分区信息的 `MemoryInfo` 结构体。

---

### `src/cpu.rs` — CPU 模块

```rust
pub fn get_cpu_info() -> Result<CpuInfo>
pub fn get_cpu_usage(sample_duration: Duration) -> Result<Vec<f64>>
pub fn get_cpu_times() -> Result<Vec<CpuTimes>>
```

- `get_cpu_info`：静态 CPU 信息（型号、核心数、主频等）。
- `get_cpu_usage`：通过两次采样计算各核心实时使用率（需要传入采样间隔，会阻塞对应时长）。
- `get_cpu_times`：获取各核心原始时间片数据，可用于自定义使用率计算。

---

### `src/process.rs` — 进程模块

```rust
pub fn list_processes() -> Result<Vec<ProcessInfo>>
pub fn get_process_info(pid: u32) -> Result<ProcessInfo>
```

- `list_processes`：枚举系统中所有当前运行的进程。
- `get_process_info`：查询指定 PID 的进程详情。

Linux 实现从 `/proc/[pid]/stat`、`/proc/[pid]/status`、`/proc/[pid]/cmdline` 和 `/proc/[pid]/exe` 读取信息；macOS 使用 `sysctl KERN_PROC`；Windows 使用 `EnumProcesses` + `OpenProcess`。

---

### `src/disk.rs` — 磁盘模块

```rust
pub fn get_disks() -> Result<Vec<DiskInfo>>
pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>>
```

- `get_disks`：列举所有已挂载的物理磁盘分区及其空间使用情况（自动过滤 tmpfs、devfs 等虚拟文件系统）。
- `get_disk_io_stats`：获取设备级读写统计（Linux 读取 `/proc/diskstats`；macOS 调用 `iostat`；Windows 使用 WMI）。

---

### `src/socket.rs` — 网络套接字模块

```rust
pub fn get_tcp_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_udp_sockets()     -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_all_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_socket_summary()  -> Result<SocketStateSummary>

// 细粒度查询
pub fn get_tcp4_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_tcp6_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_udp4_sockets()     -> Result<HashMap<SocketState, Vec<SocketConnection>>>
pub fn get_udp6_sockets()     -> Result<HashMap<SocketState, Vec<SocketConnection>>>
```

返回值以 `SocketState` 为 key 的 `HashMap` 组织，方便按状态快速过滤连接列表。`get_socket_summary` 返回所有状态的连接数统计。

---

### `src/lib.rs` — 库入口

提供一站式汇总接口：

```rust
pub fn get_system_summary() -> Result<SystemSummary>
```

`SystemSummary` 包含：`memory`、`cpu`、`disks`、`socket_summary`、`process_count`。

---

### `js-abi/` — Node.js 绑定

基于 [NAPI-RS](https://napi.rs/) 将核心库封装为 Node.js 原生模块（`.node`），提供：

- `JsSystemSummary` 类：构造时一次性采集所有系统信息，通过方法按需读取。
- 独立函数：`jsGetCpuUsage`、`jsGetCpuInfo`、`jsGetMemoryInfo`、`jsGetDisks`、`jsGetSocketSummary`、`getConnections`、`getProcesses` 等。

所有数值在 JavaScript 侧均以 `number`（`f64`）类型表示以规避 JS 整型溢出问题。

---

### `py-abi/` — Python 绑定

基于 [PyO3](https://pyo3.rs/) + [maturin](https://www.maturin.rs/) 将核心库打包为 Python wheel（`py_query_system_info`），提供：

- `PySystemSummary` 类：同 JS 绑定，一次性采集所有系统信息。
- 独立函数：`get_connections`、`get_processes`、`get_process_count`、`get_process_by_pid`、`get_connection_by_pid`、`get_connection_by_inode`、`get_connection_by_local_addr`、`get_connection_by_remote_addr`、`get_connection_by_state` 等。

---

## 快速开始

### 环境要求

- **Rust**：1.85+（`js-abi`/`py-abi` 使用 Edition 2024）
- **Node.js 绑定**：Node.js 16+、Yarn
- **Python 绑定**：Python 3.8+、`python3-dev`、`maturin`

更新 Rust 工具链：

```bash
rustup update stable
```

---

### 构建

```bash
# 检查全工作区
cargo check --workspace

# 构建（调试版）
cargo build --workspace

# 构建（发布版，输出到 dist/）
make build

# 运行所有测试（15 个单元测试）
cargo test --workspace

# Lint 检查
cargo clippy --workspace

# 代码格式检查
cargo fmt --check
```

---

## 使用教程

### Rust 库

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
query_system_info = { path = "." }
```

#### 内存信息

```rust
use query_system_info::memory;

let mem = memory::get_memory_info()?;
println!("总内存：{} MB", mem.total / 1024 / 1024);
println!("已使用：{} MB ({:.1}%)", mem.used / 1024 / 1024, mem.usage_percent);
println!("可用：{} MB", mem.available / 1024 / 1024);
if mem.swap_total > 0 {
    println!("交换分区：{}/{} MB", mem.swap_used / 1024 / 1024, mem.swap_total / 1024 / 1024);
}
```

#### CPU 信息与实时使用率

```rust
use query_system_info::cpu;
use std::time::Duration;

let info = cpu::get_cpu_info()?;
println!("型号：{}", info.model_name);
println!("物理核心：{}，逻辑核心：{}", info.physical_cores, info.logical_cores);

// 采样 500ms 后返回各核心使用率
let usage = cpu::get_cpu_usage(Duration::from_millis(500))?;
for (i, u) in usage.iter().enumerate() {
    println!("Core {}: {:.1}%", i, u);
}
```

#### 进程信息

```rust
use query_system_info::process;

// 列举所有进程
let processes = process::list_processes()?;
println!("当前进程数：{}", processes.len());

// 按内存降序排列，显示 Top 10
let mut sorted = processes.clone();
sorted.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));
for p in sorted.iter().take(10) {
    println!("[{}] {} - {} MB ({})", p.pid, p.name, p.memory_bytes / 1024 / 1024, p.state);
}

// 查询指定 PID
let pid = std::process::id();
let info = process::get_process_info(pid)?;
println!("当前进程：{} ({})", info.name, info.exe_path);
```

#### 磁盘信息

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

// 磁盘 I/O 统计（Linux 精确，其他平台有限支持）
match disk::get_disk_io_stats() {
    Ok(stats) => {
        for s in &stats {
            if s.bytes_read > 0 || s.bytes_written > 0 {
                println!("{}: 读 {} MB，写 {} MB",
                    s.device,
                    s.bytes_read / 1024 / 1024,
                    s.bytes_written / 1024 / 1024
                );
            }
        }
    }
    Err(e) => eprintln!("无法获取磁盘 I/O 统计：{}", e),
}
```

#### 网络套接字

```rust
use query_system_info::socket;
use query_system_info::types::SocketState;

// 汇总统计
let summary = socket::get_socket_summary()?;
println!("总连接数：{}", summary.total);
println!("ESTABLISHED: {}", summary.established);
println!("LISTEN:      {}", summary.listen);
println!("TIME_WAIT:   {}", summary.time_wait);

// 获取 TCP 连接（按状态分组的 HashMap）
let tcp = socket::get_tcp_connections()?;

// 列出所有监听端口
if let Some(listeners) = tcp.get(&SocketState::Listen) {
    println!("\n监听端口 ({}):", listeners.len());
    for conn in listeners {
        println!("  {} -> {}", conn.protocol, conn.local_addr);
    }
}

// 列出已建立的连接
if let Some(established) = tcp.get(&SocketState::Established) {
    for conn in established {
        println!("{} {} -> {:?}", conn.protocol, conn.local_addr, conn.remote_addr);
    }
}
```

#### 系统全量汇总

```rust
use query_system_info::get_system_summary;

let summary = get_system_summary()?;
println!("内存使用率：{:.1}%", summary.memory.usage_percent);
println!("CPU 型号：{}", summary.cpu.model_name);
println!("磁盘数量：{}", summary.disks.len());
println!("进程数量：{}", summary.process_count);
println!("总连接数：{}", summary.socket_summary.total);
```

---

### CLI 工具

直接运行内置 CLI，输出当前系统的完整信息报告：

```bash
# 开发模式运行
cargo run

# 构建发布版后运行
make build
./dist/query_system_info
```

输出示例：

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
  TIME_WAIT:   5
```

---

### Node.js 绑定

#### 构建

```bash
cd js-abi
yarn install
yarn build
# 输出：../dist/index.node
```

#### 使用

```javascript
const sysinfo = require('./dist/index.node');

// ---- 使用 JsSystemSummary 类（推荐，一次采样所有数据）----
// 参数为 CPU 采样时长（秒），默认 1 秒
const summary = new sysinfo.JsSystemSummary(1);

// 内存信息
const mem = summary.getMemoryInfo();
console.log(`内存：${mem.used / 1024 / 1024 / 1024} GB / ${mem.total / 1024 / 1024 / 1024} GB`);

// CPU 信息
const cpu = summary.getCpuInfo();
console.log(`CPU：${cpu.modelName}，${cpu.logicalCores} 核`);

// 各核心使用率（数组）
const cpuUsage = summary.getCpuUsage();
console.log('CPU 使用率：', cpuUsage);

// 磁盘列表
const disks = summary.getDisks();
disks.forEach(d => console.log(`${d.mountPoint}: ${d.usagePercent.toFixed(1)}%`));

// 进程列表
const processes = summary.getProcesses();
console.log(`进程数：${summary.getProcessCount()}`);

// Socket 汇总
const socketSummary = summary.getSocketSummary();
console.log(`ESTABLISHED: ${socketSummary.established}, LISTEN: ${socketSummary.listen}`);

// 连接列表
const connections = summary.getConnections();
connections.forEach(c => {
    console.log(c.protocol, c.localAddr, c.remoteAddr, c.state);
});

// ---- 按条件查询连接 ----
const established = summary.getConnectionByState('ESTABLISHED');
console.log(`ESTABLISHED 连接数：${established.length}`);

// ---- 独立函数调用 ----
const memInfo = sysinfo.jsGetMemoryInfo();
const cpuInfo = sysinfo.jsGetCpuInfo();
const allConns = sysinfo.getConnections();
const allProcs = sysinfo.getProcesses();
```

---

### Python 绑定

#### 构建与安装

```bash
# 安装 maturin
pip install maturin

# 开发模式（直接在当前环境安装，需先从 pyproject.toml 移除 query_system_info 依赖）
maturin develop --manifest-path py-abi/Cargo.toml

# 或构建 wheel 后安装（使用 --no-deps 跳过不存在的 PyPI 依赖）
maturin build --manifest-path py-abi/Cargo.toml
pip install --no-deps target/wheels/py_query_system_info-*.whl
```

#### 使用

```python
import py_query_system_info as sysinfo

# ---- 使用 PySystemSummary 类（推荐）----
# 参数为 CPU 采样时长（秒），默认 1 秒
summary = sysinfo.PySystemSummary(1)

# 内存信息
mem = summary.memory
print(f"内存：{mem.used // 1024 // 1024} MB / {mem.total // 1024 // 1024} MB ({mem.usage_percent:.1f}%)")

# CPU 信息
cpu = summary.cpu
print(f"CPU：{cpu.model_name}，{cpu.logical_cores} 核")
print(f"各核心使用率：{summary.cpu_usage}")

# 磁盘信息
for disk in summary.disks:
    print(f"{disk.mount_point} ({disk.fs_type}): {disk.usage_percent:.1f}%")

# 进程信息
print(f"进程数：{summary.process_count}")
for p in summary.processes[:5]:
    print(f"  [{p.pid}] {p.name} - {p.memory_usage // 1024 // 1024} MB ({p.status})")

# Socket 汇总
sock = summary.socket_summary
print(f"总连接：{sock.total}，ESTABLISHED：{sock.established}，LISTEN：{sock.listen}")

# ---- 独立查询函数 ----
connections = sysinfo.get_connections()
for c in connections:
    print(c.protocol, c.local_addr, c.remote_addr, c.state, c.pid)

# 按状态过滤
established = sysinfo.get_connection_by_state("ESTABLISHED")

# 按 PID 查找连接
conn = sysinfo.get_connection_by_pid(1234)

# 按 inode 查找连接（Linux）
conn = sysinfo.get_connection_by_inode(12345)

# 进程查询
processes = sysinfo.get_processes()
proc = sysinfo.get_process_by_pid(1)
print(sysinfo.get_process_count())
```

---

## 交叉编译

`Makefile` 支持对主要平台进行交叉编译，输出到 `dist/` 目录。

```bash
# 安装所需目标平台工具链
make install-targets

# 为当前平台构建（默认）
make build

# 指定目标平台
make build PLATFORM=linux-x64
make build PLATFORM=linux-arm64
make build PLATFORM=windows-x64
make build PLATFORM=macos-x64
make build PLATFORM=macos-arm64

# 一次构建所有平台
make all
```

支持的平台与对应 Rust target：

| PLATFORM | Rust Target |
|----------|-------------|
| `linux-x64` | `x86_64-unknown-linux-gnu` |
| `linux-arm64` | `aarch64-unknown-linux-gnu` |
| `windows-x64` | `x86_64-pc-windows-gnu` |
| `macos-x64` | `x86_64-apple-darwin` |
| `macos-arm64` | `aarch64-apple-darwin` |

---

## API 参考

### 核心库函数速查

#### `memory` 模块

| 函数 | 返回类型 | 说明 |
|------|----------|------|
| `get_memory_info()` | `Result<MemoryInfo>` | 获取完整内存信息 |

#### `cpu` 模块

| 函数 | 返回类型 | 说明 |
|------|----------|------|
| `get_cpu_info()` | `Result<CpuInfo>` | 获取 CPU 静态信息 |
| `get_cpu_usage(duration)` | `Result<Vec<f64>>` | 采样指定时长后返回各核心使用率（%） |
| `get_cpu_times()` | `Result<Vec<CpuTimes>>` | 获取各核心原始时间片 |

#### `process` 模块

| 函数 | 返回类型 | 说明 |
|------|----------|------|
| `list_processes()` | `Result<Vec<ProcessInfo>>` | 列举所有进程 |
| `get_process_info(pid)` | `Result<ProcessInfo>` | 获取指定 PID 进程信息 |

#### `disk` 模块

| 函数 | 返回类型 | 说明 |
|------|----------|------|
| `get_disks()` | `Result<Vec<DiskInfo>>` | 列举所有物理磁盘分区 |
| `get_disk_io_stats()` | `Result<Vec<DiskIoStats>>` | 获取磁盘 I/O 统计 |

#### `socket` 模块

| 函数 | 返回类型 | 说明 |
|------|----------|------|
| `get_tcp_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | 所有 TCP 连接（IPv4+IPv6） |
| `get_udp_sockets()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | 所有 UDP 套接字（IPv4+IPv6） |
| `get_all_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | 所有 TCP+UDP 套接字 |
| `get_socket_summary()` | `Result<SocketStateSummary>` | 各状态连接数汇总 |
| `get_tcp4_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | 仅 TCP IPv4 |
| `get_tcp6_connections()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | 仅 TCP IPv6 |
| `get_udp4_sockets()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | 仅 UDP IPv4 |
| `get_udp6_sockets()` | `Result<HashMap<SocketState, Vec<SocketConnection>>>` | 仅 UDP IPv6 |

#### 顶层函数

| 函数 | 返回类型 | 说明 |
|------|----------|------|
| `get_system_summary()` | `Result<SystemSummary>` | 一次调用获取全部系统信息快照 |

---

## 许可证

MIT License — 详见 [LICENSE](./LICENSE)。
