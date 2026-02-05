//! Common types used across the library

use std::net::SocketAddr;

/// Memory information
#[derive(Debug, Clone, Default)]
pub struct MemoryInfo {
    /// Total physical memory in bytes
    pub total: u64,
    /// Available memory in bytes
    pub available: u64,
    /// Used memory in bytes
    pub used: u64,
    /// Free memory in bytes
    pub free: u64,
    /// Memory usage percentage (0.0 - 100.0)
    pub usage_percent: f64,
    /// Swap total in bytes
    pub swap_total: u64,
    /// Swap used in bytes
    pub swap_used: u64,
    /// Swap free in bytes
    pub swap_free: u64,
    /// Cached memory in bytes (Linux specific)
    pub cached: u64,
    /// Buffer memory in bytes (Linux specific)
    pub buffers: u64,
}

/// CPU information
#[derive(Debug, Clone, Default)]
pub struct CpuInfo {
    /// Number of physical CPU cores
    pub physical_cores: u32,
    /// Number of logical CPU cores (including hyperthreading)
    pub logical_cores: u32,
    /// CPU model name
    pub model_name: String,
    /// CPU vendor
    pub vendor: String,
    /// CPU frequency in MHz
    pub frequency_mhz: u64,
    /// Overall CPU usage percentage (0.0 - 100.0)
    pub usage_percent: f64,
    /// Per-core usage percentages
    pub per_core_usage: Vec<f64>,
}

/// CPU times for calculating usage
#[derive(Debug, Clone, Default)]
pub struct CpuTimes {
    /// Time spent in user mode
    pub user: u64,
    /// Time spent in system/kernel mode
    pub system: u64,
    /// Time spent idle
    pub idle: u64,
    /// Time spent in nice mode (Linux)
    pub nice: u64,
    /// Time spent waiting for I/O (Linux)
    pub iowait: u64,
    /// Time spent servicing interrupts (Linux)
    pub irq: u64,
    /// Time spent servicing soft interrupts (Linux)
    pub softirq: u64,
}

/// Process information
#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: u32,
    /// Process name
    pub name: String,
    /// Process executable path
    pub exe_path: String,
    /// Process command line arguments
    pub cmdline: Vec<String>,
    /// Process state
    pub state: ProcessState,
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// Virtual memory size in bytes
    pub virtual_memory: u64,
    /// CPU usage percentage
    pub cpu_percent: f64,
    /// Number of threads
    pub threads: u32,
    /// Start time (unix timestamp)
    pub start_time: u64,
    /// User ID (Unix)
    pub uid: u32,
    /// Username
    pub username: String,
}

/// Process state
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProcessState {
    /// Running
    Running,
    /// Sleeping
    Sleeping,
    /// Stopped
    Stopped,
    /// Zombie
    Zombie,
    /// Idle
    Idle,
    /// Unknown state
    #[default]
    Unknown,
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessState::Running => write!(f, "Running"),
            ProcessState::Sleeping => write!(f, "Sleeping"),
            ProcessState::Stopped => write!(f, "Stopped"),
            ProcessState::Zombie => write!(f, "Zombie"),
            ProcessState::Idle => write!(f, "Idle"),
            ProcessState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Disk information
#[derive(Debug, Clone, Default)]
pub struct DiskInfo {
    /// Device name (e.g., /dev/sda1)
    pub device: String,
    /// Mount point
    pub mount_point: String,
    /// Filesystem type
    pub fs_type: String,
    /// Total size in bytes
    pub total_bytes: u64,
    /// Used space in bytes
    pub used_bytes: u64,
    /// Available space in bytes
    pub available_bytes: u64,
    /// Usage percentage
    pub usage_percent: f64,
}

/// Disk I/O statistics
#[derive(Debug, Clone, Default)]
pub struct DiskIoStats {
    /// Device name
    pub device: String,
    /// Number of read operations
    pub reads: u64,
    /// Number of write operations
    pub writes: u64,
    /// Bytes read
    pub bytes_read: u64,
    /// Bytes written
    pub bytes_written: u64,
    /// Read time in milliseconds
    pub read_time_ms: u64,
    /// Write time in milliseconds
    pub write_time_ms: u64,
}

/// Socket/TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SocketState {
    /// Connection established
    Established = 1,
    /// Waiting for SYN+ACK (connect)
    SynSent,
    /// Waiting for ACK after receiving SYN
    SynReceived,
    /// Waiting for FIN ACK
    FinWait1,
    /// Waiting for FIN
    FinWait2,
    /// Waiting for enough time to pass to ensure remote received ACK
    TimeWait,
    /// Connection closed
    Closed,
    /// Waiting for connection termination from remote
    CloseWait,
    /// Waiting for connection termination ACK
    LastAck,
    /// Listening for incoming connections
    Listen,
    /// Waiting for ACK of connection termination
    Closing,
    /// Unknown state
    #[default]
    Unknown,
}

impl TryFrom<i32> for SocketState {
    type Error = ();
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SocketState::Established),
            1 => Ok(SocketState::SynSent),
            2 => Ok(SocketState::SynReceived),
            3 => Ok(SocketState::FinWait1),
            4 => Ok(SocketState::FinWait2),
            5 => Ok(SocketState::TimeWait),
            6 => Ok(SocketState::Closed),
            7 => Ok(SocketState::CloseWait),
            8 => Ok(SocketState::LastAck),
            9 => Ok(SocketState::Listen),
            10 => Ok(SocketState::Closing),
            11 => Ok(SocketState::Unknown),
            _ => Err(()),
        }
    }
}

impl TryFrom<&str> for SocketState {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_uppercase().as_str() {
            "ESTABLISHED" => Ok(SocketState::Established),
            "SYN_SENT" => Ok(SocketState::SynSent),
            "SYN_RECV" => Ok(SocketState::SynReceived),
            "FIN_WAIT1" => Ok(SocketState::FinWait1),
            "FIN_WAIT2" => Ok(SocketState::FinWait2),
            "TIME_WAIT" => Ok(SocketState::TimeWait),
            "CLOSED" => Ok(SocketState::Closed),
            "CLOSE_WAIT" => Ok(SocketState::CloseWait),
            "LAST_ACK" => Ok(SocketState::LastAck),
            "LISTEN" => Ok(SocketState::Listen),
            "CLOSING" => Ok(SocketState::Closing),
            "UNKNOWN" => Ok(SocketState::Unknown),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for SocketState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketState::Established => write!(f, "ESTABLISHED"),
            SocketState::SynSent => write!(f, "SYN_SENT"),
            SocketState::SynReceived => write!(f, "SYN_RECV"),
            SocketState::FinWait1 => write!(f, "FIN_WAIT1"),
            SocketState::FinWait2 => write!(f, "FIN_WAIT2"),
            SocketState::TimeWait => write!(f, "TIME_WAIT"),
            SocketState::Closed => write!(f, "CLOSED"),
            SocketState::CloseWait => write!(f, "CLOSE_WAIT"),
            SocketState::LastAck => write!(f, "LAST_ACK"),
            SocketState::Listen => write!(f, "LISTEN"),
            SocketState::Closing => write!(f, "CLOSING"),
            SocketState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Socket connection information
#[derive(Debug, Clone)]
pub struct SocketConnection {
    /// Socket protocol
    pub protocol: SocketProtocol,
    /// Local address
    pub local_addr: SocketAddr,
    /// Remote address (None for listening sockets)
    pub remote_addr: Option<SocketAddr>,
    /// Connection state
    pub state: SocketState,
    /// Process ID owning this socket (if available)
    pub pid: Option<u32>,
    /// Inode number (Linux specific)
    pub inode: u64,
}

/// Socket protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketProtocol {
    /// TCP IPv4
    TcpV4,
    /// TCP IPv6
    TcpV6,
    /// UDP IPv4
    UdpV4,
    /// UDP IPv6
    UdpV6,
}

impl std::fmt::Display for SocketProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketProtocol::TcpV4 => write!(f, "tcp"),
            SocketProtocol::TcpV6 => write!(f, "tcp6"),
            SocketProtocol::UdpV4 => write!(f, "udp"),
            SocketProtocol::UdpV6 => write!(f, "udp6"),
        }
    }
}

/// Summary of socket states
#[derive(Debug, Clone, Default)]
pub struct SocketStateSummary {
    /// Total number of connections
    pub total: usize,
    /// Number of established connections
    pub established: usize,
    /// Number of listening sockets
    pub listen: usize,
    /// Number of time_wait connections
    pub time_wait: usize,
    /// Number of close_wait connections
    pub close_wait: usize,
    /// Number of syn_sent connections
    pub syn_sent: usize,
    /// Number of syn_received connections
    pub syn_recv: usize,
    /// Number of fin_wait1 connections
    pub fin_wait1: usize,
    /// Number of fin_wait2 connections
    pub fin_wait2: usize,
    /// Number of closing connections
    pub closing: usize,
    /// Number of last_ack connections
    pub last_ack: usize,
    /// Number of closed connections
    pub closed: usize,
}

impl SocketStateSummary {
    /// Create summary from a list of socket connections
    pub fn from_connections(connections: &Vec<&SocketConnection>) -> Self {
        let mut summary = Self::default();
        summary.total += connections.len();

        for conn in connections {
            match conn.state {
                SocketState::Established => summary.established += 1,
                SocketState::Listen => summary.listen += 1,
                SocketState::TimeWait => summary.time_wait += 1,
                SocketState::CloseWait => summary.close_wait += 1,
                SocketState::SynSent => summary.syn_sent += 1,
                SocketState::SynReceived => summary.syn_recv += 1,
                SocketState::FinWait1 => summary.fin_wait1 += 1,
                SocketState::FinWait2 => summary.fin_wait2 += 1,
                SocketState::Closing => summary.closing += 1,
                SocketState::LastAck => summary.last_ack += 1,
                SocketState::Closed => summary.closed += 1,
                SocketState::Unknown => {}
            }
        }

        summary
    }
}


#[repr(C)]
#[derive(Clone, Copy)]
pub struct XTcpInfo {
    xt_len: u32,
    t_state: i32,
    t_timer: [i32; 4],
    t_rxtshift: i32,
    t_rxtcur: i32,
    t_dupacks: i32,
    t_maxseg: u32,
    t_force: u32,
    t_flags: u32,
    snd_una: u32,
    snd_max: u32,
    snd_nxt: u32,
    snd_up: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    iss: u32,
    irs: u32,
    rcv_nxt: u32,
    rcv_adv: u32,
    rcv_wnd: u32,
    rcv_up: u32,
    snd_wnd: u32,
    snd_cwnd: u32,
    snd_ssthresh: u32,
    t_maxopd: u32,
    t_rcvtime: u32,
    t_starttime: u32,
    t_rtttime: u32,
    t_rtseq: u32,
    t_rttvar: i32,
    t_rttmin: i32,
    t_rtt: i32,
    t_srtt: i32,
    t_rttbest: i32,
    max_sndwnd: u32,
    t_softerror: i32,
    t_oobflags: i8,
    t_iobc: i8,
    _padding: [u8; 2],
    snd_scale: u8,
    rcv_scale: u8,
    request_r_scale: u8,
    requested_s_scale: u8,
    ts_recent: u32,
    ts_recent_age: u32,
    last_ack_sent: u32,
    cc_send: u32,
    cc_recv: u32,
    snd_recover: u32,
    snd_fack: u32,
    snd_numholes: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct XinpGen {
    xig_len: u32,
    xig_count: u32,
    xig_gen: u64,
    xig_sogen: u64,
}