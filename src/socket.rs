//! Socket/Network connection information module
//!
//! Provides cross-platform network socket information gathering.
//!
//! Platform-specific implementations:
//! - **Linux**: Uses netlink socket (NETLINK_SOCK_DIAG) for efficient kernel-level socket enumeration
//! - **macOS**: Uses `proc_listpidspath` and `lsof` style syscalls via libproc
//! - **Windows**: Uses `GetExtendedTcpTable` and `GetExtendedUdpTable` from IP Helper API

use crate::error::{Result, SysInfoError};
use crate::types::{
    SocketConnection, SocketConnectionEvent, SocketProtocol, SocketQueueInfo, SocketState,
    SocketStateSummary, SocketStats,
};
use std::collections::HashMap;

/// Get all TCP connections (IPv4 and IPv6)
pub fn get_tcp_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
    for (state, conns) in get_tcp4_connections()? {
        connections.entry(state).or_default().extend(conns);
    }
    for (state, conns) in get_tcp6_connections()? {
        connections.entry(state).or_default().extend(conns);
    }
    Ok(connections)
}

/// Get all UDP sockets (IPv4 and IPv6)
pub fn get_udp_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
    for (state, conns) in get_udp4_sockets()? {
        connections.entry(state).or_default().extend(conns);
    }
    for (state, conns) in get_udp6_sockets()? {
        connections.entry(state).or_default().extend(conns);
    }
    Ok(connections)
}

/// Get all socket connections (TCP and UDP)
pub fn get_all_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
    for (state, conns) in get_tcp_connections()? {
        connections.entry(state).or_default().extend(conns);
    }
    for (state, conns) in get_udp_sockets()? {
        connections.entry(state).or_default().extend(conns);
    }
    Ok(connections)
}

/// Get socket state summary
pub fn get_socket_summary() -> Result<SocketStateSummary> {
    let connections = get_all_connections()?;
    Ok(SocketStateSummary::from_connections(
        &connections
            .values()
            .flatten()
            .collect::<Vec<&SocketConnection>>(),
    ))
}

/// Get socket connections for a specific process ID
pub fn get_connections_by_pid(pid: u32) -> Result<Vec<SocketConnectionEvent>> {
    let connections = get_all_connections()?;
    let mut result = Vec::new();
    for conn in connections.values().flatten() {
        if conn.pid == Some(pid) {
            result.push(SocketConnectionEvent {
                protocol: conn.protocol,
                local_addr: conn.local_addr,
                remote_addr: conn.remote_addr,
                state: conn.state,
                pid,
                inode: conn.inode,
            });
        }
    }
    Ok(result)
}

/// Get per-socket I/O statistics for a specific process ID
pub fn get_process_socket_stats(pid: u32) -> Result<Vec<SocketStats>> {
    #[cfg(target_os = "linux")]
    return linux::get_process_socket_stats(pid);

    #[cfg(target_os = "macos")]
    return macos::get_process_socket_stats(pid);

    #[cfg(target_os = "windows")]
    return innerWindows::get_process_socket_stats(pid);

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get per-socket receive/send queue information for a specific process
///
/// Returns the current bytes in each socket's receive and send queues,
/// along with the high water marks for each queue.
pub fn get_process_socket_queues(pid: u32) -> Result<Vec<SocketQueueInfo>> {
    #[cfg(target_os = "linux")]
    return linux::get_process_socket_queues(pid);

    #[cfg(target_os = "macos")]
    return macos::get_process_socket_queues(pid);

    #[cfg(target_os = "windows")]
    return innerWindows::get_process_socket_queues(pid);

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get TCP IPv4 connections
pub fn get_tcp4_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    #[cfg(target_os = "linux")]
    return linux::get_tcp4_connections();

    #[cfg(target_os = "macos")]
    return macos::get_tcp4_connections();

    #[cfg(target_os = "windows")]
    return innerWindows::get_tcp4_connections();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get TCP IPv6 connections
pub fn get_tcp6_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    #[cfg(target_os = "linux")]
    return linux::get_tcp6_connections();

    #[cfg(target_os = "macos")]
    return macos::get_tcp6_connections();

    #[cfg(target_os = "windows")]
    return innerWindows::get_tcp6_connections();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get UDP IPv4 sockets
pub fn get_udp4_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    #[cfg(target_os = "linux")]
    return linux::get_udp4_sockets();

    #[cfg(target_os = "macos")]
    return macos::get_udp4_sockets();

    #[cfg(target_os = "windows")]
    return innerWindows::get_udp4_sockets();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get UDP IPv6 sockets
pub fn get_udp6_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    #[cfg(target_os = "linux")]
    return linux::get_udp6_sockets();

    #[cfg(target_os = "macos")]
    return macos::get_udp6_sockets();

    #[cfg(target_os = "windows")]
    return innerWindows::get_udp6_sockets();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

// ============================================================================
// Linux Implementation - Using Netlink SOCK_DIAG
// ============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use netlink_packet_core::{
        NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
    };
    use netlink_packet_sock_diag::{
        constants::*,
        inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
        SockDiagMessage,
    };
    use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr as NetlinkSocketAddr};
    use std::collections::HashSet;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    const INODE_PID_CACHE_TTL: Duration = Duration::from_secs(1);

    struct InodePidCache {
        fetched_at: Instant,
        map: HashMap<u64, u32>,
    }

    static INODE_PID_CACHE: OnceLock<Mutex<InodePidCache>> = OnceLock::new();

    /// TCP state mapping from kernel values to our enum
    fn tcp_state_from_kernel(state: u8) -> SocketState {
        match state {
            1 => SocketState::Established,
            2 => SocketState::SynSent,
            3 => SocketState::SynReceived,
            4 => SocketState::FinWait1,
            5 => SocketState::FinWait2,
            6 => SocketState::TimeWait,
            7 => SocketState::Closed,
            8 => SocketState::CloseWait,
            9 => SocketState::LastAck,
            10 => SocketState::Listen,
            11 => SocketState::Closing,
            _ => SocketState::Unknown,
        }
    }

    pub fn get_tcp4_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_inet_connections(SocketProtocol::TcpV4)
    }

    pub fn get_tcp6_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_inet_connections(SocketProtocol::TcpV6)
    }

    pub fn get_udp4_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_inet_connections(SocketProtocol::UdpV4)
    }

    pub fn get_udp6_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_inet_connections(SocketProtocol::UdpV6)
    }

    fn get_inet_connections(
        proto_type: SocketProtocol,
    ) -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
        let inode_pid_map = get_inode_pid_map_cached();
        let mut socket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
        let _port_number = socket.bind_auto().unwrap().port_number();
        socket.connect(&NetlinkSocketAddr::new(0, 0)).unwrap();

        let mut nl_hdr = NetlinkHeader::default();
        nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        let use_protocol;
        let use_family;
        let use_socket_id;
        match proto_type {
            SocketProtocol::TcpV4 => {
                use_protocol = IPPROTO_TCP;
                use_family = AF_INET;
                use_socket_id = SocketId::new_v4();
            }
            SocketProtocol::TcpV6 => {
                use_protocol = IPPROTO_TCP;
                use_family = AF_INET6;
                use_socket_id = SocketId::new_v6();
            }
            SocketProtocol::UdpV4 => {
                use_protocol = IPPROTO_UDP;
                use_family = AF_INET;
                use_socket_id = SocketId::new_v4();
            }
            SocketProtocol::UdpV6 => {
                use_protocol = IPPROTO_UDP;
                use_family = AF_INET6;
                use_socket_id = SocketId::new_v6();
            }
        }
        let mut packet = NetlinkMessage::new(
            nl_hdr,
            SockDiagMessage::InetRequest(InetRequest {
                family: use_family,
                protocol: use_protocol,
                extensions: ExtensionFlags::empty(),
                states: StateFlags::all(),
                socket_id: use_socket_id,
            })
            .into(),
        );
        packet.finalize();
        let mut buf = vec![0; packet.header.length as usize];
        packet.serialize(&mut buf[..]);
        if let Err(e) = socket.send(&buf[..], 0) {
            return Err(e.into());
        }
        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;
        while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
            loop {
                let bytes = &receive_buffer[offset..];
                let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
                match rx_packet.payload {
                    NetlinkPayload::Noop => {}
                    NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                        let state = tcp_state_from_kernel(response.header.state);
                        let local_ip = response.header.socket_id.source_address;
                        let local_port = response.header.socket_id.source_port;
                        let remote_ip = response.header.socket_id.destination_address;
                        let remote_port = response.header.socket_id.destination_port;

                        let local_addr = std::net::SocketAddr::new(local_ip, local_port);
                        let remote_addr = if remote_port != 0 {
                            Some(std::net::SocketAddr::new(remote_ip, remote_port))
                        } else {
                            None
                        };

                        let conn = SocketConnection {
                            protocol: proto_type,
                            local_addr,
                            remote_addr,
                            state,
                            pid: inode_pid_map.get(&(response.header.inode as u64)).copied(),
                            inode: response.header.inode as u64,
                        };
                        connections.entry(state).or_insert(Vec::new()).push(conn);
                    }
                    NetlinkPayload::Done(_) => {
                        // All data received, return results
                        return Ok(connections);
                    }
                    _ => {
                        // Unexpected message, return what we have
                        return Ok(connections);
                    }
                }
                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
                }
            }
        }
        Ok(connections)
    }
    /// Fallback: Parse /proc/net/tcp for socket information
    /// Used when netlink is not available or for debugging
    #[allow(dead_code)]
    fn parse_proc_tcp() -> Result<Vec<SocketConnection>> {
        let contents = fs::read_to_string("/proc/net/tcp")?;
        let mut connections = Vec::new();
        let inode_pid_map = get_inode_pid_map_cached();

        for line in contents.lines().skip(1) {
            // Skip header
            if let Some(conn) = parse_proc_net_line(line, SocketProtocol::TcpV4, &inode_pid_map) {
                connections.push(conn);
            }
        }

        Ok(connections)
    }

    #[allow(dead_code)]
    fn parse_proc_net_line(
        line: &str,
        protocol: SocketProtocol,
        inode_pid_map: &HashMap<u64, u32>,
    ) -> Option<SocketConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        // Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
        let local = parse_hex_addr(parts[1])?;
        let remote = parse_hex_addr(parts[2])?;
        let state = u8::from_str_radix(parts[3], 16).ok()?;
        let inode: u64 = parts[9].parse().ok()?;

        let remote_addr = if remote.port() != 0 {
            Some(remote)
        } else {
            None
        };

        let pid = inode_pid_map.get(&inode).copied();
        Some(SocketConnection {
            protocol,
            local_addr: local,
            remote_addr,
            state: tcp_state_from_kernel(state),
            pid,
            inode,
        })
    }

    fn parse_hex_addr(s: &str) -> Option<std::net::SocketAddr> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16).ok()?;

        if ip_hex.len() == 8 {
            // IPv4
            let ip = u32::from_str_radix(ip_hex, 16).ok()?;
            let ip = Ipv4Addr::from(ip.to_le());
            Some(std::net::SocketAddr::new(IpAddr::V4(ip), port))
        } else if ip_hex.len() == 32 {
            // IPv6
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                bytes[i] = u8::from_str_radix(&ip_hex[i * 2..i * 2 + 2], 16).ok()?;
            }
            Some(std::net::SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(bytes)),
                port,
            ))
        } else {
            None
        }
    }

    fn get_inode_pid_map_cached() -> HashMap<u64, u32> {
        let cache = INODE_PID_CACHE.get_or_init(|| {
            Mutex::new(InodePidCache {
                fetched_at: Instant::now() - INODE_PID_CACHE_TTL,
                map: HashMap::new(),
            })
        });

        if let Ok(mut cache_lock) = cache.lock() {
            if cache_lock.fetched_at.elapsed() < INODE_PID_CACHE_TTL {
                return cache_lock.map.clone();
            }

            let map = build_inode_pid_map();
            cache_lock.fetched_at = Instant::now();
            cache_lock.map = map.clone();
            return map;
        }

        build_inode_pid_map()
    }

    fn build_inode_pid_map() -> HashMap<u64, u32> {
        let mut map = HashMap::new();
        let proc_root = Path::new("/proc");
        let entries = match fs::read_dir(proc_root) {
            Ok(entries) => entries,
            Err(_) => return map,
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            let pid: u32 = match name.parse() {
                Ok(pid) => pid,
                Err(_) => continue,
            };

            let fd_dir = proc_root.join(name.as_ref()).join("fd");
            let fd_entries = match fs::read_dir(&fd_dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            for fd_entry in fd_entries.flatten() {
                let link = match fs::read_link(fd_entry.path()) {
                    Ok(link) => link,
                    Err(_) => continue,
                };
                if let Some(inode) = parse_socket_inode(&link) {
                    map.entry(inode).or_insert(pid);
                }
            }
        }

        map
    }

    fn parse_socket_inode(path: &std::path::Path) -> Option<u64> {
        let link = path.to_string_lossy();
        if !link.starts_with("socket:[") || !link.ends_with(']') {
            return None;
        }
        let inode_str = &link[8..link.len() - 1];
        inode_str.parse().ok()
    }

    pub fn get_process_socket_stats(pid: u32) -> Result<Vec<SocketStats>> {
        use std::os::unix::io::RawFd;

        let fd_dir = format!("/proc/{}/fd", pid);
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(Vec::new()),
        };

        let mut stats = Vec::new();

        for fd_entry in fd_entries.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(link) => link,
                Err(_) => continue,
            };
            let link_str = link.to_string_lossy();
            if !link_str.starts_with("socket:[") {
                continue;
            }

            let fd_num: u32 = match fd_entry.file_name().to_string_lossy().parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            // We cannot call getsockopt on another process's fd directly.
            // Instead, we open /proc/[pid]/fd/[fd] which gives us a new fd
            // pointing to the same socket, then query TCP_INFO on it.
            let proc_fd_path = format!("/proc/{}/fd/{}", pid, fd_num);
            let raw_fd: RawFd = unsafe {
                libc::open(
                    std::ffi::CString::new(proc_fd_path.as_str())
                        .unwrap()
                        .as_ptr(),
                    libc::O_RDONLY | libc::O_NONBLOCK,
                )
            };
            if raw_fd < 0 {
                continue;
            }

            let mut tcp_info: libc::tcp_info = unsafe { std::mem::zeroed() };
            let mut info_len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    raw_fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_INFO,
                    &mut tcp_info as *mut _ as *mut libc::c_void,
                    &mut info_len,
                )
            };

            if ret == 0 {
                // Get local and remote addresses
                let mut local_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                unsafe {
                    libc::getsockname(
                        raw_fd,
                        &mut local_addr as *mut _ as *mut libc::sockaddr,
                        &mut addr_len,
                    );
                }

                let mut remote_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                unsafe {
                    libc::getpeername(
                        raw_fd,
                        &mut remote_addr as *mut _ as *mut libc::sockaddr,
                        &mut addr_len,
                    );
                }

                let local = sockaddr_to_socket_addr(&local_addr);
                let remote = sockaddr_to_socket_addr(&remote_addr);

                let protocol = if local.is_ipv6() {
                    SocketProtocol::TcpV6
                } else {
                    SocketProtocol::TcpV4
                };

                stats.push(SocketStats {
                    pid,
                    fd: fd_num,
                    protocol,
                    local_addr: local,
                    remote_addr: Some(remote),
                    bytes_sent: 0,
                    bytes_received: 0,
                });
            }

            unsafe {
                libc::close(raw_fd);
            }
        }

        Ok(stats)
    }

    fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> std::net::SocketAddr {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
        unsafe {
            match storage.ss_family as i32 {
                libc::AF_INET => {
                    let addr = &*(storage as *const _ as *const libc::sockaddr_in);
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr))),
                        u16::from_be(addr.sin_port),
                    )
                }
                libc::AF_INET6 => {
                    let addr = &*(storage as *const _ as *const libc::sockaddr_in6);
                    SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                        u16::from_be(addr.sin6_port),
                    )
                }
                _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            }
        }
    }

    pub fn get_process_socket_queues(pid: u32) -> Result<Vec<SocketQueueInfo>> {
        let inode_set = get_process_socket_inodes(pid);
        let mut result = Vec::new();

        // Parse /proc/net/tcp for TCPv4 sockets
        if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                if let Some(info) = parse_tcp_queue_line(line, SocketProtocol::TcpV4, &inode_set) {
                    result.push(info);
                }
            }
        }

        // Parse /proc/net/tcp6 for TCPv6 sockets
        if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
            for line in content.lines().skip(1) {
                if let Some(info) = parse_tcp_queue_line(line, SocketProtocol::TcpV6, &inode_set) {
                    result.push(info);
                }
            }
        }

        Ok(result)
    }

    fn get_process_socket_inodes(pid: u32) -> HashSet<u64> {
        let mut inodes = HashSet::new();
        let fd_dir = format!("/proc/{}/fd", pid);
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(_) => return inodes,
        };

        for fd_entry in fd_entries.flatten() {
            if let Ok(link) = fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy();
                if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                    let inode_str = &link_str[8..link_str.len() - 1];
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        inodes.insert(inode);
                    }
                }
            }
        }
        inodes
    }

    fn parse_tcp_queue_line(
        line: &str,
        protocol: SocketProtocol,
        inodes: &HashSet<u64>,
    ) -> Option<SocketQueueInfo> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return None;
        }

        let local = parse_hex_addr(parts[1])?;
        let remote = parse_hex_addr(parts[2])?;
        let state_byte = u8::from_str_radix(parts[3], 16).ok()?;
        let state = tcp_state_from_kernel(state_byte);

        // tx_queue:rx_queue field (parts[4]), format: "XXXX:XXXX"
        let queue_parts: Vec<&str> = parts[4].split(':').collect();
        let send_queue = if queue_parts.len() >= 1 {
            u32::from_str_radix(queue_parts[0], 16).unwrap_or(0)
        } else {
            0
        };
        let recv_queue = if queue_parts.len() >= 2 {
            u32::from_str_radix(queue_parts[1], 16).unwrap_or(0)
        } else {
            0
        };

        let inode: u64 = parts[9].parse().ok()?;

        if !inodes.contains(&inode) {
            return None;
        }

        let remote_addr = if remote.port() != 0 {
            Some(remote)
        } else {
            None
        };

        Some(SocketQueueInfo {
            pid: 0,
            fd: 0,
            protocol,
            local_addr: local,
            remote_addr,
            state,
            recv_queue_bytes: recv_queue,
            recv_queue_hiwat: 0,
            send_queue_bytes: send_queue,
            send_queue_hiwat: 0,
        })
    }
}

// ============================================================================
// macOS Implementation - Using syscalls and /proc-like interfaces
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
    use libproc::net_info::{SocketFDInfo, SocketInfoKind, TcpSIState};
    use libproc::proc_pid::{listpidinfo, pidinfo};
    use libproc::processes::{pids_by_type, ProcFilter};
    use libproc::task_info::TaskAllInfo;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    const INI_IPV4: u8 = 1;
    const INI_IPV6: u8 = 2;
    const PID_SOCKET_CACHE_TTL: Duration = Duration::from_secs(1);

    struct SocketCache {
        fetched_at: Instant,
        by_protocol: HashMap<SocketProtocol, HashMap<SocketState, Vec<SocketConnection>>>,
    }

    static SOCKET_CACHE: OnceLock<Mutex<SocketCache>> = OnceLock::new();

    pub fn get_tcp4_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        Ok(get_connections_for_protocol(SocketProtocol::TcpV4))
    }

    pub fn get_tcp6_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        Ok(get_connections_for_protocol(SocketProtocol::TcpV6))
    }

    pub fn get_udp4_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        Ok(get_connections_for_protocol(SocketProtocol::UdpV4))
    }

    pub fn get_udp6_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        Ok(get_connections_for_protocol(SocketProtocol::UdpV6))
    }

    fn get_connections_for_protocol(
        protocol: SocketProtocol,
    ) -> HashMap<SocketState, Vec<SocketConnection>> {
        if let Some(all) = get_cached_all() {
            return all.get(&protocol).cloned().unwrap_or_default();
        }

        let all = scan_all_connections();
        store_cached_all(&all);
        all.get(&protocol).cloned().unwrap_or_default()
    }

    fn get_cached_all(
    ) -> Option<HashMap<SocketProtocol, HashMap<SocketState, Vec<SocketConnection>>>> {
        let cache = SOCKET_CACHE.get_or_init(|| {
            Mutex::new(SocketCache {
                fetched_at: Instant::now() - PID_SOCKET_CACHE_TTL,
                by_protocol: HashMap::new(),
            })
        });

        let cache_lock = cache.lock().ok()?;
        if cache_lock.fetched_at.elapsed() >= PID_SOCKET_CACHE_TTL {
            return None;
        }
        Some(cache_lock.by_protocol.clone())
    }

    fn store_cached_all(
        by_protocol: &HashMap<SocketProtocol, HashMap<SocketState, Vec<SocketConnection>>>,
    ) {
        let cache = SOCKET_CACHE.get_or_init(|| {
            Mutex::new(SocketCache {
                fetched_at: Instant::now() - PID_SOCKET_CACHE_TTL,
                by_protocol: HashMap::new(),
            })
        });

        if let Ok(mut cache_lock) = cache.lock() {
            cache_lock.fetched_at = Instant::now();
            cache_lock.by_protocol = by_protocol.clone();
        }
    }

    fn scan_all_connections() -> HashMap<SocketProtocol, HashMap<SocketState, Vec<SocketConnection>>>
    {
        let mut by_protocol =
            HashMap::<SocketProtocol, HashMap<SocketState, Vec<SocketConnection>>>::new();
        let debug_pid = std::env::var("DEBUG_SOCKET_PID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        let pids = match pids_by_type(ProcFilter::All) {
            Ok(pids) => pids,
            Err(_) => return by_protocol,
        };

        for pid in pids {
            let pid_i32 = pid as i32;
            let task_info = match pidinfo::<TaskAllInfo>(pid_i32, 0) {
                Ok(info) => info,
                Err(_) => continue,
            };
            let fd_count = task_info.pbsd.pbi_nfiles as usize;
            let fds = match listpidinfo::<ListFDs>(pid_i32, fd_count) {
                Ok(fds) => fds,
                Err(_) => continue,
            };

            for fd in fds {
                if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                    continue;
                }
                let sock = match pidfdinfo::<SocketFDInfo>(pid_i32, fd.proc_fd) {
                    Ok(sock) => sock,
                    Err(_) => continue,
                };

                let conn = match socket_info_to_connection_any(pid, &sock) {
                    Some(conn) => conn,
                    None => continue,
                };
                match debug_pid {
                    Some(target_pid) => {
                        if pid == target_pid {
                            println!("conn: {:?}", conn);
                        }
                    }
                    None => {}
                }
                by_protocol
                    .entry(conn.protocol)
                    .or_default()
                    .entry(conn.state)
                    .or_default()
                    .push(conn);
            }
        }

        by_protocol
    }

    fn socket_info_to_connection_any(pid: u32, socket: &SocketFDInfo) -> Option<SocketConnection> {
        let kind = SocketInfoKind::from(socket.psi.soi_kind);
        let proto = socket.psi.soi_protocol;
        let family = socket.psi.soi_family;

        if matches!(kind, SocketInfoKind::Tcp) && (proto == libc::IPPROTO_TCP || proto == 0) {
            let info = unsafe { socket.psi.soi_proto.pri_tcp };
            let protocol = protocol_from_vflag_or_family(info.tcpsi_ini.insi_vflag, family, true)?;
            let (local_addr, remote_addr) = parse_in_sock_info(protocol, &info.tcpsi_ini)?;
            let state = tcp_state_from_macos(info.tcpsi_state);
            return Some(SocketConnection {
                protocol,
                local_addr,
                remote_addr,
                state,
                pid: Some(pid),
                inode: 0,
            });
        }

        if matches!(kind, SocketInfoKind::In) && (proto == libc::IPPROTO_UDP || proto == 0) {
            let info = unsafe { socket.psi.soi_proto.pri_in };
            let protocol = protocol_from_vflag_or_family(info.insi_vflag, family, false)?;
            let (local_addr, _remote_addr) = parse_in_sock_info(protocol, &info)?;
            return Some(SocketConnection {
                protocol,
                local_addr,
                remote_addr: None,
                state: SocketState::Unknown,
                pid: Some(pid),
                inode: 0,
            });
        }

        if matches!(kind, SocketInfoKind::In) && (proto == libc::IPPROTO_TCP || proto == 0) {
            let info = unsafe { socket.psi.soi_proto.pri_in };
            let protocol = protocol_from_vflag_or_family(info.insi_vflag, family, true)?;
            let (local_addr, remote_addr) = parse_in_sock_info(protocol, &info)?;
            return Some(SocketConnection {
                protocol,
                local_addr,
                remote_addr,
                state: SocketState::Unknown,
                pid: Some(pid),
                inode: 0,
            });
        }

        None
    }

    fn parse_in_sock_info(
        protocol: SocketProtocol,
        info: &libproc::net_info::InSockInfo,
    ) -> Option<(SocketAddr, Option<SocketAddr>)> {
        match protocol {
            SocketProtocol::TcpV4 | SocketProtocol::UdpV4 => {
                if info.insi_vflag != INI_IPV4 {
                    if info.insi_vflag != 0 {
                        return None;
                    }
                }
                let local_ip = unsafe {
                    Ipv4Addr::from(u32::from_be(info.insi_laddr.ina_46.i46a_addr4.s_addr))
                };
                let remote_ip = unsafe {
                    Ipv4Addr::from(u32::from_be(info.insi_faddr.ina_46.i46a_addr4.s_addr))
                };
                let local_port = u16::from_be(info.insi_lport as u16);
                let remote_port = u16::from_be(info.insi_fport as u16);
                let local_addr = SocketAddr::new(IpAddr::V4(local_ip), local_port);
                let remote_addr = if remote_port == 0 {
                    None
                } else {
                    Some(SocketAddr::new(IpAddr::V4(remote_ip), remote_port))
                };
                Some((local_addr, remote_addr))
            }
            SocketProtocol::TcpV6 | SocketProtocol::UdpV6 => {
                if info.insi_vflag != INI_IPV6 {
                    if info.insi_vflag != 0 {
                        return None;
                    }
                }
                let local_ip = unsafe { ipv6_from_in6_addr(info.insi_laddr.ina_6) };
                let remote_ip = unsafe { ipv6_from_in6_addr(info.insi_faddr.ina_6) };
                let local_port = u16::from_be(info.insi_lport as u16);
                let remote_port = u16::from_be(info.insi_fport as u16);
                let local_addr = SocketAddr::new(IpAddr::V6(local_ip), local_port);
                let remote_addr = if remote_port == 0 {
                    None
                } else {
                    Some(SocketAddr::new(IpAddr::V6(remote_ip), remote_port))
                };
                Some((local_addr, remote_addr))
            }
        }
    }

    fn ipv6_from_in6_addr(addr: libc::in6_addr) -> Ipv6Addr {
        Ipv6Addr::from(addr.s6_addr)
    }

    fn protocol_from_vflag_or_family(
        vflag: u8,
        family: i32,
        is_tcp: bool,
    ) -> Option<SocketProtocol> {
        match vflag {
            INI_IPV4 => {
                return Some(if is_tcp {
                    SocketProtocol::TcpV4
                } else {
                    SocketProtocol::UdpV4
                })
            }
            INI_IPV6 => {
                return Some(if is_tcp {
                    SocketProtocol::TcpV6
                } else {
                    SocketProtocol::UdpV6
                })
            }
            _ => {}
        }

        match family {
            libc::AF_INET => Some(if is_tcp {
                SocketProtocol::TcpV4
            } else {
                SocketProtocol::UdpV4
            }),
            libc::AF_INET6 => Some(if is_tcp {
                SocketProtocol::TcpV6
            } else {
                SocketProtocol::UdpV6
            }),
            _ => None,
        }
    }

    fn tcp_state_from_macos(state: i32) -> SocketState {
        match TcpSIState::from(state) {
            TcpSIState::Closed => SocketState::Closed,
            TcpSIState::Listen => SocketState::Listen,
            TcpSIState::SynSent => SocketState::SynSent,
            TcpSIState::SynReceived => SocketState::SynReceived,
            TcpSIState::Established => SocketState::Established,
            TcpSIState::CloseWait => SocketState::CloseWait,
            TcpSIState::FinWait1 => SocketState::FinWait1,
            TcpSIState::Closing => SocketState::Closing,
            TcpSIState::LastAck => SocketState::LastAck,
            TcpSIState::FinWait2 => SocketState::FinWait2,
            TcpSIState::TimeWait => SocketState::TimeWait,
            _ => SocketState::Unknown,
        }
    }

    pub fn get_process_socket_stats(pid: u32) -> Result<Vec<SocketStats>> {
        use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
        use libproc::net_info::{SocketFDInfo, SocketInfoKind};
        use libproc::proc_pid::{listpidinfo, pidinfo};
        use libproc::task_info::TaskAllInfo;

        let pid_i32 = pid as i32;

        let task_info = match pidinfo::<TaskAllInfo>(pid_i32, 0) {
            Ok(info) => info,
            Err(e) => {
                eprintln!("[SocketStats] pidinfo failed for PID {}: {:?}", pid, e);
                return Ok(Vec::new());
            }
        };
        let fd_count = task_info.pbsd.pbi_nfiles as usize;
        let fds = match listpidinfo::<ListFDs>(pid_i32, fd_count) {
            Ok(fds) => fds,
            Err(e) => {
                eprintln!("[SocketStats] listpidinfo failed for PID {}: {:?}", pid, e);
                return Ok(Vec::new());
            }
        };

        // Collect socket info from proc_pidfdinfo (addresses only)
        let mut stats: Vec<SocketStats> = Vec::new();

        for fd in &fds {
            if !matches!(ProcFDType::from(fd.proc_fdtype), ProcFDType::Socket) {
                continue;
            }
            let sock = match pidfdinfo::<SocketFDInfo>(pid_i32, fd.proc_fd) {
                Ok(sock) => sock,
                Err(_) => continue,
            };

            let kind = SocketInfoKind::from(sock.psi.soi_kind);
            if !matches!(kind, SocketInfoKind::Tcp) {
                continue;
            }

            let info = unsafe { sock.psi.soi_proto.pri_tcp };
            let protocol = match info.tcpsi_ini.insi_vflag {
                1 => SocketProtocol::TcpV4,
                2 => SocketProtocol::TcpV6,
                _ => continue,
            };

            let (local_addr, remote_addr) = match parse_in_sock_info(protocol, &info.tcpsi_ini) {
                Some(addrs) => addrs,
                None => continue,
            };

            stats.push(SocketStats {
                pid,
                fd: fd.proc_fd as u32,
                protocol,
                local_addr,
                remote_addr,
                bytes_sent: 0,
                bytes_received: 0,
            });
        }

        // Fetch byte counters from nettop
        if !stats.is_empty() {
            if let Ok(nettop_map) = fetch_nettop_byte_counters(pid) {
                for stat in &mut stats {
                    let local_ip = stat.local_addr.ip().to_string();
                    let local_port = stat.local_addr.port().to_string();
                    let remote_ip = stat
                        .remote_addr
                        .map(|a| a.ip().to_string())
                        .unwrap_or_default();
                    let remote_port = stat
                        .remote_addr
                        .map(|a| a.port().to_string())
                        .unwrap_or_default();

                    for (key, (tx, rx)) in &nettop_map {
                        // nettop key format: "tcp4 192.168.1.1:55806<->17.57.145.153:5223"
                        // Match by checking if the key contains our local and remote addr:port
                        let key_contains_local = key.contains(&format!("{local_ip}:{local_port}"))
                            || key.contains(&format!("{local_ip}.{local_port}"));
                        let key_contains_remote = if stat.remote_addr.is_some() {
                            key.contains(&format!("{remote_ip}:{remote_port}"))
                                || key.contains(&format!("{remote_ip}.{remote_port}"))
                        } else {
                            // Listening sockets have *:* on remote side
                            key.contains("<->*")
                        };

                        if key_contains_local && key_contains_remote {
                            stat.bytes_sent = *tx;
                            stat.bytes_received = *rx;
                            break;
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Use `nettop` to fetch per-connection byte counters for a given PID.
    /// Uses `-L` CSV logging mode for reliable parsing.
    /// Returns a map of "local_addr<->remote_addr" -> (bytes_out, bytes_in).
    fn fetch_nettop_byte_counters(pid: u32) -> Result<HashMap<String, (u64, u64)>> {
        let mut map = HashMap::new();
        let pid_str = pid.to_string();

        let output = match std::process::Command::new("nettop")
            .args(["-L", "1", "-n", "-p", &pid_str])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                eprintln!("[SocketStats] nettop failed: {e}");
                return Ok(map);
            }
        };

        if !output.status.success() {
            return Ok(map);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // nettop -L CSV format:
        //   Header: time,,interface,state,bytes_in,bytes_out,rx_dupe,...
        //   Process summary: time,name.PID,,,total_in,total_out,...
        //   Connection:      time,local<->remote,interface,state,conn_in,conn_out,...
        //
        // bytes_in is column index 4, bytes_out is column index 5
        let mut in_header = true;
        for line in stdout.lines() {
            if in_header {
                in_header = false;
                continue;
            }

            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let cols: Vec<&str> = line.split(',').collect();
            if cols.len() < 6 {
                continue;
            }

            // Column 1: connection identifier (local<->remote) or process name
            // Column 4: bytes_in
            // Column 5: bytes_out
            let conn_id = cols[1].trim();
            let bytes_in: u64 = cols[4].trim().parse().unwrap_or(0);
            let bytes_out: u64 = cols[5].trim().parse().unwrap_or(0);

            // Skip process summary lines (no <-> in the identifier)
            if !conn_id.contains("<->") {
                continue;
            }

            if bytes_in > 0 || bytes_out > 0 {
                map.insert(conn_id.to_string(), (bytes_out, bytes_in));
            }
        }

        Ok(map)
    }

    // ---- Queue info structures (from sys/proc_info.h) ----

    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct SockbufInfo {
        sbi_cc: u32,
        sbi_hiwat: u32,
        sbi_mbcnt: u32,
        sbi_mbmax: u32,
        sbi_lowat: u32,
        sbi_flags: i16,
        sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct ProcFdinfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    #[repr(C)]
    struct SocketFdinfo {
        pfi_fi_flags: u32,
        pfi_status: u32,
        pfi_offset: i64,
        pfi_type: i32,
        pfi_guardflags: u32,
        soi_stat: [u8; 136],
        soi_so: u64,
        soi_pcb: u64,
        soi_type: i32,
        soi_protocol: i32,
        soi_family: i32,
        soi_options: i16,
        soi_linger: i16,
        soi_state: i16,
        soi_qlen: i16,
        soi_incqlen: i16,
        soi_qlimit: i16,
        soi_timeo: i16,
        soi_error: u16,
        soi_oobmark: u32,
        soi_rcv: SockbufInfo,
        soi_snd: SockbufInfo,
        soi_kind: i32,
        _reserved: u32,
        _proto: [u8; 528],
    }

    fn list_process_socket_fds(pid: i32) -> Vec<ProcFdinfo> {
        use std::ffi::c_void;
        let mut buf: Vec<ProcFdinfo> = vec![unsafe { std::mem::zeroed() }; 2048];
        let buf_size = buf.len() * std::mem::size_of::<ProcFdinfo>();

        let ret = unsafe {
            libc::proc_pidinfo(
                pid,
                PROC_PIDLISTFDS,
                0,
                buf.as_mut_ptr() as *mut c_void,
                buf_size as i32,
            )
        };

        if ret <= 0 {
            return Vec::new();
        }

        let fd_count = ret as usize / std::mem::size_of::<ProcFdinfo>();
        buf.into_iter()
            .take(fd_count)
            .filter(|fd| fd.proc_fdtype == PROX_FDTYPE_SOCKET)
            .collect()
    }

    fn get_socket_fdinfo(pid: i32, fd: i32) -> Option<SocketFdinfo> {
        use std::ffi::c_void;
        let mut info: SocketFdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<SocketFdinfo>() as i32;

        let ret = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDSOCKETINFO,
                &mut info as *mut _ as *mut c_void,
                size,
            )
        };

        if ret >= size {
            Some(info)
        } else {
            None
        }
    }

    pub fn get_process_socket_queues(pid: u32) -> Result<Vec<SocketQueueInfo>> {
        let pid_i32 = pid as i32;
        let fds = list_process_socket_fds(pid_i32);
        let mut result = Vec::new();

        for fd_info in fds {
            let sock = match get_socket_fdinfo(pid_i32, fd_info.proc_fd) {
                Some(s) => s,
                None => continue,
            };

            let protocol = match sock.soi_protocol {
                p if p == libc::IPPROTO_TCP && sock.soi_family == libc::AF_INET => {
                    SocketProtocol::TcpV4
                }
                p if p == libc::IPPROTO_TCP && sock.soi_family == libc::AF_INET6 => {
                    SocketProtocol::TcpV6
                }
                p if p == libc::IPPROTO_UDP && sock.soi_family == libc::AF_INET => {
                    SocketProtocol::UdpV4
                }
                p if p == libc::IPPROTO_UDP && sock.soi_family == libc::AF_INET6 => {
                    SocketProtocol::UdpV6
                }
                _ => continue,
            };

            let state = match sock.soi_kind {
                2 => {
                    // SOCKINFO_TCP
                    let tcp_state = sock.soi_state;
                    tcp_state_from_macos(tcp_state as i32)
                }
                _ => SocketState::Unknown,
            };

            // Parse addresses from the soi_proto union area.
            // For TCP (SOCKINFO_TCP=2), the inpcb info starts at proto offset 48
            // (after xtcpcb64 header). The local/remote addr+port are there.
            let (local_addr, remote_addr) = parse_queue_sock_addrs(sock.soi_family, &sock._proto);

            result.push(SocketQueueInfo {
                pid,
                fd: fd_info.proc_fd as u32,
                protocol,
                local_addr,
                remote_addr,
                state,
                recv_queue_bytes: sock.soi_rcv.sbi_cc,
                recv_queue_hiwat: sock.soi_rcv.sbi_hiwat,
                send_queue_bytes: sock.soi_snd.sbi_cc,
                send_queue_hiwat: sock.soi_snd.sbi_hiwat,
            });
        }

        Ok(result)
    }

    fn parse_queue_sock_addrs(family: i32, proto: &[u8; 528]) -> (SocketAddr, Option<SocketAddr>) {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let default_v4 = || (SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), None);

        // The proto union layout for TCP (in inpcb section of xtcpcb64):
        // After 48 bytes of xtcpcb header, the inpcb section has:
        //   xip_raddr: [u8; 16]   (offset 48 within proto)
        //   xip_laddr: [u8; 16]   (offset 64 within proto)
        //   xip_fport: u16        (offset 80, big-endian)
        //   xip_lport: u16        (offset 82, big-endian)
        if proto.len() < 84 {
            return default_v4();
        }

        let lport = u16::from_be_bytes([proto[82], proto[83]]);
        let fport = u16::from_be_bytes([proto[80], proto[81]]);

        match family {
            libc::AF_INET => {
                let laddr = Ipv4Addr::new(
                    proto[64 + 12],
                    proto[64 + 13],
                    proto[64 + 14],
                    proto[64 + 15],
                );
                let faddr = Ipv4Addr::new(
                    proto[48 + 12],
                    proto[48 + 13],
                    proto[48 + 14],
                    proto[48 + 15],
                );
                let local = SocketAddr::new(IpAddr::V4(laddr), lport);
                let remote = if fport != 0 {
                    Some(SocketAddr::new(IpAddr::V4(faddr), fport))
                } else {
                    None
                };
                (local, remote)
            }
            libc::AF_INET6 => {
                let laddr = Ipv6Addr::from(<[u8; 16]>::try_from(&proto[64..80]).unwrap_or([0; 16]));
                let faddr = Ipv6Addr::from(<[u8; 16]>::try_from(&proto[48..64]).unwrap_or([0; 16]));
                let local = SocketAddr::new(IpAddr::V6(laddr), lport);
                let remote = if fport != 0 {
                    Some(SocketAddr::new(IpAddr::V6(faddr), fport))
                } else {
                    None
                };
                (local, remote)
            }
            _ => default_v4(),
        }
    }
}

// ============================================================================
// Windows Implementation - Using IP Helper API (iphlpapi)
// ============================================================================
// Windows Implementation - Using IP Helper API (iphlpapi)
// ============================================================================

#[cfg(target_os = "windows")]
#[cfg(target_os = "windows")]
mod innerWindows {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    // TCP states from Windows headers
    const MIB_TCP_STATE_CLOSED: u32 = 1;
    const MIB_TCP_STATE_LISTEN: u32 = 2;
    const MIB_TCP_STATE_SYN_SENT: u32 = 3;
    const MIB_TCP_STATE_SYN_RCVD: u32 = 4;
    const MIB_TCP_STATE_ESTAB: u32 = 5;
    const MIB_TCP_STATE_FIN_WAIT1: u32 = 6;
    const MIB_TCP_STATE_FIN_WAIT2: u32 = 7;
    const MIB_TCP_STATE_CLOSE_WAIT: u32 = 8;
    const MIB_TCP_STATE_CLOSING: u32 = 9;
    const MIB_TCP_STATE_LAST_ACK: u32 = 10;
    const MIB_TCP_STATE_TIME_WAIT: u32 = 11;
    const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

    fn tcp_state_from_windows(state: u32) -> SocketState {
        match state {
            MIB_TCP_STATE_CLOSED | MIB_TCP_STATE_DELETE_TCB => SocketState::Closed,
            MIB_TCP_STATE_LISTEN => SocketState::Listen,
            MIB_TCP_STATE_SYN_SENT => SocketState::SynSent,
            MIB_TCP_STATE_SYN_RCVD => SocketState::SynReceived,
            MIB_TCP_STATE_ESTAB => SocketState::Established,
            MIB_TCP_STATE_FIN_WAIT1 => SocketState::FinWait1,
            MIB_TCP_STATE_FIN_WAIT2 => SocketState::FinWait2,
            MIB_TCP_STATE_CLOSE_WAIT => SocketState::CloseWait,
            MIB_TCP_STATE_CLOSING => SocketState::Closing,
            MIB_TCP_STATE_LAST_ACK => SocketState::LastAck,
            MIB_TCP_STATE_TIME_WAIT => SocketState::TimeWait,
            _ => SocketState::Unknown,
        }
    }

    pub fn get_tcp4_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size == 0 {
            return Ok(HashMap::new());
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let mut connections: HashMap<SocketState, Vec<SocketConnection>> = HashMap::new();

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID).add(i)) };
            let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
            let remote_port = u16::from_be(row.dwRemotePort as u16);

            let local_addr = SocketAddr::new(IpAddr::V4(local_ip), local_port);
            let remote_addr = if remote_port != 0 {
                Some(SocketAddr::new(IpAddr::V4(remote_ip), remote_port))
            } else {
                None
            };

            let state = tcp_state_from_windows(row.dwState);
            connections
                .entry(state)
                .or_default()
                .push(SocketConnection {
                    protocol: SocketProtocol::TcpV4,
                    local_addr,
                    remote_addr,
                    state,
                    pid: Some(row.dwOwningPid),
                    inode: 0,
                });
        }
        Ok(connections)
    }

    pub fn get_tcp6_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size == 0 {
            return Ok(HashMap::new());
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let mut connections: HashMap<SocketState, Vec<SocketConnection>> = HashMap::new();

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_TCP6ROW_OWNER_PID).add(i)) };
            let local_ip = Ipv6Addr::from(row.ucLocalAddr);
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let remote_ip = Ipv6Addr::from(row.ucRemoteAddr);
            let remote_port = u16::from_be(row.dwRemotePort as u16);

            let local_addr = SocketAddr::new(IpAddr::V6(local_ip), local_port);
            let remote_addr = if remote_port != 0 {
                Some(SocketAddr::new(IpAddr::V6(remote_ip), remote_port))
            } else {
                None
            };

            let state = tcp_state_from_windows(row.dwState);
            connections
                .entry(state)
                .or_default()
                .push(SocketConnection {
                    protocol: SocketProtocol::TcpV6,
                    local_addr,
                    remote_addr,
                    state,
                    pid: Some(row.dwOwningPid),
                    inode: 0,
                });
        }
        Ok(connections)
    }

    pub fn get_udp4_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }
        if size == 0 {
            return Ok(HashMap::new());
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        unsafe {
            GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let mut connections: HashMap<SocketState, Vec<SocketConnection>> = HashMap::new();

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID).add(i)) };
            let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let local_addr = SocketAddr::new(IpAddr::V4(local_ip), local_port);

            connections
                .entry(SocketState::Unknown)
                .or_default()
                .push(SocketConnection {
                    protocol: SocketProtocol::UdpV4,
                    local_addr,
                    remote_addr: None,
                    state: SocketState::Unknown,
                    pid: Some(row.dwOwningPid),
                    inode: 0,
                });
        }
        Ok(connections)
    }

    pub fn get_udp6_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }
        if size == 0 {
            return Ok(HashMap::new());
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        unsafe {
            GetExtendedUdpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let mut connections: HashMap<SocketState, Vec<SocketConnection>> = HashMap::new();

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_UDP6ROW_OWNER_PID).add(i)) };
            let local_ip = Ipv6Addr::from(row.ucLocalAddr);
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let local_addr = SocketAddr::new(IpAddr::V6(local_ip), local_port);

            connections
                .entry(SocketState::Unknown)
                .or_default()
                .push(SocketConnection {
                    protocol: SocketProtocol::UdpV6,
                    local_addr,
                    remote_addr: None,
                    state: SocketState::Unknown,
                    pid: Some(row.dwOwningPid),
                    inode: 0,
                });
        }
        Ok(connections)
    }

    pub fn get_process_socket_stats(pid: u32) -> Result<Vec<SocketStats>> {
        // Start ETW network tracing on first call
        crate::etw::start_etw_trace();

        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let mut stats = Vec::new();

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID).add(i)) };
            if row.dwOwningPid != pid {
                continue;
            }

            let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
            let remote_port = u16::from_be(row.dwRemotePort as u16);

            let local_addr = SocketAddr::new(IpAddr::V4(local_ip), local_port);
            let remote_addr = if remote_port != 0 {
                Some(SocketAddr::new(IpAddr::V4(remote_ip), remote_port))
            } else {
                None
            };

            stats.push(SocketStats {
                pid,
                fd: 0,
                protocol: SocketProtocol::TcpV4,
                local_addr,
                remote_addr,
                bytes_sent: 0,
                bytes_received: 0,
            });
        }

        // Apply ETW per-PID byte counters.
        // ETW gives aggregate per-PID counters, so we put them on the first socket.
        // The frontend sums all sockets, giving the correct total.
        if !stats.is_empty() {
            let counters = crate::etw::get_net_io_counters(pid);
            stats[0].bytes_sent = counters.bytes_sent;
            stats[0].bytes_received = counters.bytes_received;
        }

        Ok(stats)
    }

    pub fn get_process_socket_queues(pid: u32) -> Result<Vec<SocketQueueInfo>> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetPerTcpConnectionEStats, SetPerTcpConnectionEStats, TCP_ESTATS_REC_ROD_v0,
            TCP_ESTATS_REC_RW_v0, TCP_ESTATS_SEND_BUFF_ROD_v0, TCP_ESTATS_SEND_BUFF_RW_v0,
            TcpConnectionEstatsRec, TcpConnectionEstatsSendBuff, MIB_TCPROW_LH,
        };

        let mut size: u32 = 0;
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size == 0 {
            return Ok(Vec::new());
        }

        let mut buffer: Vec<u8> = vec![0; size as usize];
        unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let mut result = Vec::new();
        let send_rod_size = std::mem::size_of::<TCP_ESTATS_SEND_BUFF_ROD_v0>();
        let rec_rod_size = std::mem::size_of::<TCP_ESTATS_REC_ROD_v0>();

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID).add(i)) };
            if row.dwOwningPid != pid {
                continue;
            }

            let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let local_port = u16::from_be(row.dwLocalPort as u16);
            let remote_ip = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
            let remote_port = u16::from_be(row.dwRemotePort as u16);

            let local_addr = SocketAddr::new(IpAddr::V4(local_ip), local_port);
            let remote_addr = if remote_port != 0 {
                Some(SocketAddr::new(IpAddr::V4(remote_ip), remote_port))
            } else {
                None
            };

            let state = tcp_state_from_windows(row.dwState);
            let tcp_row_ptr = row as *const MIB_TCPROW_OWNER_PID as *const MIB_TCPROW_LH;

            let mut send_queue: u32 = 0;
            let mut recv_queue: u32 = 0;

            unsafe {
                // Enable EStats SendBuff collection
                let send_rw = TCP_ESTATS_SEND_BUFF_RW_v0 {
                    EnableCollection: windows::Win32::Foundation::BOOLEAN(1),
                };
                let send_set_ret = SetPerTcpConnectionEStats(
                    tcp_row_ptr,
                    TcpConnectionEstatsSendBuff,
                    std::slice::from_raw_parts(
                        &send_rw as *const _ as *const u8,
                        std::mem::size_of::<TCP_ESTATS_SEND_BUFF_RW_v0>(),
                    ),
                    0,
                    0,
                );
                if send_set_ret != 0 {
                    eprintln!(
                        "[QueueStats] SetPerTcpConnectionEStats(SendBuff) returned {send_set_ret}"
                    );
                }

                // Enable EStats Rec collection
                let rec_rw = TCP_ESTATS_REC_RW_v0 {
                    EnableCollection: windows::Win32::Foundation::BOOLEAN(1),
                };
                let rec_set_ret = SetPerTcpConnectionEStats(
                    tcp_row_ptr,
                    TcpConnectionEstatsRec,
                    std::slice::from_raw_parts(
                        &rec_rw as *const _ as *const u8,
                        std::mem::size_of::<TCP_ESTATS_REC_RW_v0>(),
                    ),
                    0,
                    0,
                );
                if rec_set_ret != 0 {
                    eprintln!("[QueueStats] SetPerTcpConnectionEStats(Rec) returned {rec_set_ret}");
                }

                // Read SendBuff ROD
                let mut send_rod_buf = vec![0u8; send_rod_size];
                let send_ret = GetPerTcpConnectionEStats(
                    tcp_row_ptr,
                    TcpConnectionEstatsSendBuff,
                    None,
                    0,
                    None,
                    0,
                    Some(send_rod_buf.as_mut_slice()),
                    0,
                );
                eprintln!("[QueueStats] GetPerTcpConnectionEStats(SendBuff) returned {send_ret} for {local_ip}:{local_port}");

                if send_ret == 0 {
                    let rod = std::ptr::read_unaligned(
                        send_rod_buf.as_ptr() as *const TCP_ESTATS_SEND_BUFF_ROD_v0
                    );
                    let app_queue = rod.CurAppWQueue as u64;
                    let retx_queue = rod.CurRetxQueue as u64;
                    send_queue = (app_queue + retx_queue).min(u32::MAX as u64) as u32;
                    eprintln!(
                        "[QueueStats]   CurAppWQueue={} CurRetxQueue={} send_queue={}",
                        rod.CurAppWQueue, rod.CurRetxQueue, send_queue
                    );
                }

                // Read Rec ROD
                let mut rec_rod_buf = vec![0u8; rec_rod_size];
                let rec_ret = GetPerTcpConnectionEStats(
                    tcp_row_ptr,
                    TcpConnectionEstatsRec,
                    None,
                    0,
                    None,
                    0,
                    Some(rec_rod_buf.as_mut_slice()),
                    0,
                );
                eprintln!("[QueueStats] GetPerTcpConnectionEStats(Rec) returned {rec_ret} for {local_ip}:{local_port}");

                if rec_ret == 0 {
                    let rod = std::ptr::read_unaligned(
                        rec_rod_buf.as_ptr() as *const TCP_ESTATS_REC_ROD_v0
                    );
                    let app_r_queue = rod.CurAppRQueue as u64;
                    let reasm_queue = rod.CurReasmQueue as u64;
                    recv_queue = (app_r_queue + reasm_queue).min(u32::MAX as u64) as u32;
                    eprintln!(
                        "[QueueStats]   CurAppRQueue={} CurReasmQueue={} recv_queue={}",
                        rod.CurAppRQueue, rod.CurReasmQueue, recv_queue
                    );
                }
            }

            result.push(SocketQueueInfo {
                pid,
                fd: 0,
                protocol: SocketProtocol::TcpV4,
                local_addr,
                remote_addr,
                state,
                recv_queue_bytes: recv_queue,
                recv_queue_hiwat: 0,
                send_queue_bytes: send_queue,
                send_queue_hiwat: 0,
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tcp_connections() {
        let result = get_tcp_connections();
        for (state, connections) in result.as_ref().unwrap().iter() {
            println!(
                "state: {:?}, connections count: {:?}",
                state,
                connections.len()
            );
        }
        assert!(
            result.as_ref().is_ok(),
            "Should be able to get TCP connections"
        );
    }

    #[test]
    fn test_get_socket_summary() {
        let summary = get_socket_summary().expect("Failed to get socket summary");
        println!("established: {:?}", summary.established);
        println!("listen: {:?}", summary.listen);
        println!("time_wait: {:?}", summary.time_wait);
        println!("close_wait: {:?}", summary.close_wait);
        println!("syn_sent: {:?}", summary.syn_sent);
        println!("syn_recv: {:?}", summary.syn_recv);
        println!("fin_wait1: {:?}", summary.fin_wait1);
        println!("fin_wait2: {:?}", summary.fin_wait2);
        println!("closing: {:?}", summary.closing);
        println!("last_ack: {:?}", summary.last_ack);
        println!("closed: {:?}", summary.closed);
        println!("total: {:?}", summary.total);
        // Total should be sum of all states
        let sum = summary.established
            + summary.listen
            + summary.time_wait
            + summary.close_wait
            + summary.syn_sent
            + summary.syn_recv
            + summary.fin_wait1
            + summary.fin_wait2
            + summary.closing
            + summary.last_ack
            + summary.closed;

        // Note: sum might not equal total because of Unknown states
        assert!(sum <= summary.total, "State counts should not exceed total");
    }

    #[test]
    fn test_get_process_socket_queues() {
        let pid = std::process::id();
        let result = get_process_socket_queues(pid);
        assert!(result.is_ok(), "Should be able to get socket queues");
        let queues = result.unwrap();
        println!("Found {} socket queues for PID {}", queues.len(), pid);
        for q in &queues {
            println!(
                "  fd={} proto={:?} recv={} send={} state={:?}",
                q.fd, q.protocol, q.recv_queue_bytes, q.send_queue_bytes, q.state
            );
        }
    }
}
