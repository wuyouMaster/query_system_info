//! Socket/Network connection information module
//!
//! Provides cross-platform network socket information gathering.
//!
//! Platform-specific implementations:
//! - **Linux**: Uses netlink socket (NETLINK_SOCK_DIAG) for efficient kernel-level socket enumeration
//! - **macOS**: Uses `proc_listpidspath` and `lsof` style syscalls via libproc
//! - **Windows**: Uses `GetExtendedTcpTable` and `GetExtendedUdpTable` from IP Helper API

use crate::error::Result;
use crate::types::{
    SocketConnection, SocketConnectionEvent, SocketProtocol, SocketState, SocketStateSummary,
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
    use std::fs;
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
}

// ============================================================================
// Windows Implementation - Using IP Helper API (iphlpapi)
// ============================================================================

#[cfg(target_os = "windows")]
mod innerWindows {
    use super::*;
    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr};
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

        // First call to get required buffer size
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
}
