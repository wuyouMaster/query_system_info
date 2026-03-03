//! Socket/Network connection information module
//!
//! Provides cross-platform network socket information gathering.
//!
//! Platform-specific implementations:
//! - **Linux**: Uses netlink socket (NETLINK_SOCK_DIAG) for efficient kernel-level socket enumeration
//! - **macOS**: Uses `proc_listpidspath` and `lsof` style syscalls via libproc
//! - **Windows**: Uses `GetExtendedTcpTable` and `GetExtendedUdpTable` from IP Helper API

use crate::error::{Result, SysInfoError};
use crate::types::{SocketConnection, SocketProtocol, SocketState, SocketStateSummary};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Get all TCP connections (IPv4 and IPv6)
pub fn get_tcp_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
    connections.extend(get_tcp4_connections()?);
    connections.extend(get_tcp6_connections()?);
    Ok(connections)
}

/// Get all UDP sockets (IPv4 and IPv6)
pub fn get_udp_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
    connections.extend(get_udp4_sockets()?.into_iter());
    connections.extend(get_udp6_sockets()?.into_iter());
    Ok(connections)
}

/// Get all socket connections (TCP and UDP)
pub fn get_all_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
    let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
    connections.extend(get_tcp_connections()?);
    connections.extend(get_udp_sockets()?);
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
                            pid: None,
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

        for line in contents.lines().skip(1) {
            // Skip header
            if let Some(conn) = parse_proc_net_line(line, SocketProtocol::TcpV4) {
                connections.push(conn);
            }
        }

        Ok(connections)
    }

    #[allow(dead_code)]
    fn parse_proc_net_line(line: &str, protocol: SocketProtocol) -> Option<SocketConnection> {
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

        Some(SocketConnection {
            protocol,
            local_addr: local,
            remote_addr,
            state: tcp_state_from_kernel(state),
            pid: None,
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
}

// ============================================================================
// macOS Implementation - Using syscalls and /proc-like interfaces
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    // use the `netstat` command to get the status of the socket

    pub fn get_tcp4_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_connections_via_netstat(SocketProtocol::TcpV4, "tcp4")
    }

    pub fn get_tcp6_connections() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_connections_via_netstat(SocketProtocol::TcpV6, "tcp6")
    }

    pub fn get_udp4_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_connections_via_netstat(SocketProtocol::UdpV4, "udp4")
    }

    pub fn get_udp6_sockets() -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        get_connections_via_netstat(SocketProtocol::UdpV6, "udp6")
    }

    pub fn get_connections_via_netstat(
        protocol: SocketProtocol,
        proto_type: &str,
    ) -> Result<HashMap<SocketState, Vec<SocketConnection>>> {
        let mut connections = HashMap::<SocketState, Vec<SocketConnection>>::new();
        let output = Command::new("netstat").arg("-anv").output()?;
        let stdout = String::from_utf8(output.stdout).unwrap();
        let lines = stdout.lines();
        for line in lines {
            let conn = match parse_netstat_line(line, protocol, proto_type) {
                Some(conn) => conn,
                None => continue,
            };
            connections
                .entry(conn.state)
                .or_insert(Vec::new())
                .push(conn);
        }
        Ok(connections)
    }

    fn parse_netstat_line(
        line: &str,
        protocol: SocketProtocol,
        proto_type: &str,
    ) -> Option<SocketConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // netstat -anv format:
        // Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
        if parts.len() < 6 {
            return None;
        }

        let local_str = parts[3];
        let remote_str = parts[4];

        let local_addr = parse_addr(local_str)?;
        let remote_addr = parse_addr(remote_str);
        let state = parse_state(parts[5]);

        match proto_type {
            "tcp4" => {
                if parts[0] != "tcp4" {
                    return None;
                }
            }
            "tcp6" => {
                if parts[0] != "tcp6" {
                    return None;
                }
            }
            "udp4" => {
                if parts[0] != "udp4" {
                    return None;
                }
            }
            "udp6" => {
                if parts[0] != "udp6" {
                    return None;
                }
            }
            _ => {
                return None;
            }
        }

        Some(SocketConnection {
            protocol,
            local_addr,
            remote_addr,
            state,
            pid: None,
            inode: 0,
        })
    }

    fn parse_addr(s: &str) -> Option<SocketAddr> {
        // Handle formats like:
        // 127.0.0.1.8080 (IPv4)
        // *.* (wildcard)
        // fe80::1%lo0.8080 (IPv6 with scope)

        if s == "*.*" {
            return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        }

        // Find the last dot which separates port
        if let Some(last_dot) = s.rfind('.') {
            let addr_part = &s[..last_dot];
            let port_part = &s[last_dot + 1..];

            let port: u16 = if port_part == "*" {
                0
            } else {
                port_part.parse().ok()?
            };

            // Try parsing as IPv4
            if let Ok(ip) = addr_part.parse::<Ipv4Addr>() {
                return Some(SocketAddr::new(IpAddr::V4(ip), port));
            }

            // Handle macOS IPv4 format: a.b.c.d.port -> need to rejoin
            let parts: Vec<&str> = s.split('.').collect();
            if parts.len() >= 5 {
                // IPv4 has 4 octets + port
                let ip_str = parts[..4].join(".");
                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                    let port: u16 = parts[4].parse().unwrap_or(0);
                    return Some(SocketAddr::new(IpAddr::V4(ip), port));
                }
            }

            // Try IPv6
            // Remove scope identifier if present
            let addr_clean = addr_part.split('%').next().unwrap_or(addr_part);
            if let Ok(ip) = addr_clean.parse::<Ipv6Addr>() {
                return Some(SocketAddr::new(IpAddr::V6(ip), port));
            }
        }

        // Try standard socket address parsing
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Some(addr);
        }

        None
    }

    fn parse_state(s: &str) -> SocketState {
        match s.to_uppercase().as_str() {
            "ESTABLISHED" => SocketState::Established,
            "SYN_SENT" => SocketState::SynSent,
            "SYN_RECEIVED" | "SYN_RECV" => SocketState::SynReceived,
            "FIN_WAIT_1" | "FIN_WAIT1" => SocketState::FinWait1,
            "FIN_WAIT_2" | "FIN_WAIT2" => SocketState::FinWait2,
            "TIME_WAIT" => SocketState::TimeWait,
            "CLOSED" => SocketState::Closed,
            "CLOSE_WAIT" => SocketState::CloseWait,
            "LAST_ACK" => SocketState::LastAck,
            "LISTEN" => SocketState::Listen,
            "CLOSING" => SocketState::Closing,
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

    pub fn get_tcp4_connections() -> Result<SocketState, Vec<SocketConnection>> {
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
            )
            .map_err(|e| SysInfoError::WindowsApi(format!("GetExtendedTcpTable failed: {}", e)))?;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let mut connections = Vec::with_capacity(table.dwNumEntries as usize);

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

            connections.push(SocketConnection {
                protocol: SocketProtocol::TcpV4,
                local_addr,
                remote_addr,
                state: tcp_state_from_windows(row.dwState),
                pid: Some(row.dwOwningPid),
                inode: 0,
            });
        }

        Ok(connections)
    }

    pub fn get_tcp6_connections() -> Result<SocketState, Vec<SocketConnection>> {
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
            return Ok(Vec::new());
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
            )
            .map_err(|e| {
                SysInfoError::WindowsApi(format!("GetExtendedTcpTable IPv6 failed: {}", e))
            })?;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let mut connections = Vec::with_capacity(table.dwNumEntries as usize);

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

            connections
                .entry(tcp_state_from_windows(row.dwState))
                .or_insert(Vec::new())
                .push(SocketConnection {
                    protocol: SocketProtocol::TcpV6,
                    local_addr,
                    remote_addr,
                    state: tcp_state_from_windows(row.dwState),
                    pid: Some(row.dwOwningPid),
                    inode: 0,
                });
        }

        Ok(connections)
    }

    pub fn get_udp4_sockets() -> Result<SocketState, Vec<SocketConnection>> {
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
            return Ok(Vec::new());
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
            )
            .map_err(|e| SysInfoError::WindowsApi(format!("GetExtendedUdpTable failed: {}", e)))?;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let mut connections = Vec::with_capacity(table.dwNumEntries as usize);

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_UDPROW_OWNER_PID).add(i)) };

            let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
            let local_port = u16::from_be(row.dwLocalPort as u16);

            let local_addr = SocketAddr::new(IpAddr::V4(local_ip), local_port);

            connections
                .entry(SocketState::Unknown)
                .or_insert(Vec::new())
                .push(SocketConnection {
                    protocol: SocketProtocol::UdpV4,
                    local_addr,
                    remote_addr: None, // UDP is connectionless
                    state: tcp_state_from_windows(row.dwState),
                    pid: Some(row.dwOwningPid),
                    inode: 0,
                });
        }

        Ok(connections)
    }

    pub fn get_udp6_sockets() -> Result<Vec<SocketConnection>> {
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
            return Ok(Vec::new());
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
            )
            .map_err(|e| {
                SysInfoError::WindowsApi(format!("GetExtendedUdpTable IPv6 failed: {}", e))
            })?;
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let mut connections = Vec::with_capacity(table.dwNumEntries as usize);

        for i in 0..table.dwNumEntries as usize {
            let row = unsafe { &*((table.table.as_ptr() as *const MIB_UDP6ROW_OWNER_PID).add(i)) };

            let local_ip = Ipv6Addr::from(row.ucLocalAddr);
            let local_port = u16::from_be(row.dwLocalPort as u16);

            let local_addr = SocketAddr::new(IpAddr::V6(local_ip), local_port);

            connections
                .entry(tcp_state_from_windows(row.dwState))
                .or_insert(Vec::new())
                .push(SocketConnection {
                    protocol: SocketProtocol::UdpV6,
                    local_addr,
                    remote_addr: None,
                    state: tcp_state_from_windows(row.dwState),
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
