mod macos {
    use super::*;
    use std::process::Command;
    use query_system_info::types::{SocketProtocol, SocketState, SocketConnection};
    use query_system_info::error::{Result, SysInfoError};
    use std::collections::HashMap;
    use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

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
        
        let output = Command::new("netstat")
            .arg("-anv")
            .output()?;
        let stdout = String::from_utf8(output.stdout).unwrap();
        let lines = stdout.lines();
        for line in lines {
            let conn = match parse_netstat_line(line, protocol, proto_type) {
                Some(conn) => conn,
                None => continue,
            };
            connections.entry(conn.state).or_insert(Vec::new()).push(conn);
        }
           
        Ok(connections)
    }

    fn parse_netstat_line(line: &str, protocol: SocketProtocol, proto_type: &str) -> Option<SocketConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // netstat -anv format:
        // Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
        if parts.len() < 6 {
            return None;
        }

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

        let local_str = parts[3];
        let remote_str = parts[4];
        let state = parse_state(parts[5]);

        let local_addr = parse_addr(local_str)?;
        let remote_addr = parse_addr(remote_str);

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


fn main() {
    let sockets = macos::get_tcp4_connections().unwrap();
    for (state, connections) in sockets {
        println!("protocol: tcp4, State: {}， Connections: {}", state, connections.len());
    }
    let sockets = macos::get_tcp6_connections().unwrap();
    for (state, connections) in sockets {
        println!("protocol: tcp6, State: {}， Connections: {}", state, connections.len());
    }
    let sockets = macos::get_udp4_sockets().unwrap();
    for (state, connections) in sockets {
        println!("protocol: udp4, State: {}， Connections: {}", state, connections.len());
    }
    let sockets = macos::get_udp6_sockets().unwrap();
    for (state, connections) in sockets {
        println!("protocol: udp6, State: {}， Connections: {}", state, connections.len());
    }
}