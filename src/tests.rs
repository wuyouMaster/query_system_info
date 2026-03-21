// Unit tests for all public platform APIs.
//
// Run: cargo test --lib

// ============================================================================
//  types.rs
// ============================================================================

#[cfg(test)]
mod test_types {
    use crate::types::*;

    #[test]
    fn test_socket_state_summary_from_connections() {
        let conns = vec![
            SocketConnection {
                protocol: SocketProtocol::TcpV4,
                local_addr: "127.0.0.1:80".parse().unwrap(),
                remote_addr: None,
                state: SocketState::Listen,
                pid: Some(1),
                inode: 0,
            },
            SocketConnection {
                protocol: SocketProtocol::TcpV4,
                local_addr: "127.0.0.1:443".parse().unwrap(),
                remote_addr: Some("10.0.0.1:55555".parse().unwrap()),
                state: SocketState::Established,
                pid: Some(1),
                inode: 0,
            },
            SocketConnection {
                protocol: SocketProtocol::UdpV4,
                local_addr: "0.0.0.0:53".parse().unwrap(),
                remote_addr: None,
                state: SocketState::Unknown,
                pid: Some(2),
                inode: 0,
            },
        ];
        let summary =
            SocketStateSummary::from_connections(&conns.iter().collect::<Vec<&SocketConnection>>());
        assert_eq!(summary.total, 3);
        assert_eq!(summary.established, 1);
        assert_eq!(summary.listen, 1);
    }

    #[test]
    fn test_socket_protocol_variants() {
        let p = SocketProtocol::TcpV4;
        let s = p.to_string();
        assert!(!s.is_empty(), "protocol display should not be empty");
        // Just verify it has a Display impl - exact format depends on platform
        let _ = format!("{p:?}");
    }

    #[test]
    fn test_process_state_variants() {
        let states = [
            ProcessState::Running,
            ProcessState::Sleeping,
            ProcessState::Stopped,
            ProcessState::Zombie,
            ProcessState::Idle,
            ProcessState::Unknown,
        ];
        assert_eq!(states.len(), 6);
        assert!(format!("{:?}", ProcessState::Running).contains("Running"));
    }

    #[test]
    fn test_memory_info_defaults() {
        let m = MemoryInfo::default();
        assert_eq!(m.total, 0);
        assert_eq!(m.usage_percent, 0.0);
    }

    #[test]
    fn test_disk_info_fields() {
        let d = DiskInfo {
            device: "/dev/sda1".to_string(),
            mount_point: "/".to_string(),
            fs_type: "ext4".to_string(),
            total_bytes: 1_000_000_000,
            used_bytes: 500_000_000,
            available_bytes: 500_000_000,
            usage_percent: 50.0,
        };
        assert_eq!(d.device, "/dev/sda1");
        assert!(d.usage_percent > 0.0);
    }

    #[test]
    fn test_socket_state_display() {
        let s = format!("{}", SocketState::Established);
        assert!(!s.is_empty(), "Established display should not be empty");
        let _ = format!("{}", SocketState::Listen);
        let _ = format!("{}", SocketState::Closed);
        let _ = format!("{}", SocketState::Unknown);
    }
}

// ============================================================================
//  util.rs
// ============================================================================

#[cfg(test)]
mod test_util {
    use crate::util::*;

    #[test]
    fn test_read_u32_ok() {
        let buf: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32(&buf, 0), Some(u32::from_ne_bytes(buf)));
    }

    #[test]
    fn test_read_u32_out_of_bounds() {
        let buf: [u8; 3] = [0x01, 0x02, 0x03];
        assert_eq!(read_u32(&buf, 0), None);
    }

    #[test]
    fn test_read_u32_offset_ok() {
        let buf: [u8; 8] = [0, 0, 0xFF, 0, 0, 0, 0, 0];
        assert_eq!(read_u32(&buf, 2), Some(u32::from_ne_bytes([0xFF, 0, 0, 0])));
    }

    #[test]
    fn test_read_u32_as_usize() {
        let buf: [u8; 4] = [0x10, 0, 0, 0];
        assert_eq!(read_u32_as_usize(&buf, 0), Some(16usize));
    }

    #[test]
    fn test_read_i32() {
        let buf: [u8; 4] = (-42i32).to_ne_bytes();
        assert_eq!(read_i32(&buf, 0), Some(-42));
    }
}

// ============================================================================
//  error.rs
// ============================================================================

#[cfg(test)]
mod test_error {
    use crate::error::SysInfoError;
    use std::io;

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let sys_err: SysInfoError = io_err.into();
        match sys_err {
            SysInfoError::Io(_) => {}
            _ => panic!("Expected Io variant"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = SysInfoError::NotSupported("test".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("Not supported"));
    }
}

// ============================================================================
//  cpu.rs
// ============================================================================

#[cfg(test)]
mod test_cpu {
    use crate::cpu::*;
    use std::time::Duration;

    #[test]
    fn test_get_cpu_times_returns_entries() {
        let result = get_cpu_times();
        assert!(result.is_ok(), "get_cpu_times should not error");
        // On some Windows setups, PDH counters may return empty; just verify no panic
        let times = result.unwrap();
        if !times.is_empty() {
            for (i, t) in times.iter().enumerate() {
                let total = t.user + t.system + t.idle;
                assert!(total > 0, "CPU {i} total ticks should be > 0");
            }
        }
    }

    #[test]
    fn test_get_cpu_times_values_sane() {
        let times = get_cpu_times().expect("get_cpu_times failed");
        for (i, t) in times.iter().enumerate() {
            let total = t.user + t.system + t.idle;
            assert!(total > 0, "CPU {i} total ticks should be > 0");
        }
    }

    #[test]
    fn test_get_cpu_info_basic() {
        let info = get_cpu_info().expect("get_cpu_info failed");
        assert!(info.logical_cores > 0, "should have > 0 logical cores");
        assert!(
            info.physical_cores > 0 && info.physical_cores <= info.logical_cores,
            "physical_cores should be in [1, logical_cores]"
        );
    }

    #[test]
    fn test_get_cpu_info_model_name() {
        let info = get_cpu_info().unwrap();
        assert!(
            !info.model_name.is_empty(),
            "model_name should not be empty"
        );
    }

    #[test]
    fn test_get_cpu_usage_range() {
        let usages = get_cpu_usage(Duration::from_millis(200)).expect("get_cpu_usage failed");
        assert!(!usages.is_empty(), "should have at least 1 CPU usage entry");
        for (i, u) in usages.iter().enumerate() {
            assert!(
                *u >= 0.0 && *u <= 100.0,
                "CPU {i} usage {u} not in [0, 100]"
            );
        }
    }

    #[test]
    fn test_get_cpu_times_increases_over_time() {
        let t1 = get_cpu_times().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let t2 = get_cpu_times().unwrap();
        assert_eq!(t1.len(), t2.len(), "CPU count should not change");
        let total1: u64 = t1.iter().map(|t| t.user + t.system + t.idle).sum();
        let total2: u64 = t2.iter().map(|t| t.user + t.system + t.idle).sum();
        assert!(total2 >= total1, "total CPU ticks should not decrease");
    }
}

// ============================================================================
//  memory.rs
// ============================================================================

#[cfg(test)]
mod test_memory {
    use crate::memory::*;

    #[test]
    fn test_get_memory_info_basic() {
        let info = get_memory_info().expect("get_memory_info failed");
        assert!(info.total > 0, "total memory should be > 0");
        assert!(info.used <= info.total, "used should not exceed total");
        assert!(
            info.available <= info.total,
            "available should not exceed total"
        );
    }

    #[test]
    fn test_get_memory_info_usage_percent() {
        let info = get_memory_info().unwrap();
        assert!(
            info.usage_percent >= 0.0 && info.usage_percent <= 100.0,
            "usage_percent ({}) not in [0, 100]",
            info.usage_percent
        );
    }

    #[test]
    fn test_get_memory_info_free_le_total() {
        let info = get_memory_info().unwrap();
        assert!(info.free <= info.total, "free should not exceed total");
    }
}

// ============================================================================
//  disk.rs
// ============================================================================

#[cfg(test)]
mod test_disk {
    use crate::disk::*;

    #[test]
    fn test_get_disks_returns_entries() {
        let disks = get_disks().expect("get_disks failed");
        assert!(!disks.is_empty(), "should have at least 1 disk");
    }

    #[test]
    fn test_get_disks_sane_values() {
        let disks = get_disks().unwrap();
        for d in &disks {
            assert!(!d.device.is_empty(), "device name should not be empty");
            assert!(!d.mount_point.is_empty(), "mount_point should not be empty");
            assert!(
                d.total_bytes > 0,
                "disk {} total_bytes should be > 0",
                d.device
            );
            assert!(
                d.used_bytes <= d.total_bytes,
                "disk {} used_bytes overflow",
                d.device
            );
            assert!(
                d.available_bytes <= d.total_bytes,
                "disk {} available_bytes overflow",
                d.device
            );
            assert!(
                d.usage_percent >= 0.0 && d.usage_percent <= 100.0,
                "disk {} usage_percent out of range",
                d.device
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_disks_linux_has_root() {
        let disks = get_disks().unwrap();
        assert!(
            disks.iter().any(|d| d.mount_point == "/"),
            "should have root filesystem on Linux"
        );
    }

    #[test]
    fn test_get_disk_io_stats_runs() {
        let result = get_disk_io_stats();
        assert!(result.is_ok(), "get_disk_io_stats should not error");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_disk_io_stats_linux_has_entries() {
        let stats = get_disk_io_stats().unwrap();
        assert!(!stats.is_empty(), "should have disk IO entries on Linux");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_disk_io_stats_linux_sane_values() {
        let stats = get_disk_io_stats().unwrap();
        for s in &stats {
            assert!(!s.device.is_empty(), "device name should not be empty");
        }
    }
}

// ============================================================================
//  process.rs
// ============================================================================

#[cfg(test)]
mod test_process {
    use crate::process::*;

    #[test]
    fn test_list_processes_returns_entries() {
        let procs = list_processes().expect("list_processes failed");
        assert!(!procs.is_empty(), "should have at least 1 process");
    }

    #[test]
    fn test_list_processes_sane_values() {
        let procs = list_processes().unwrap();
        for p in &procs {
            assert!(p.pid > 0, "pid should be > 0");
            assert!(!p.name.is_empty(), "process name should not be empty");
        }
    }

    #[test]
    fn test_list_processes_has_current_process() {
        let procs = list_processes().unwrap();
        let my_pid = std::process::id();
        assert!(
            procs.iter().any(|p| p.pid == my_pid),
            "should find current process (pid={my_pid}) in list"
        );
    }

    #[test]
    fn test_get_process_info_self() {
        let pid = std::process::id();
        let info = get_process_info(pid).expect("get_process_info failed for self");
        assert_eq!(info.pid, pid);
        assert!(!info.name.is_empty());
    }

    #[test]
    fn test_get_process_io_self() {
        let pid = std::process::id();
        let io = get_process_io(pid).expect("get_process_io failed for self");
        let _ = io.read_bytes;
        let _ = io.write_bytes;
    }

    #[test]
    fn test_get_process_info_nonexistent() {
        let result = get_process_info(u32::MAX);
        assert!(result.is_err(), "nonexistent PID should return error");
    }

    #[test]
    fn test_kill_process_nonexistent() {
        let result = kill_process(u32::MAX);
        assert!(result.is_err(), "killing nonexistent process should error");
    }

    #[test]
    fn test_start_tracking_children_detects_spawned_process() {
        use std::sync::mpsc;
        use std::time::Duration;

        let my_pid = std::process::id();
        let (tx, rx) = mpsc::channel();

        let tracker = start_tracking_children(my_pid, move |event| {
            let _ = tx.send(event);
        })
        .expect("start_tracking_children failed");

        // Spawn a child process from this process
        #[cfg(not(target_os = "windows"))]
        let child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("failed to spawn child");

        #[cfg(target_os = "windows")]
        let child = std::process::Command::new("cmd")
            .args(["/c", "ping", "-n", "6", "127.0.0.1"])
            .spawn()
            .expect("failed to spawn child");

        let child_pid = child.id();

        // Wait for the tracker callback to fire (poll interval is 500ms)
        let mut found = false;
        for _ in 0..10 {
            if let Ok(event) = rx.recv_timeout(Duration::from_millis(600)) {
                if event.pid == child_pid {
                    assert_eq!(event.ppid, my_pid);
                    assert!(!event.name.is_empty(), "child name should not be empty");
                    found = true;
                    break;
                }
            }
        }

        tracker.stop();

        // Clean up child
        let _ = kill_process(child_pid);

        assert!(
            found,
            "tracker should have detected child process (pid={child_pid})"
        );
    }

    #[test]
    fn test_start_tracking_children_stop_terminates_loop() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::Duration;

        let my_pid = std::process::id();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let tracker = start_tracking_children(my_pid, move |_event| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("start_tracking_children failed");

        // Let it run for a bit
        std::thread::sleep(Duration::from_millis(1200));
        tracker.stop();

        // Drain any pending notifications
        std::thread::sleep(Duration::from_millis(200));
        let count_after_stop = counter.load(Ordering::SeqCst);

        // Wait a bit more and verify no more callbacks
        std::thread::sleep(Duration::from_millis(1200));
        let count_final = counter.load(Ordering::SeqCst);

        assert_eq!(
            count_after_stop, count_final,
            "no callbacks should fire after stop()"
        );
    }

    #[test]
    fn test_start_tracking_sockets_self() {
        use std::sync::mpsc;
        use std::time::Duration;

        let my_pid = std::process::id();
        let (tx, rx) = mpsc::channel();

        let tracker = start_tracking_sockets(my_pid, move |event| {
            let _ = tx.send(event);
        })
        .expect("start_tracking_sockets failed");

        // Give the tracker time to poll
        std::thread::sleep(Duration::from_millis(1200));
        tracker.stop();

        // Verify all received events belong to our PID
        let mut event_count = 0usize;
        while let Ok(event) = rx.try_recv() {
            assert_eq!(event.pid, my_pid, "event pid should match tracked pid");
            event_count += 1;
        }

        // It's OK if there are no sockets for this process, but the tracker should not error
        println!("Received {event_count} socket events for pid {my_pid}");
    }

    #[test]
    fn test_start_tracking_queues_self() {
        use std::sync::mpsc;
        use std::time::Duration;

        let my_pid = std::process::id();
        let (tx, rx) = mpsc::channel();

        let tracker = start_tracking_queues(my_pid, move |queues| {
            let _ = tx.send(queues);
        })
        .expect("start_tracking_queues failed");

        // Queue tracker polls every 500ms
        let mut found_queues = false;
        for _ in 0..5 {
            if let Ok(queues) = rx.recv_timeout(Duration::from_millis(600)) {
                for q in &queues {
                    assert_eq!(q.pid, my_pid, "queue pid should match tracked pid");
                }
                found_queues = true;
                break;
            }
        }

        tracker.stop();
        assert!(
            found_queues,
            "should have received at least one queue snapshot"
        );
    }

    #[test]
    fn test_start_tracking_sockets_with_tcp_listener() {
        use std::net::TcpListener;
        use std::sync::mpsc;
        use std::time::Duration;

        let my_pid = std::process::id();
        let (tx, rx) = mpsc::channel();

        // Bind a TCP listener to create a known socket
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let local_port = listener.local_addr().unwrap().port();

        let tracker = start_tracking_sockets(my_pid, move |event| {
            let _ = tx.send(event);
        })
        .expect("start_tracking_sockets failed");

        // Wait for tracker to detect the socket
        std::thread::sleep(Duration::from_millis(1200));
        tracker.stop();

        let mut found_our_socket = false;
        while let Ok(event) = rx.try_recv() {
            if event.local_addr.port() == local_port {
                assert_eq!(event.pid, my_pid);
                found_our_socket = true;
                break;
            }
        }

        drop(listener);

        assert!(
            found_our_socket,
            "tracker should have detected our TCP listener on port {local_port}"
        );
    }
}

// ============================================================================
//  socket.rs  (cross-platform public APIs)
// ============================================================================

#[cfg(test)]
mod test_socket {
    use crate::socket::*;

    #[test]
    fn test_get_tcp_connections() {
        assert!(
            get_tcp_connections().is_ok(),
            "get_tcp_connections should not error"
        );
    }

    #[test]
    fn test_get_udp_sockets() {
        assert!(
            get_udp_sockets().is_ok(),
            "get_udp_sockets should not error"
        );
    }

    #[test]
    fn test_get_all_connections() {
        assert!(
            get_all_connections().is_ok(),
            "get_all_connections should not error"
        );
    }

    #[test]
    fn test_get_tcp4_connections() {
        assert!(
            get_tcp4_connections().is_ok(),
            "get_tcp4_connections should not error"
        );
    }

    #[test]
    fn test_get_tcp6_connections() {
        assert!(
            get_tcp6_connections().is_ok(),
            "get_tcp6_connections should not error"
        );
    }

    #[test]
    fn test_get_udp4_sockets() {
        assert!(
            get_udp4_sockets().is_ok(),
            "get_udp4_sockets should not error"
        );
    }

    #[test]
    fn test_get_udp6_sockets() {
        assert!(
            get_udp6_sockets().is_ok(),
            "get_udp6_sockets should not error"
        );
    }

    #[test]
    fn test_get_all_connections_is_tcp_plus_udp() {
        let tcp = get_tcp_connections().unwrap();
        let udp = get_udp_sockets().unwrap();
        let all = get_all_connections().unwrap();

        let tcp_total: usize = tcp.values().map(|v| v.len()).sum();
        let udp_total: usize = udp.values().map(|v| v.len()).sum();
        let all_total: usize = all.values().map(|v| v.len()).sum();

        assert_eq!(
            all_total,
            tcp_total + udp_total,
            "all_connections should equal tcp + udp"
        );
    }

    #[test]
    fn test_get_socket_summary() {
        let summary = get_socket_summary().expect("get_socket_summary failed");
        assert!(summary.total >= summary.established + summary.listen);
    }

    #[test]
    fn test_get_process_socket_stats_self() {
        let pid = std::process::id();
        let stats = get_process_socket_stats(pid).expect("get_process_socket_stats failed");
        for s in &stats {
            assert_eq!(s.pid, pid);
        }
    }

    #[test]
    fn test_get_process_socket_queues_self() {
        let pid = std::process::id();
        let queues = get_process_socket_queues(pid).expect("get_process_socket_queues failed");
        for q in &queues {
            assert_eq!(q.pid, pid);
        }
    }

    #[test]
    fn test_get_connections_by_pid_self() {
        let pid = std::process::id();
        let events = get_connections_by_pid(pid).expect("get_connections_by_pid failed");
        for e in &events {
            assert_eq!(e.pid, pid);
        }
    }
}

// ============================================================================
//  etw.rs  (Windows-only)
// ============================================================================

#[cfg(target_os = "windows")]
#[cfg(test)]
mod test_etw {
    use crate::etw::*;

    #[test]
    fn test_get_net_io_counters_default() {
        let c = get_net_io_counters(u32::MAX);
        assert_eq!(c.bytes_sent, 0);
        assert_eq!(c.bytes_received, 0);
    }
}
