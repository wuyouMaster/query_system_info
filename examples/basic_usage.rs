//! Basic usage example for query_system_info
//!
//! Run with: cargo run --example basic_usage

use query_system_info::{cpu, disk, memory, process, socket, types::SocketState};
use std::time::Duration;

fn main() -> query_system_info::Result<()> {
    println!("=== System Information Query ===\n");

    // ========================================
    // Memory Information
    // ========================================
    println!("--- Memory Information ---");
    let mem = memory::get_memory_info()?;
    println!("Total:     {:>12} MB", mem.total / 1024 / 1024);
    println!(
        "Used:      {:>12} MB ({:.1}%)",
        mem.used / 1024 / 1024,
        mem.usage_percent
    );
    println!("Available: {:>12} MB", mem.available / 1024 / 1024);
    println!("Free:      {:>12} MB", mem.free / 1024 / 1024);
    if mem.swap_total > 0 {
        println!(
            "Swap:      {:>12} MB / {} MB",
            mem.swap_used / 1024 / 1024,
            mem.swap_total / 1024 / 1024
        );
    }
    println!();

    // ========================================
    // CPU Information
    // ========================================
    println!("--- CPU Information ---");
    let cpu_info = cpu::get_cpu_info()?;
    println!("Model:          {}", cpu_info.model_name);
    println!("Vendor:         {}", cpu_info.vendor);
    println!("Physical cores: {}", cpu_info.physical_cores);
    println!("Logical cores:  {}", cpu_info.logical_cores);
    if cpu_info.frequency_mhz > 0 {
        println!("Frequency:      {} MHz", cpu_info.frequency_mhz);
    }

    // Get CPU usage (takes ~500ms to sample)
    print!("CPU Usage:      ");
    std::io::Write::flush(&mut std::io::stdout()).ok();
    let usage = cpu::get_cpu_usage(Duration::from_millis(500))?;
    for (i, usage) in usage.iter().enumerate() {
        println!("Core {}: {:.1}%", i, usage);
    }
    println!();

    // ========================================
    // Disk Information
    // ========================================
    println!("--- Disk Information ---");
    let disks = disk::get_disks()?;
    for d in &disks {
        println!(
            "{:20} {:>10} GB / {:>10} GB ({:.1}%) [{}]",
            d.mount_point,
            d.used_bytes / 1024 / 1024 / 1024,
            d.total_bytes / 1024 / 1024 / 1024,
            d.usage_percent,
            d.fs_type
        );
    }
    println!();

    // Disk I/O stats (if available)
    println!("--- Disk I/O Statistics ---");
    match disk::get_disk_io_stats() {
        Ok(stats) => {
            for stat in &stats {
                if stat.bytes_read > 0 || stat.bytes_written > 0 {
                    println!(
                        "{:12} Read: {:>10} MB, Written: {:>10} MB",
                        stat.device,
                        stat.bytes_read / 1024 / 1024,
                        stat.bytes_written / 1024 / 1024
                    );
                }
            }
        }
        Err(e) => println!("Could not get disk I/O stats: {}", e),
    }
    println!();

    // ========================================
    // Process Information
    // ========================================
    println!("--- Process Information ---");
    let processes = process::list_processes()?;
    println!("Total processes: {}", processes.len());

    // Show top 10 processes by memory usage
    let mut sorted_procs = processes.clone();
    sorted_procs.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));

    println!("\nTop 10 processes by memory:");
    println!(
        "{:>8} {:>10} {:>8} {}",
        "PID", "Memory(MB)", "State", "Name"
    );
    for p in sorted_procs.iter().take(10) {
        println!(
            "{:>8} {:>10} {:>8} {}",
            p.pid,
            p.memory_bytes / 1024 / 1024,
            p.state.to_string(),
            p.name
        );
    }
    println!();

    // ========================================
    // Socket Information
    // ========================================
    println!("--- Socket Information ---");

    // Get summary
    let summary = socket::get_socket_summary()?;

    println!("Total connections: {}", summary.total);
    println!("  ESTABLISHED: {}", summary.established);
    println!("  LISTEN:      {}", summary.listen);
    println!("  TIME_WAIT:   {}", summary.time_wait);
    println!("  CLOSE_WAIT:  {}", summary.close_wait);
    println!("  SYN_SENT:    {}", summary.syn_sent);
    println!("  SYN_RECV:    {}", summary.syn_recv);
    println!("  FIN_WAIT1:   {}", summary.fin_wait1);
    println!("  FIN_WAIT2:   {}", summary.fin_wait2);
    println!("  CLOSING:     {}", summary.closing);
    println!("  LAST_ACK:    {}", summary.last_ack);
    println!();

    // Show some TCP connections
    let tcp_conns = socket::get_tcp_connections()?;
    let listening: Vec<_> = tcp_conns
        .iter()
        .filter(|(state, _)| **state == SocketState::Listen)
        .collect();
    for (state, connections) in listening {
        println!(
            "state: {:?}, connections count: {:?}",
            state,
            connections.len()
        );
    }

    // Get established connections from the HashMap
    if let Some(established_conns) = tcp_conns.get(&SocketState::Established) {
        println!(
            "state: {:?}, len: {}",
            SocketState::Established,
            established_conns.len()
        );
        for item in established_conns.iter() {
            println!("item: {:?}", item);
        }
    }
    Ok(())
}
