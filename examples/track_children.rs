use query_system_info::process;
use std::thread;
use std::time::Duration;

fn main() {
    let pid = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| {
            eprintln!("Usage: cargo run --example track_children <pid>");
            std::process::exit(1);
        });

    println!("Tracking children of PID: {}", pid);

    let tracker = process::start_tracking_children(pid, |child| {
        println!("\n[New Child Process Detected]");
        println!("  PID: {}", child.pid);
        println!("  PPID: {}", child.ppid);
        println!("  Name: {}", child.name);
        println!("  Command: {}", child.cmdline.join(" "));
        println!("  Exe: {}", child.exe_path);
    })
    .expect("Failed to start tracking");

    println!("Tracking started. Press Ctrl+C to stop...\n");

    thread::sleep(Duration::from_secs(60));

    tracker.stop();
    println!("\nTracking stopped.");
}
