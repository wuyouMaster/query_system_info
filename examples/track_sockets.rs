use query_system_info::process;
use std::thread;
use std::time::Duration;

fn main() {
    let pid = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| {
            eprintln!("Usage: cargo run --example track_sockets <pid>");
            std::process::exit(1);
        });

    println!("Tracking sockets of PID: {}", pid);

    let tracker = process::start_tracking_sockets(pid, |socket| {
        println!("\n[New Socket Detected]");
        println!("  PID: {}", socket.pid);
        println!("  Protocol: {}", socket.protocol);
        println!("  Local: {}", socket.local_addr);
        println!("  Remote: {:?}", socket.remote_addr);
        println!("  State: {}", socket.state);
        println!("  Inode: {}", socket.inode);
    })
    .expect("Failed to start tracking");

    println!("Tracking started. Press Ctrl+C to stop...\n");

    thread::sleep(Duration::from_secs(60));

    tracker.stop();
    println!("\nTracking stopped.");
}
