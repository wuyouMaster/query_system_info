//! ETW-based network I/O byte counter for Windows.
//!
//! Uses the Kernel TCP/IP provider to trace
//! TcpIp_Send / TcpIp_Receive events and accumulate per-PID byte counters.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Per-process network I/O byte counters accumulated from ETW events.
#[derive(Debug, Clone, Default)]
pub struct NetIoCounters {
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

struct EtwState {
    counters: HashMap<u32, NetIoCounters>,
}

static ETW_STATE: OnceLock<Mutex<EtwState>> = OnceLock::new();

fn get_state() -> &'static Mutex<EtwState> {
    ETW_STATE.get_or_init(|| {
        Mutex::new(EtwState {
            counters: HashMap::new(),
        })
    })
}

/// Get the accumulated network I/O counters for a process.
pub fn get_net_io_counters(pid: u32) -> NetIoCounters {
    let state = get_state();
    if let Ok(guard) = state.lock() {
        guard.counters.get(&pid).cloned().unwrap_or_default()
    } else {
        NetIoCounters::default()
    }
}

/// Start the background ETW trace session (no-op if already started).
pub fn start_etw_trace() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        eprintln!("[ETW] Starting kernel network trace thread...");
        std::thread::Builder::new()
            .name("etw-net-trace".into())
            .spawn(etw_trace_loop)
            .ok();
    });
}

fn etw_trace_loop() {
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::kernel_providers::TCP_IP_PROVIDER;
    use ferrisetw::provider::Provider;
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::{KernelTrace, RealTimeTraceTrait, TraceTrait};
    use ferrisetw::EventRecord;

    // Kernel TcpIp event type IDs (from MOF definition) - these are opcodes, not event IDs
    const EVENT_SEND_V4: u8 = 10;
    const EVENT_RECV_V4: u8 = 11;
    const EVENT_SEND_V6: u8 = 26;
    const EVENT_RECV_V6: u8 = 27;

    static EVENT_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn on_event(record: &EventRecord, schema_locator: &SchemaLocator) {
        let opcode = record.opcode();

        // For kernel MOF-based TCP/IP events, the event type is in the opcode field
        let is_send = opcode == EVENT_SEND_V4 || opcode == EVENT_SEND_V6;
        let is_recv = opcode == EVENT_RECV_V4 || opcode == EVENT_RECV_V6;

        if !is_send && !is_recv {
            return;
        }

        // Parse event fields - kernel MOF events have PID in the payload
        let (pid, size): (u32, u32) = match schema_locator.event_schema(record) {
            Ok(schema) => {
                let parser = Parser::create(record, &schema);
                let size: u32 = match parser.try_parse("size") {
                    Ok(s) => s,
                    Err(_) => return,
                };
                // Kernel MOF TcpIp events: try "PID" field
                let pid: u32 = parser.try_parse("PID").unwrap_or(0);
                (pid, size)
            }
            Err(_) => return,
        };

        if pid == 0 {
            return;
        }

        let count = EVENT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count < 20 || count % 1000 == 0 {
            eprintln!("[ETW] NET event #{count}: pid={pid} opcode={opcode} size={size}");
        }

        let state = get_state();
        if let Ok(mut guard) = state.lock() {
            let counters = guard.counters.entry(pid).or_default();
            if is_send {
                counters.bytes_sent += size as u64;
            } else {
                counters.bytes_received += size as u64;
            }
        }
    }

    eprintln!("[ETW] Building KernelTrace with TCP_IP_PROVIDER...");
    let provider = Provider::kernel(&TCP_IP_PROVIDER)
        .add_callback(on_event)
        .build();

    let builder = KernelTrace::new().enable(provider);

    eprintln!("[ETW] Starting trace session...");
    let (mut trace, _handle) = match builder.start() {
        Ok(t) => {
            eprintln!("[ETW] KernelTrace started successfully!");
            t
        }
        Err(e) => {
            eprintln!("[ETW] Failed to start KernelTrace: {:?}", e);
            eprintln!("[ETW] Hint: KernelTrace requires Administrator privileges.");
            return;
        }
    };

    eprintln!("[ETW] Processing events...");
    // Process events (blocks until trace is stopped)
    if let Err(e) = trace.process() {
        eprintln!("[ETW] Trace processing error: {:?}", e);
    }
}
