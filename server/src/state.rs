use query_system_info::process::{ProcessSocketTracker, ProcessTracker};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::db::DbPool;

#[derive(Clone)]
pub struct AppState {
    pub trackers: Arc<RwLock<TrackerManager>>,
    pub db: DbPool,
    pub jwt_secret: String,
    pub jwt_expiration: u64,
}

pub struct TrackerManager {
    child_trackers: HashMap<u32, ProcessTracker>,
    socket_trackers: HashMap<u32, ProcessSocketTracker>,
    child_tx: HashMap<u32, broadcast::Sender<ChildEvent>>,
    socket_tx: HashMap<u32, broadcast::Sender<SocketEvent>>,
}

#[derive(Clone, serde::Serialize)]
pub struct ChildEvent {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: Vec<String>,
    pub exe_path: String,
    pub start_time: u64,
    pub event_type: String,
}

#[derive(Clone, serde::Serialize)]
pub struct SocketEvent {
    pub pid: u32,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: Option<String>,
    pub state: String,
    pub inode: u64,
    pub event_type: String,
}

impl AppState {
    pub fn new(db: DbPool, jwt_secret: String, jwt_expiration: u64) -> Self {
        Self {
            trackers: Arc::new(RwLock::new(TrackerManager::new())),
            db,
            jwt_secret,
            jwt_expiration,
        }
    }

    pub async fn get_or_create_child_channel(
        &self,
        pid: u32,
    ) -> broadcast::Receiver<ChildEvent> {
        let mut trackers = self.trackers.write().await;

        if let Some(tx) = trackers.child_tx.get(&pid) {
            return tx.subscribe();
        }

        let (tx, rx) = broadcast::channel(64);
        trackers.child_tx.insert(pid, tx.clone());

        let tx_clone = tx.clone();
        let tracker = query_system_info::process::start_tracking_children(pid, move |event| {
            let child_event = ChildEvent {
                pid: event.pid,
                ppid: event.ppid,
                name: event.name,
                cmdline: event.cmdline,
                exe_path: event.exe_path,
                start_time: event.start_time,
                event_type: "child_process".to_string(),
            };
            let _ = tx_clone.send(child_event);
        })
        .expect("Failed to start child tracker");

        trackers.child_trackers.insert(pid, tracker);

        rx
    }

    pub async fn get_or_create_socket_channel(
        &self,
        pid: u32,
    ) -> broadcast::Receiver<SocketEvent> {
        let mut trackers = self.trackers.write().await;

        if let Some(tx) = trackers.socket_tx.get(&pid) {
            return tx.subscribe();
        }

        let (tx, rx) = broadcast::channel(256);
        trackers.socket_tx.insert(pid, tx.clone());

        let tx_clone = tx.clone();
        let tracker = query_system_info::process::start_tracking_sockets(pid, move |event| {
            let socket_event = SocketEvent {
                pid: event.pid,
                protocol: event.protocol.to_string(),
                local_addr: event.local_addr.to_string(),
                remote_addr: event.remote_addr.map(|a| a.to_string()),
                state: event.state.to_string(),
                inode: event.inode,
                event_type: "socket_connection".to_string(),
            };
            let _ = tx_clone.send(socket_event);
        })
        .expect("Failed to start socket tracker");

        trackers.socket_trackers.insert(pid, tracker);

        rx
    }
}

impl TrackerManager {
    fn new() -> Self {
        Self {
            child_trackers: HashMap::new(),
            socket_trackers: HashMap::new(),
            child_tx: HashMap::new(),
            socket_tx: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.child_trackers.is_empty() && self.socket_trackers.is_empty()
    }

    pub fn child_tracker_count(&self) -> usize {
        self.child_trackers.len()
    }

    pub fn socket_tracker_count(&self) -> usize {
        self.socket_trackers.len()
    }
}
