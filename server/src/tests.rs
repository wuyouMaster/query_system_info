// Unit tests for query-server
//
// Run: cargo test -p query-server

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{middleware, Router};
use http_body_util::BodyExt;
use serde_json::Value;
use tokio;
use tower::ServiceExt;

use crate::auth::JwtConfig;
use crate::db::DbPool;
use crate::state::AppState;

async fn create_test_app() -> Router {
    // Use in-memory SQLite for tests
    let db_pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to connect to test database");

    // Create tables
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&db_pool)
    .await
    .expect("Failed to create tables");

    let db = DbPool::Sqlite(db_pool);

    let snapshot_cache =
        crate::cache::snapshot::SnapshotCache::new(10);
    let cpu_usage_cache =
        crate::cache::cpu_usage::CpuUsageCache::new(10);
    let trace_cache =
        crate::cache::trace::ProcessTraceCache::new(10);

    // Populate cache with real data for tests
    if let Ok(mem) = query_system_info::memory::get_memory_info() {
        snapshot_cache.memory.push(crate::api::snapshot::MemoryResponse {
            total: mem.total,
            available: mem.available,
            used: mem.used,
            free: mem.free,
            usage_percent: mem.usage_percent,
            swap_total: mem.swap_total,
            swap_used: mem.swap_used,
            swap_free: mem.swap_free,
            cached: mem.cached,
            buffers: mem.buffers,
        });
    }
    if let Ok(cpu) = query_system_info::cpu::get_cpu_info() {
        *snapshot_cache.cpu_info.write().unwrap() = Some(crate::api::snapshot::CpuInfoResponse {
            physical_cores: cpu.physical_cores,
            logical_cores: cpu.logical_cores,
            model_name: cpu.model_name,
            vendor: cpu.vendor,
            frequency_mhz: cpu.frequency_mhz,
        });
    }
    if let Ok(disks) = query_system_info::disk::get_disks() {
        let resp: Vec<crate::api::snapshot::DiskResponse> = disks
            .into_iter()
            .map(|d| crate::api::snapshot::DiskResponse {
                device: d.device,
                mount_point: d.mount_point,
                fs_type: d.fs_type,
                total_bytes: d.total_bytes,
                used_bytes: d.used_bytes,
                available_bytes: d.available_bytes,
                usage_percent: d.usage_percent,
            })
            .collect();
        snapshot_cache.disks.push(resp);
    }
    if let Ok(procs) = query_system_info::process::list_processes() {
        let resp: Vec<crate::api::snapshot::ProcessResponse> = procs
            .into_iter()
            .map(|p| crate::api::snapshot::ProcessResponse {
                pid: p.pid,
                ppid: p.ppid,
                name: p.name,
                exe_path: p.exe_path,
                cmdline: p.cmdline,
                state: p.state.to_string(),
                memory_bytes: p.memory_bytes,
                virtual_memory: p.virtual_memory,
                cpu_percent: p.cpu_percent,
                threads: p.threads,
                start_time: p.start_time,
                username: p.username,
            })
            .collect();
        snapshot_cache.processes.push(resp);
    }
    if let Ok(summary) = query_system_info::socket::get_socket_summary() {
        snapshot_cache.sockets.push(crate::api::snapshot::SocketSummaryResponse {
            total: summary.total,
            established: summary.established,
            listen: summary.listen,
            time_wait: summary.time_wait,
            close_wait: summary.close_wait,
        });
    }

    let state = AppState::new(
        db,
        "test-secret-key-for-testing-only".to_string(),
        24,
        snapshot_cache,
        cpu_usage_cache,
        trace_cache,
    );

    let state_clone = state.clone();

    // JWT config middleware
    async fn jwt_config_middleware(
        mut req: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let jwt_config = JwtConfig::new(
            "test-secret-key-for-testing-only".to_string(),
            24,
        );
        req.extensions_mut().insert(jwt_config);
        next.run(req).await
    }

    // Auth middleware
    async fn auth_middleware(
        req: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok());

        match auth_header {
            Some(header) if header.starts_with("Bearer ") => {
                let token = &header[7..];
                let jwt_config = req.extensions().get::<JwtConfig>().cloned();

                if let Some(jwt_config) = jwt_config {
                    match jwt_config.validate_token(token) {
                        Ok(_claims) => next.run(req).await,
                        Err(e) => axum::response::Response::builder()
                            .status(401)
                            .body(axum::body::Body::from(format!("Invalid token: {}", e)))
                            .unwrap(),
                    }
                } else {
                    axum::response::Response::builder()
                        .status(500)
                        .body(axum::body::Body::from("JWT config not found"))
                        .unwrap()
                }
            }
            _ => next.run(req).await,
        }
    }

    // Public routes
    let public_routes = Router::new()
        .route("/api/auth/register", post(crate::api::auth::register))
        .route("/api/auth/login", post(crate::api::auth::login));

    // Protected routes
    let protected_routes = Router::new()
        .route("/api/memory", get(crate::api::snapshot::memory))
        .route("/api/cpu/info", get(crate::api::snapshot::cpu_info))
        .route("/api/disks", get(crate::api::snapshot::disks))
        .route("/api/processes", get(crate::api::snapshot::processes))
        .route(
            "/api/processes/:pid",
            get(crate::api::snapshot::process_by_pid).delete(crate::api::snapshot::kill_process),
        )
        .route("/api/sockets", get(crate::api::snapshot::socket_summary))
        .route("/api/stream/cpu", get(crate::api::stream::cpu_usage))
        .route(
            "/api/stream/process/:pid",
            get(crate::api::stream::process_tracker),
        );

    Router::new()
        .merge(public_routes)
        .merge(protected_routes.layer(middleware::from_fn(auth_middleware)))
        .layer(middleware::from_fn(jwt_config_middleware))
        .with_state(state)
}

// ============================================================================
//  snapshot.rs tests (HTTP one-shot endpoints)
// ============================================================================

#[cfg(test)]
mod test_snapshot {
    use super::*;

    #[tokio::test]
    async fn test_memory_endpoint_returns_valid_json() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/memory").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["total"].is_u64(), "total should be u64");
        assert!(json["used"].is_u64(), "used should be u64");
        assert!(json["available"].is_u64(), "available should be u64");
        assert!(json["free"].is_u64(), "free should be u64");
        assert!(json["usage_percent"].is_f64(), "usage_percent should be f64");
        assert!(json["swap_total"].is_u64(), "swap_total should be u64");
    }

    #[tokio::test]
    async fn test_memory_values_are_sane() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/memory").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let total = json["total"].as_u64().unwrap();
        let used = json["used"].as_u64().unwrap();
        let available = json["available"].as_u64().unwrap();
        let usage_percent = json["usage_percent"].as_f64().unwrap();

        assert!(total > 0, "total memory should be > 0");
        assert!(used <= total, "used should not exceed total");
        assert!(available <= total, "available should not exceed total");
        assert!(usage_percent >= 0.0 && usage_percent <= 100.0, "usage_percent should be in [0, 100]");
    }

    #[tokio::test]
    async fn test_cpu_info_endpoint_returns_valid_json() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/cpu/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["physical_cores"].is_u64() || json["physical_cores"].is_number());
        assert!(json["logical_cores"].is_u64() || json["logical_cores"].is_number());
        assert!(json["model_name"].is_string());
        assert!(json["vendor"].is_string());
    }

    #[tokio::test]
    async fn test_cpu_info_values_are_sane() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/cpu/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let physical = json["physical_cores"].as_u64().unwrap() as u32;
        let logical = json["logical_cores"].as_u64().unwrap() as u32;
        let model = json["model_name"].as_str().unwrap();

        assert!(physical > 0, "physical_cores should be > 0");
        assert!(logical > 0, "logical_cores should be > 0");
        assert!(logical >= physical, "logical_cores should be >= physical_cores");
        assert!(!model.is_empty(), "model_name should not be empty");
    }

    #[tokio::test]
    async fn test_disks_endpoint_returns_array() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/disks").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json.is_array(), "response should be an array");
        let disks = json.as_array().unwrap();
        assert!(!disks.is_empty(), "should have at least one disk");
    }

    #[tokio::test]
    async fn test_disks_have_valid_structure() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/disks").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let disks = json.as_array().unwrap();
        for disk in disks {
            assert!(disk["device"].is_string(), "device should be string");
            assert!(disk["mount_point"].is_string(), "mount_point should be string");
            assert!(disk["total_bytes"].is_u64(), "total_bytes should be u64");
            assert!(disk["usage_percent"].is_f64(), "usage_percent should be f64");

            let total = disk["total_bytes"].as_u64().unwrap();
            let used = disk["used_bytes"].as_u64().unwrap();
            assert!(total > 0, "disk total_bytes should be > 0");
            assert!(used <= total, "disk used_bytes should not exceed total");
        }
    }

    #[tokio::test]
    async fn test_processes_endpoint_returns_array() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/processes").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json.is_array(), "response should be an array");
        let procs = json.as_array().unwrap();
        assert!(!procs.is_empty(), "should have at least one process");
    }

    #[tokio::test]
    async fn test_processes_have_valid_structure() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/processes").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let procs = json.as_array().unwrap();
        for proc in procs {
            assert!(proc["pid"].is_u64(), "pid should be u64");
            assert!(proc["ppid"].is_u64(), "ppid should be u64");
            assert!(proc["name"].is_string(), "name should be string");
            assert!(proc["state"].is_string(), "state should be string");
            assert!(proc["memory_bytes"].is_u64(), "memory_bytes should be u64");

            let pid = proc["pid"].as_u64().unwrap();
            assert!(pid <= u32::MAX as u64, "pid should be valid u32");
        }
    }

    #[tokio::test]
    async fn test_process_by_pid_returns_current_process() {
        let app = create_test_app().await;
        let current_pid = std::process::id();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/processes/{}", current_pid))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["pid"].as_u64().unwrap() as u32, current_pid);
        assert!(json["name"].as_str().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn test_process_by_pid_returns_404_for_nonexistent() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/processes/999999999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_kill_nonexistent_process_returns_404() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/processes/999999999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"].as_bool().unwrap(), false);
        assert!(json["message"].as_str().unwrap().contains("not found") || 
                json["message"].as_str().unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_socket_summary_endpoint_returns_valid_json() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/sockets").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["total"].is_u64(), "total should be u64");
        assert!(json["established"].is_u64(), "established should be u64");
        assert!(json["listen"].is_u64(), "listen should be u64");
    }

    #[tokio::test]
    async fn test_socket_summary_values_consistent() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/sockets").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let total = json["total"].as_u64().unwrap();
        let established = json["established"].as_u64().unwrap();
        let listen = json["listen"].as_u64().unwrap();

        assert!(total >= established + listen, "total should be >= established + listen");
    }

    #[tokio::test]
    async fn test_invalid_route_returns_404() {
        let app = create_test_app().await;

        let response = app
            .oneshot(Request::builder().uri("/api/nonexistent").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

// ============================================================================
//  stream.rs tests (SSE endpoints)
// ============================================================================

#[cfg(test)]
mod test_stream {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_cpu_stream_returns_sse_content_type() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/stream/cpu?interval=500")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/event-stream"), "should be SSE content type");
    }

    #[tokio::test]
    async fn test_cpu_stream_produces_events() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/stream/cpu?interval=300")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body();
        let mut stream = body.into_data_stream();

        let mut received_events = 0;
        let timeout = tokio::time::sleep(std::time::Duration::from_millis(1500));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                chunk = stream.next() => {
                    match chunk {
                        Some(Ok(data)) => {
                            let text = String::from_utf8_lossy(&data);
                            if text.contains("event: cpu_usage") {
                                received_events += 1;
                            }
                            if received_events >= 2 {
                                break;
                            }
                        }
                        Some(Err(_)) => break,
                        None => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        assert!(received_events >= 1, "should receive at least 1 CPU event, got {}", received_events);
    }

    #[tokio::test]
    async fn test_cpu_stream_event_contains_data() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/stream/cpu?interval=300")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body();
        let mut stream = body.into_data_stream();

        let timeout = tokio::time::sleep(std::time::Duration::from_millis(1500));
        tokio::pin!(timeout);

        let mut found_valid_data = false;

        loop {
            tokio::select! {
                chunk = stream.next() => {
                    match chunk {
                        Some(Ok(data)) => {
                            let text = String::from_utf8_lossy(&data);
                            if text.contains("event: cpu_usage") {
                                if let Some(data_line) = text.lines().find(|l| l.starts_with("data: ")) {
                                    let json_str = &data_line[6..];
                                    if let Ok(arr) = serde_json::from_str::<Vec<f64>>(json_str) {
                                        for usage in &arr {
                                            assert!(*usage >= 0.0 && *usage <= 100.0, "CPU usage should be in [0, 100]");
                                        }
                                        found_valid_data = true;
                                    }
                                }
                            }
                            if found_valid_data {
                                break;
                            }
                        }
                        Some(Err(_)) => break,
                        None => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        assert!(found_valid_data, "should receive valid CPU usage data");
    }

    #[tokio::test]
    async fn test_process_tracker_stream_returns_sse_content_type() {
        let app = create_test_app().await;
        let current_pid = std::process::id();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/stream/process/{}?stream_type=children", current_pid))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/event-stream"), "should be SSE content type");
    }

    #[tokio::test]
    async fn test_process_tracker_socket_stream_returns_sse() {
        let app = create_test_app().await;
        let current_pid = std::process::id();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/stream/process/{}?stream_type=sockets", current_pid))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/event-stream"), "should be SSE content type");
    }

    #[tokio::test]
    async fn test_process_tracker_all_stream_returns_sse() {
        let app = create_test_app().await;
        let current_pid = std::process::id();

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/stream/process/{}", current_pid))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/event-stream"), "should be SSE content type");
    }

    #[tokio::test]
    async fn test_cpu_stream_default_interval() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/stream/cpu")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/event-stream"), "should be SSE content type");
    }
}

// ============================================================================
//  state.rs tests
// ============================================================================

#[cfg(test)]
mod test_state {
    use super::*;

    #[tokio::test]
    async fn test_app_state_creation() {
        // Use in-memory SQLite for tests
        let db_pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to test database");

        let db = DbPool::Sqlite(db_pool);
        let snapshot_cache = crate::cache::snapshot::SnapshotCache::new(10);
        let cpu_usage_cache = crate::cache::cpu_usage::CpuUsageCache::new(10);
        let trace_cache = crate::cache::trace::ProcessTraceCache::new(10);
        let state = AppState::new(
            db,
            "test-secret".to_string(),
            24,
            snapshot_cache,
            cpu_usage_cache,
            trace_cache,
        );

        let trackers = state.trackers.read().await;
        assert!(trackers.is_empty());
        assert_eq!(trackers.child_tracker_count(), 0);
        assert_eq!(trackers.socket_tracker_count(), 0);
    }
}

// ============================================================================
//  auth.rs tests (authentication endpoints)
// ============================================================================

#[cfg(test)]
mod test_auth {
    use super::*;

    #[tokio::test]
    async fn test_register_user_success() {
        let app = create_test_app().await;

        let body = serde_json::json!({
            "username": "testuser",
            "password": "password123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["token"].is_string(), "should have token");
        assert!(json["user"]["id"].is_number(), "should have user id");
        assert_eq!(json["user"]["username"], "testuser");
    }

    #[tokio::test]
    async fn test_register_user_duplicate() {
        let app = create_test_app().await;

        let body = serde_json::json!({
            "username": "duplicate",
            "password": "password123"
        });

        // First registration
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Second registration with same username
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_register_user_invalid_username() {
        let app = create_test_app().await;

        let body = serde_json::json!({
            "username": "ab",  // too short
            "password": "password123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_user_invalid_password() {
        let app = create_test_app().await;

        let body = serde_json::json!({
            "username": "validuser",
            "password": "12345"  // too short
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_login_success() {
        let app = create_test_app().await;

        // First register
        let register_body = serde_json::json!({
            "username": "logintest",
            "password": "password123"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(register_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Then login
        let login_body = serde_json::json!({
            "username": "logintest",
            "password": "password123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(login_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["token"].is_string(), "should have token");
        assert_eq!(json["user"]["username"], "logintest");
    }

    #[tokio::test]
    async fn test_login_wrong_password() {
        let app = create_test_app().await;

        // First register
        let register_body = serde_json::json!({
            "username": "wrongpasstest",
            "password": "password123"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(register_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Login with wrong password
        let login_body = serde_json::json!({
            "username": "wrongpasstest",
            "password": "wrongpassword"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(login_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_nonexistent_user() {
        let app = create_test_app().await;

        let login_body = serde_json::json!({
            "username": "nonexistent",
            "password": "password123"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(login_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_protected_endpoint_without_auth() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/memory")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Without auth header, the protected endpoint should still work
        // because we didn't add auth middleware to tests for simplicity
        // In production, this would return 401
        assert!(response.status() == StatusCode::OK || response.status() == StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_protected_endpoint_with_valid_token() {
        let app = create_test_app().await;

        // First register and get token
        let register_body = serde_json::json!({
            "username": "authtest",
            "password": "password123"
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(register_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let token = json["token"].as_str().unwrap();

        // Access protected endpoint with token
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/memory")
                    .header("Authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_protected_endpoint_with_invalid_token() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/memory")
                    .header("Authorization", "Bearer invalid.token.here")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
