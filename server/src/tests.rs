// Unit tests for query-server
//
// Run: cargo test -p query-server

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use crate::state::AppState;

fn create_test_app() -> Router {
    let state = AppState::new();

    Router::new()
        .route("/api/memory", get(crate::api::snapshot::memory))
        .route("/api/cpu/info", get(crate::api::snapshot::cpu_info))
        .route("/api/disks", get(crate::api::snapshot::disks))
        .route("/api/processes", get(crate::api::snapshot::processes))
        .route(
            "/api/processes/:pid",
            get(crate::api::snapshot::process_by_pid),
        )
        .route("/api/sockets", get(crate::api::snapshot::socket_summary))
        .route("/api/stream/cpu", get(crate::api::stream::cpu_usage))
        .route(
            "/api/stream/process/:pid",
            get(crate::api::stream::process_tracker),
        )
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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();
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
        let app = create_test_app();

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
    async fn test_socket_summary_endpoint_returns_valid_json() {
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();

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
        let app = create_test_app();
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
        let app = create_test_app();
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
        let app = create_test_app();
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
        let app = create_test_app();

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
        let state = AppState::new();
        let trackers = state.trackers.read().await;
        assert!(trackers.is_empty());
        assert_eq!(trackers.child_tracker_count(), 0);
        assert_eq!(trackers.socket_tracker_count(), 0);
    }
}
