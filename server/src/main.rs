mod api;
mod state;
#[cfg(test)]
mod tests;

use axum::routing::get;
use axum::Router;
use state::AppState;
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    let state = AppState::new();

    let app = Router::new()
        .route("/api/memory", get(api::snapshot::memory))
        .route("/api/cpu/info", get(api::snapshot::cpu_info))
        .route("/api/disks", get(api::snapshot::disks))
        .route("/api/processes", get(api::snapshot::processes))
        .route("/api/processes/:pid", get(api::snapshot::process_by_pid))
        .route("/api/sockets", get(api::snapshot::socket_summary))
        .route("/api/stream/cpu", get(api::stream::cpu_usage))
        .route(
            "/api/stream/process/:pid",
            get(api::stream::process_tracker),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:3030";
    println!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
