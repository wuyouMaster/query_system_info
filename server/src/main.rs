mod api;
mod auth;
mod cache;
mod config;
mod db;
mod state;
#[cfg(test)]
mod tests;

use axum::routing::{get, post};
use axum::{middleware, Router};
use clap::Parser;
use state::AppState;
use tokio::task;
use tower_http::cors::CorsLayer;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::auth::JwtConfig;
use crate::config::AppConfig;
use crate::db::DbPool;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long)]
    config: Option<String>,

    /// Server host
    #[arg(long)]
    host: Option<String>,

    /// Server port
    #[arg(short, long)]
    port: Option<u16>,

    /// Database type: sqlite or mysql
    #[arg(long)]
    db_type: Option<String>,

    /// SQLite database path
    #[arg(long)]
    sqlite_path: Option<String>,

    /// MySQL host
    #[arg(long)]
    mysql_host: Option<String>,

    /// MySQL port
    #[arg(long)]
    mysql_port: Option<u16>,

    /// MySQL username
    #[arg(long)]
    mysql_user: Option<String>,

    /// MySQL password
    #[arg(long)]
    mysql_password: Option<String>,

    /// MySQL database name
    #[arg(long)]
    mysql_database: Option<String>,

    /// JWT secret
    #[arg(long)]
    jwt_secret: Option<String>,

    /// JWT expiration in hours
    #[arg(long)]
    jwt_expiration: Option<u64>,

    /// Default admin username
    #[arg(long)]
    default_username: Option<String>,

    /// Default admin password
    #[arg(long)]
    default_password: Option<String>,
}

fn apply_args(config: &mut AppConfig, args: &Args) {
    if let Some(host) = &args.host {
        config.server.host = host.clone();
    }
    if let Some(port) = args.port {
        config.server.port = port;
    }
    if let Some(db_type) = &args.db_type {
        match db_type.as_str() {
            "sqlite" => {
                let path = args
                    .sqlite_path
                    .clone()
                    .unwrap_or_else(|| "query_server.db".to_string());
                config.database = config::DatabaseConfig::Sqlite { path };
            }
            "mysql" => {
                config.database = config::DatabaseConfig::Mysql {
                    host: args.mysql_host.clone().unwrap_or_else(|| "localhost".to_string()),
                    port: args.mysql_port.unwrap_or(3306),
                    username: args.mysql_user.clone().unwrap_or_else(|| "root".to_string()),
                    password: args.mysql_password.clone().unwrap_or_default(),
                    database: args.mysql_database.clone().unwrap_or_else(|| "query_server".to_string()),
                };
            }
            _ => {
                tracing::warn!("Unknown db type: {}, using default", db_type);
            }
        }
    }
    if let Some(secret) = &args.jwt_secret {
        config.jwt.secret = secret.clone();
    }
    if let Some(exp) = args.jwt_expiration {
        config.jwt.expiration_hours = exp;
    }
    if let Some(username) = &args.default_username {
        config.default_user.username = username.clone();
    }
    if let Some(password) = &args.default_password {
        config.default_user.password = password.clone();
    }
}

// JWT auth middleware
async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
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
            let jwt_config = JwtConfig::new(state.jwt_secret, state.jwt_expiration);
            match jwt_config.validate_token(token) {
                Ok(_claims) => next.run(req).await,
                Err(e) => {
                    axum::response::Response::builder()
                        .status(401)
                        .body(axum::body::Body::from(format!("Invalid token: {}", e)))
                        .unwrap()
                }
            }
        }
        _ => axum::response::Response::builder()
            .status(401)
            .body(axum::body::Body::from("Missing or invalid Authorization header"))
            .unwrap(),
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Parse command line arguments
    let args = Args::parse();

    // Load configuration
    let mut app_config = AppConfig::load(args.config.as_deref()).expect("Failed to load config");

    // Apply command line overrides
    apply_args(&mut app_config, &args);

    info!("Starting server with config: {:?}", app_config);

    // Connect to database
    let db_pool = DbPool::connect(&app_config)
        .await
        .expect("Failed to connect to database");

    // Initialize database tables
    db_pool
        .init_tables()
        .await
        .expect("Failed to initialize database tables");

    info!("Database initialized successfully");

    // Create default admin user if no users exist
    {
        let user_count = match &db_pool {
            DbPool::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
                    .fetch_one(pool)
                    .await
                    .unwrap_or(0)
            }
            DbPool::Mysql(pool) => {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
                    .fetch_one(pool)
                    .await
                    .unwrap_or(0)
            }
        };

        if user_count == 0 {
            let username = &app_config.default_user.username;
            let password = &app_config.default_user.password;
            match db_pool.create_user(username, password).await {
                Ok(user) => {
                    info!(
                        "Created default admin user: {} (id={})",
                        username, user.id
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to create default admin user: {}", e);
                }
            }
        }
    }

    // Create caches
    let snapshot_cache = cache::snapshot::SnapshotCache::new(app_config.cache.ring_capacity);
    let cpu_usage_cache = cache::cpu_usage::CpuUsageCache::new(app_config.cache.ring_capacity);
    let trace_cache = cache::trace::ProcessTraceCache::new(app_config.cache.ring_capacity);

    // Populate cpu_info (static, one-shot)
    if let Ok(Ok(cpu)) = task::spawn_blocking(query_system_info::cpu::get_cpu_info).await {
        snapshot_cache
            .cpu_info
            .write()
            .unwrap()
            .replace(api::snapshot::CpuInfoResponse {
                physical_cores: cpu.physical_cores,
                logical_cores: cpu.logical_cores,
                model_name: cpu.model_name,
                vendor: cpu.vendor,
                frequency_mhz: cpu.frequency_mhz,
            });
    }

    // Start background cache refresh tasks
    snapshot_cache.start_refresh(app_config.cache.snapshot_interval_ms);
    cpu_usage_cache.start_sampling(app_config.cache.cpu_interval_ms);
    info!(
        "Cache started: ring_capacity={}, snapshot_interval={}ms, cpu_interval={}ms",
        app_config.cache.ring_capacity,
        app_config.cache.snapshot_interval_ms,
        app_config.cache.cpu_interval_ms,
    );

    // Create app state
    let state = AppState::new(
        db_pool,
        app_config.jwt.secret.clone(),
        app_config.jwt.expiration_hours,
        snapshot_cache,
        cpu_usage_cache,
        trace_cache,
    );

    // Create router
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/api/auth/register", post(api::auth::register))
        .route("/api/auth/login", post(api::auth::login));

    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/api/memory", get(api::snapshot::memory))
        .route("/api/cpu/info", get(api::snapshot::cpu_info))
        .route("/api/disks", get(api::snapshot::disks))
        .route("/api/processes", get(api::snapshot::processes))
        .route(
            "/api/processes/:pid",
            get(api::snapshot::process_by_pid).delete(api::snapshot::kill_process),
        )
        .route("/api/sockets", get(api::snapshot::socket_summary))
        .route("/api/connections", get(api::snapshot::connections))
        .route("/api/fs/list", get(api::snapshot::list_dir))
        .route(
            "/api/processes/:pid/socket-stats",
            get(api::snapshot::process_socket_stats),
        )
        .route(
            "/api/processes/:pid/socket-queues",
            get(api::snapshot::process_socket_queues),
        )
        .route(
            "/api/processes/:pid/io",
            get(api::snapshot::process_io),
        )
        .route(
            "/api/processes/:pid/cpu-usage",
            get(api::snapshot::process_cpu_usage),
        )
        .route("/api/stream/cpu", get(api::stream::cpu_usage))
        .route(
            "/api/stream/process/:pid",
            get(api::stream::process_tracker),
        )
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr = format!("{}:{}", app_config.server.host, app_config.server.port);
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
