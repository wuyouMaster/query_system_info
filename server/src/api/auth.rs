use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::JwtConfig;
use crate::db::user::{LoginRequest, UserResponse};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Validate input
    if payload.username.len() < 3 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Username must be at least 3 characters".to_string(),
            }),
        ));
    }

    if payload.password.len() < 6 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Password must be at least 6 characters".to_string(),
            }),
        ));
    }

    // Check if user exists
    let existing = state
        .db
        .find_user_by_username(&payload.username)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    if existing.is_some() {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Username already exists".to_string(),
            }),
        ));
    }

    // Create user
    let user = state
        .db
        .create_user(&payload.username, &payload.password)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    // Generate token
    let jwt_config = JwtConfig::new(state.jwt_secret.clone(), state.jwt_expiration);
    let token = jwt_config
        .generate_token(user.id, &user.username)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse { token, user }),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Authenticate user
    let user = state
        .db
        .authenticate_user(&payload.username, &payload.password)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    let user = user.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid username or password".to_string(),
            }),
        )
    })?;

    // Generate token
    let jwt_config = JwtConfig::new(state.jwt_secret.clone(), state.jwt_expiration);
    let token = jwt_config
        .generate_token(user.id, &user.username)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    Ok(Json(AuthResponse { token, user }))
}
