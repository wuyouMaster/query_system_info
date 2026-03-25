use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64,
    pub username: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: u64,
}

impl JwtConfig {
    pub fn new(secret: String, expiration_hours: u64) -> Self {
        Self {
            secret,
            expiration_hours,
        }
    }

    pub fn generate_token(&self, user_id: i64, username: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let expiration = now + Duration::hours(self.expiration_hours as i64);

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            exp: expiration.timestamp(),
            iat: now.timestamp(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )?;

        Ok(token_data.claims)
    }
}

pub struct AuthUser {
    pub user_id: i64,
    pub username: String,
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string())
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "Invalid Authorization format".to_string())
            })?;

        // Get JWT config from extensions (set by middleware)
        let jwt_config = parts
            .extensions
            .get::<JwtConfig>()
            .ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, "JWT config not found".to_string())
            })?;

        let claims = jwt_config.validate_token(token).map_err(|e| {
            (StatusCode::UNAUTHORIZED, format!("Invalid token: {}", e))
        })?;

        Ok(AuthUser {
            user_id: claims.sub,
            username: claims.username,
        })
    }
}
