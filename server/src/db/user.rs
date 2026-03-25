use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use super::DbPool;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub username: String,
    pub created_at: Option<NaiveDateTime>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            created_at: user.created_at,
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

impl DbPool {
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserResponse, sqlx::Error> {
        let password_hash =
            hash_password(password).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

        match self {
            DbPool::Sqlite(pool) => {
                let user = sqlx::query_as::<_, User>(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING *",
                )
                .bind(username)
                .bind(&password_hash)
                .fetch_one(pool)
                .await?;

                Ok(user.into())
            }
            DbPool::Mysql(pool) => {
                sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
                    .bind(username)
                    .bind(&password_hash)
                    .execute(pool)
                    .await?;

                let user: User = sqlx::query_as(
                    "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
                )
                .bind(username)
                .fetch_one(pool)
                .await?;

                Ok(user.into())
            }
        }
    }

    pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
                let user = sqlx::query_as::<_, User>(
                    "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
                )
                .bind(username)
                .fetch_optional(pool)
                .await?;

                Ok(user)
            }
            DbPool::Mysql(pool) => {
                let user = sqlx::query_as::<_, User>(
                    "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
                )
                .bind(username)
                .fetch_optional(pool)
                .await?;

                Ok(user)
            }
        }
    }

    pub async fn find_user_by_id(&self, id: i64) -> Result<Option<User>, sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
                let user = sqlx::query_as::<_, User>(
                    "SELECT id, username, password_hash, created_at FROM users WHERE id = ?",
                )
                .bind(id)
                .fetch_optional(pool)
                .await?;

                Ok(user)
            }
            DbPool::Mysql(pool) => {
                let user = sqlx::query_as::<_, User>(
                    "SELECT id, username, password_hash, created_at FROM users WHERE id = ?",
                )
                .bind(id)
                .fetch_optional(pool)
                .await?;

                Ok(user)
            }
        }
    }

    pub async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<UserResponse>, sqlx::Error> {
        let user = self.find_user_by_username(username).await?;

        match user {
            Some(user) => {
                let valid = verify_password(password, &user.password_hash)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;

                if valid {
                    Ok(Some(user.into()))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}
