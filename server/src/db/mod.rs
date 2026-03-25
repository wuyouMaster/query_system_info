use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{MySql, MySqlPool};
use sqlx::{Pool, Sqlite};
use std::str::FromStr;

use crate::config::{AppConfig, DatabaseConfig};

pub mod user;

pub type SqliteDbPool = Pool<Sqlite>;
pub type MysqlDbPool = Pool<MySql>;

#[derive(Clone)]
pub enum DbPool {
    Sqlite(SqliteDbPool),
    Mysql(MysqlDbPool),
}

impl DbPool {
    pub async fn connect(config: &AppConfig) -> Result<Self, sqlx::Error> {
        match &config.database {
            DatabaseConfig::Sqlite { path } => {
                let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path))?
                    .create_if_missing(true);

                let pool = SqlitePoolOptions::new()
                    .max_connections(5)
                    .connect_with(options)
                    .await?;

                Ok(DbPool::Sqlite(pool))
            }
            DatabaseConfig::Mysql {
                host,
                port,
                username,
                password,
                database,
            } => {
                let url = format!(
                    "mysql://{}:{}@{}:{}/{}",
                    username, password, host, port, database
                );
                let pool = MySqlPool::connect(&url).await?;
                Ok(DbPool::Mysql(pool))
            }
        }
    }

    pub async fn init_tables(&self) -> Result<(), sqlx::Error> {
        match self {
            DbPool::Sqlite(pool) => {
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
                .execute(pool)
                .await?;
            }
            DbPool::Mysql(pool) => {
                sqlx::query(
                    r#"
                    CREATE TABLE IF NOT EXISTS users (
                        id BIGINT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(255) NOT NULL UNIQUE,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    "#,
                )
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }
}
