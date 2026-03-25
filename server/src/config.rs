use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    #[serde(default)]
    pub default_user: DefaultUserConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DatabaseConfig {
    Sqlite {
        path: String,
    },
    Mysql {
        host: String,
        port: u16,
        username: String,
        password: String,
        database: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultUserConfig {
    pub username: String,
    pub password: String,
}

impl Default for DefaultUserConfig {
    fn default() -> Self {
        Self {
            username: "admin".to_string(),
            password: "admin123".to_string(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            jwt: JwtConfig::default(),
            default_user: DefaultUserConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 3030,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self::Sqlite {
            path: "query_server.db".to_string(),
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key-change-this-in-production".to_string(),
            expiration_hours: 24,
        }
    }
}

impl AppConfig {
    pub fn load(config_path: Option<&str>) -> Result<Self, config::ConfigError> {
        let mut builder = config::Config::builder();

        // Load from config file if provided
        if let Some(path) = config_path {
            builder = builder.add_source(config::File::with_name(path).required(false));
        }

        // Try to load from default locations
        builder = builder
            .add_source(config::File::with_name("config.json").required(false))
            .add_source(config::File::with_name("server/config.json").required(false));

        // Environment variables override
        builder = builder.add_source(
            config::Environment::with_prefix("QUERY_SERVER")
                .separator("__")
                .try_parsing(true),
        );

        let config = builder.build()?;
        config.try_deserialize()
    }

    pub fn database_url(&self) -> String {
        match &self.database {
            DatabaseConfig::Sqlite { path } => format!("sqlite://{}", path),
            DatabaseConfig::Mysql {
                host,
                port,
                username,
                password,
                database,
            } => format!(
                "mysql://{}:{}@{}:{}/{}",
                username, password, host, port, database
            ),
        }
    }

    pub fn is_sqlite(&self) -> bool {
        matches!(self.database, DatabaseConfig::Sqlite { .. })
    }
}
