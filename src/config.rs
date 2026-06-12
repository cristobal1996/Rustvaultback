use std::env;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret:   String,
    pub port:         u16,
    pub env:          String,
}

#[allow(dead_code)]
impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            database_url: require("DATABASE_URL")?,
            jwt_secret:   require("JWT_SECRET")?,
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse()?,
            env: env::var("ENV").unwrap_or_else(|_| "development".into()),
        })
    }

    pub fn is_production(&self) -> bool {
        self.env == "production"
    }
}

fn require(key: &str) -> anyhow::Result<String> {
    env::var(key).map_err(|_| anyhow::anyhow!("{} no definida en .env", key))
}
