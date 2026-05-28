use sqlx::PgPool;
use crate::config::Config;

/// Estado compartido inyectado en todos los handlers de Axum.
/// Clone es barato — PgPool y Config son Arc internamente.
#[derive(Clone)]
pub struct AppState {
    pub db:  PgPool,
    pub cfg: Config,
}

impl AppState {
    pub fn new(db: PgPool, cfg: Config) -> Self {
        Self { db, cfg }
    }
}
