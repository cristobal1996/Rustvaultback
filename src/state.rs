use sqlx::PgPool;
use crate::config::Config;
use crate::rate_limit::RateLimiter;

/// Estado compartido inyectado en todos los handlers de Axum.
/// Clone es barato — PgPool y Config son Arc internamente.
/// RateLimiter también es Clone barato (Arc<Mutex<HashMap<...>>>).
#[derive(Clone)]
pub struct AppState {
    pub db:           PgPool,
    pub cfg:          Config,
    pub rate_limiter: RateLimiter,
}

impl AppState {
    pub fn new(db: PgPool, cfg: Config) -> Self {
        Self {
            db,
            cfg,
            rate_limiter: RateLimiter::new(),
        }
    }
}
