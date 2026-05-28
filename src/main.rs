mod cleanup;
mod config;
mod crypto;
mod crypto_asymmetric;
mod db;
mod errors;
mod middleware;
mod models;
mod pagination;
mod routes;
mod state;
mod totp;
mod validation;

use axum::Router;
use std::net::SocketAddr;
use tokio::signal;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "rustvault=debug,tower_http=info,sqlx=warn".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg  = config::Config::from_env()?;
    let pool = db::create_pool(&cfg.database_url).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("Migraciones aplicadas");

    // Limpieza automática en background (opcional, CLEANUP_ENABLED=true)
    let cleanup_cfg = cleanup::CleanupConfig::from_env();
    if cleanup_cfg.enabled {
        cleanup::start_background_task(pool.clone(), cleanup_cfg);
    }

    let state = state::AppState::new(pool, cfg.clone());

    let app = Router::new()
        .nest("/api/auth",      routes::auth::router())
        .nest("/api/account",   routes::account::router())
        .nest("/api/passwords", routes::passwords::router())
        .nest("/api/sharing",   routes::sharing::router())
        .nest("/api/devices",   routes::devices::router())
        .nest("/api/generator", routes::generator::router())
        .nest("/api/totp",      routes::totp::router())
        .nest("/api/users",     routes::users::router())
        .route("/health", axum::routing::get(health_check))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    tracing::info!("Servidor en http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn health_check(
    axum::extract::State(state): axum::extract::State<state::AppState>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use axum::http::StatusCode;

    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();

    if db_ok {
        (StatusCode::OK, axum::Json(serde_json::json!({
            "status":  "ok",
            "db":      "ok",
            "version": env!("CARGO_PKG_VERSION"),
        }))).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(serde_json::json!({
            "status": "error",
            "db":     "unreachable",
        }))).into_response()
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Ctrl+C handler")
    };
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler")
            .recv()
            .await;
    };
    tokio::select! {
        _ = ctrl_c    => {},
        _ = terminate => {},
    }
    tracing::info!("Apagando servidor...");
}
