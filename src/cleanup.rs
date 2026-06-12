// src/cleanup.rs — limpieza periódica sin referencias a vaults/entries

use sqlx::PgPool;
use std::time::Duration;
use tokio::time;
use tracing::{error, info};

#[derive(Clone, Debug)]
pub struct CleanupConfig {
    pub enabled:                        bool,
    pub interval_hours:                 u64,
    pub sessions_retention_days:        i32,
    pub deleted_passwords_retention_days: i32,
    pub max_versions_per_password:      i64,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            enabled:                          false,
            interval_hours:                   24,
            sessions_retention_days:          30,
            deleted_passwords_retention_days: 90,
            max_versions_per_password:        50,
        }
    }
}

impl CleanupConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: std::env::var("CLEANUP_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            interval_hours: std::env::var("CLEANUP_INTERVAL_HOURS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(24),
            sessions_retention_days: std::env::var("CLEANUP_SESSIONS_DAYS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(30),
            deleted_passwords_retention_days: std::env::var("CLEANUP_DELETED_DAYS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(90),
            max_versions_per_password: std::env::var("CLEANUP_MAX_VERSIONS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(50),
        }
    }
}

#[derive(Debug, Default, serde::Serialize)]
pub struct CleanupResult {
    pub sessions_deleted:          u64,
    pub shared_expired_deleted:    u64,
    pub deleted_passwords_purged:  u64,
    pub old_versions_purged:       u64,
    pub duration_ms:               u128,
}

pub async fn run(db: &PgPool, cfg: &CleanupConfig) -> CleanupResult {
    let start = std::time::Instant::now();
    let mut result = CleanupResult::default();

    info!("Iniciando limpieza periódica...");

    // 1. Sesiones expiradas o revocadas
    match clean_sessions(db, cfg.sessions_retention_days).await {
        Ok(n) => { result.sessions_deleted = n; info!("  Sesiones eliminadas: {}", n); }
        Err(e) => error!("  Error limpiando sesiones: {}", e),
    }

    // 2. Contraseñas compartidas expiradas
    match clean_expired_shares(db).await {
        Ok(n) => { result.shared_expired_deleted = n; info!("  Compartidos expirados eliminados: {}", n); }
        Err(e) => error!("  Error limpiando compartidos: {}", e),
    }

    // 3. Contraseñas con soft delete antiguos
    match clean_deleted_passwords(db, cfg.deleted_passwords_retention_days).await {
        Ok(n) => { result.deleted_passwords_purged = n; info!("  Contraseñas borradas purgadas: {}", n); }
        Err(e) => error!("  Error purgando contraseñas: {}", e),
    }

    // 4. Versiones antiguas de contraseñas
    match clean_old_versions(db, cfg.max_versions_per_password).await {
        Ok(n) => { result.old_versions_purged = n; info!("  Versiones antiguas eliminadas: {}", n); }
        Err(e) => error!("  Error limpiando versiones: {}", e),
    }

    result.duration_ms = start.elapsed().as_millis();
    info!("Limpieza completada en {}ms", result.duration_ms);
    result
}

async fn clean_sessions(db: &PgPool, retention_days: i32) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM sessions WHERE
            (expires_at  < NOW() - CAST($1 || ' days' AS INTERVAL)) OR
            (revoked_at IS NOT NULL AND revoked_at < NOW() - CAST($1 || ' days' AS INTERVAL))"
    )
    .bind(retention_days)
    .execute(db).await?.rows_affected())
}

async fn clean_expired_shares(db: &PgPool) -> sqlx::Result<u64> {
    // 1. Borrado FÍSICO de temporales/one_shot expiradas (NO se conservan)
    let deleted_physical = sqlx::query(
        "DELETE FROM shared_passwords
         WHERE share_mode IN ('temporary', 'one_shot')
           AND expires_at IS NOT NULL
           AND expires_at < NOW()
           AND status = 'pending'"
    ).execute(db).await?.rows_affected();

    // 2. Para las permanentes con expires_at legacy (datos antiguos),
    //    marcar como expiradas (no borrar — son comparticiones que el
    //    usuario podría querer consultar en su historial).
    sqlx::query(
        "UPDATE shared_passwords
         SET status='expired'
         WHERE share_mode = 'permanent'
           AND status='pending'
           AND expires_at IS NOT NULL
           AND expires_at < NOW()"
    ).execute(db).await?;

    // 3. Borrar las permanentes procesadas (accepted/rejected/expired) con
    //    más de 30 días. Mantiene la BD limpia sin perder info reciente.
    let deleted_old = sqlx::query(
        "DELETE FROM shared_passwords
         WHERE share_mode = 'permanent'
           AND status IN ('expired','rejected','accepted')
           AND created_at < NOW() - INTERVAL '30 days'"
    ).execute(db).await?.rows_affected();

    Ok(deleted_physical + deleted_old)
}

async fn clean_deleted_passwords(db: &PgPool, retention_days: i32) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM passwords WHERE is_deleted = true
         AND deleted_at < NOW() - CAST($1 || ' days' AS INTERVAL)"
    )
    .bind(retention_days)
    .execute(db).await?.rows_affected())
}

async fn clean_old_versions(db: &PgPool, max_versions: i64) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM password_versions WHERE id IN (
            SELECT id FROM (
                SELECT id, ROW_NUMBER() OVER (
                    PARTITION BY password_id ORDER BY version DESC
                ) AS rn FROM password_versions
            ) ranked WHERE rn > $1
        )"
    )
    .bind(max_versions)
    .execute(db).await?.rows_affected())
}

pub fn start_background_task(db: PgPool, cfg: CleanupConfig) {
    let interval = Duration::from_secs(cfg.interval_hours * 3600);
    let hours    = cfg.interval_hours;
    tokio::spawn(async move {
        time::sleep(Duration::from_secs(30)).await;
        loop {
            run(&db, &cfg).await;
            time::sleep(interval).await;
        }
    });
    info!("Limpieza automática activada cada {} horas", hours);
}
