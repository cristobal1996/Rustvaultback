use axum::{extract::{Path, State}, routing::{get, delete, post}, Json, Router};
use uuid::Uuid;
use crate::{errors::Result, middleware::AuthUser, models::Device, state::AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/",          get(list_devices))
        .route("/:id",       delete(revoke_device))
        .route("/:id/trust", post(trust_device))
}

async fn list_devices(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<Device>>> {
    let devices = sqlx::query_as::<_, Device>(
        "SELECT * FROM devices WHERE user_id = $1 ORDER BY last_seen_at DESC NULLS LAST"
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(devices))
}

async fn revoke_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    sqlx::query(
        "UPDATE sessions SET revoked_at = NOW() WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL"
    )
    .bind(device_id).bind(auth.user_id).execute(&state.db).await?;
    sqlx::query("DELETE FROM devices WHERE id = $1 AND user_id = $2")
        .bind(device_id).bind(auth.user_id).execute(&state.db).await?;
    sqlx::query("INSERT INTO audit_log (user_id, device_id, action) VALUES ($1, $2, $3)")
        .bind(auth.user_id).bind(device_id).bind("device.revoked")
        .execute(&state.db).await?;
    Ok(Json(serde_json::json!({ "revoked": true })))
}

async fn trust_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<Uuid>,
) -> Result<Json<Device>> {
    let device = sqlx::query_as::<_, Device>(
        "UPDATE devices SET is_trusted = true WHERE id = $1 AND user_id = $2 RETURNING *"
    )
    .bind(device_id).bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(crate::errors::AppError::NotFound)?;
    sqlx::query("INSERT INTO audit_log (user_id, device_id, action) VALUES ($1, $2, $3)")
        .bind(auth.user_id).bind(device_id).bind("device.trusted")
        .execute(&state.db).await?;
    Ok(Json(device))
}
