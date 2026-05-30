// src/routes/passwords.rs — CRUD sin vaults

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::{
    errors::{AppError, Result},
    middleware::AuthUser,
    models::{Password, PasswordVersion},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/",               get(list_passwords).post(create_password))
        .route("/:id",            get(get_password).put(update_password).delete(delete_password))
        .route("/:id/versions",   get(get_versions))
        .route("/:id/restore/:v", post(restore_version))
        .route("/passwords/bulk-update", post(bulk_update))
}

#[derive(Deserialize)]
pub struct CreateRequest {
    pub title:       String,
    pub domain:      Option<String>,
    pub entry_type:  Option<String>,
    pub favicon_url: Option<String>,
    pub encrypted:   JsonValue,
}

#[derive(Deserialize)]
pub struct UpdateRequest {
    pub title:       Option<String>,
    pub domain:      Option<String>,
    pub favicon_url: Option<String>,
    pub encrypted:   Option<JsonValue>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub domain:     Option<String>,
    pub entry_type: Option<String>,
    pub search:     Option<String>,
    pub page:       Option<i64>,
    pub limit:      Option<i64>,
}

#[derive(Serialize)]
pub struct ListResponse {
    pub data:       Vec<Password>,
    pub total:      i64,
    pub page:       i64,
    pub total_pages: i64,
}

async fn list_passwords(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<ListResponse>> {
    let page   = q.page.unwrap_or(1).max(1);
    let limit  = q.limit.unwrap_or(50).min(100);
    let offset = (page - 1) * limit;

    let (total, passwords) = if let Some(ref domain) = q.domain {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM passwords WHERE user_id=$1 AND domain=$2 AND NOT is_deleted"
        ).bind(auth.user_id).bind(domain).fetch_one(&state.db).await?;

        let rows = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id=$1 AND domain=$2 AND NOT is_deleted ORDER BY updated_at DESC LIMIT $3 OFFSET $4"
        ).bind(auth.user_id).bind(domain).bind(limit).bind(offset)
        .fetch_all(&state.db).await?;

        (total, rows)

    } else if let Some(ref search) = q.search {
        let pat = format!("%{}%", search);
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM passwords WHERE user_id=$1 AND title ILIKE $2 AND NOT is_deleted"
        ).bind(auth.user_id).bind(&pat).fetch_one(&state.db).await?;

        let rows = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id=$1 AND title ILIKE $2 AND NOT is_deleted ORDER BY updated_at DESC LIMIT $3 OFFSET $4"
        ).bind(auth.user_id).bind(&pat).bind(limit).bind(offset)
        .fetch_all(&state.db).await?;

        (total, rows)

    } else {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM passwords WHERE user_id=$1 AND NOT is_deleted"
        ).bind(auth.user_id).fetch_one(&state.db).await?;

        let rows = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id=$1 AND NOT is_deleted ORDER BY updated_at DESC LIMIT $2 OFFSET $3"
        ).bind(auth.user_id).bind(limit).bind(offset)
        .fetch_all(&state.db).await?;

        (total, rows)
    };

    Ok(Json(ListResponse {
        data: passwords,
        total,
        page,
        total_pages: ((total as f64) / (limit as f64)).ceil() as i64,
    }))
}

async fn get_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Password>> {
    sqlx::query_as::<_, Password>(
        "SELECT * FROM passwords WHERE id=$1 AND user_id=$2 AND NOT is_deleted"
    )
    .bind(id).bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)
    .map(Json)
}

async fn create_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateRequest>,
) -> Result<Json<Password>> {
    if req.title.trim().is_empty() {
        return Err(AppError::Validation("El título no puede estar vacío".into()))
    }

    let entry_type = req.entry_type.unwrap_or_else(|| "login".into());

    let pw = sqlx::query_as::<_, Password>(
        "INSERT INTO passwords (user_id,title,domain,entry_type,favicon_url,encrypted)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *"
    )
    .bind(auth.user_id)
    .bind(req.title.trim())
    .bind(req.domain.as_deref().filter(|d| !d.is_empty()))
    .bind(&entry_type)
    .bind(req.favicon_url.as_deref())
    .bind(&req.encrypted)
    .fetch_one(&state.db).await?;

    sqlx::query(
        "INSERT INTO password_versions (password_id,version,encrypted) VALUES ($1,1,$2)"
    ).bind(pw.id).bind(&req.encrypted).execute(&state.db).await?;

    audit(&state.db, auth.user_id, "password.created").await;
    Ok(Json(pw))
}

async fn update_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<Password>> {
    let cur = sqlx::query_as::<_, Password>(
        "SELECT * FROM passwords WHERE id=$1 AND user_id=$2 AND NOT is_deleted"
    ).bind(id).bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let new_enc  = req.encrypted.as_ref().unwrap_or(&cur.encrypted);
    let new_ver  = cur.version + 1;

    let pw = sqlx::query_as::<_, Password>(
        "UPDATE passwords SET title=COALESCE($1,title), domain=COALESCE($2,domain),
         favicon_url=COALESCE($3,favicon_url), encrypted=$4, version=$5, updated_at=NOW()
         WHERE id=$6 AND user_id=$7 RETURNING *"
    )
    .bind(req.title.as_deref())
    .bind(req.domain.as_deref())
    .bind(req.favicon_url.as_deref())
    .bind(new_enc)
    .bind(new_ver)
    .bind(id)
    .bind(auth.user_id)
    .fetch_one(&state.db).await?;

    if req.encrypted.is_some() {
        sqlx::query(
            "INSERT INTO password_versions (password_id,version,encrypted) VALUES ($1,$2,$3)"
        ).bind(id).bind(new_ver).bind(new_enc).execute(&state.db).await?;
    }

    audit(&state.db, auth.user_id, "password.updated").await;
    Ok(Json(pw))
}

async fn delete_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let r = sqlx::query(
        "UPDATE passwords SET is_deleted=TRUE, deleted_at=NOW() WHERE id=$1 AND user_id=$2"
    ).bind(id).bind(auth.user_id).execute(&state.db).await?;

    if r.rows_affected() == 0 { return Err(AppError::NotFound) }

    audit(&state.db, auth.user_id, "password.deleted").await;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

async fn get_versions(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<PasswordVersion>>> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM passwords WHERE id=$1 AND user_id=$2)"
    ).bind(id).bind(auth.user_id).fetch_one(&state.db).await?;

    if !exists { return Err(AppError::NotFound) }

    let versions = sqlx::query_as::<_, PasswordVersion>(
        "SELECT * FROM password_versions WHERE password_id=$1 ORDER BY version DESC"
    ).bind(id).fetch_all(&state.db).await?;

    Ok(Json(versions))
}

async fn restore_version(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((id, version)): Path<(Uuid, i32)>,
) -> Result<Json<Password>> {
    let ver = sqlx::query_as::<_, PasswordVersion>(
        "SELECT pv.* FROM password_versions pv
         JOIN passwords p ON p.id=pv.password_id
         WHERE pv.password_id=$1 AND pv.version=$2 AND p.user_id=$3"
    ).bind(id).bind(version).bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let cur_ver: i32 = sqlx::query_scalar(
        "SELECT version FROM passwords WHERE id=$1"
    ).bind(id).fetch_one(&state.db).await?;

    let new_ver = cur_ver + 1;

    let pw = sqlx::query_as::<_, Password>(
        "UPDATE passwords SET encrypted=$1, version=$2, updated_at=NOW() WHERE id=$3 RETURNING *"
    ).bind(&ver.encrypted).bind(new_ver).bind(id)
    .fetch_one(&state.db).await?;

    sqlx::query(
        "INSERT INTO password_versions (password_id,version,encrypted) VALUES ($1,$2,$3)"
    ).bind(id).bind(new_ver).bind(&ver.encrypted).execute(&state.db).await?;

    Ok(Json(pw))
}

async fn audit(db: &sqlx::PgPool, user_id: Uuid, action: &str) {
    let _ = sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(user_id).bind(action).execute(db).await;
}

// 2. Añadir el handler al final del fichero:

#[derive(serde::Deserialize)]
pub struct BulkUpdateRequest {
    pub re_encrypted_passwords: Vec<ReEncryptedPassword>,
}

#[derive(serde::Deserialize)]
pub struct ReEncryptedPassword {
    pub id:        uuid::Uuid,
    pub encrypted: serde_json::Value,
}

async fn bulk_update(
    State(state): State<AppState>,
    auth: crate::middleware::AuthUser,
    Json(req): Json<BulkUpdateRequest>,
) -> Result<Json<serde_json::Value>> {
    let mut tx = state.db.begin().await?;
    let mut updated = 0;
    for pw in &req.re_encrypted_passwords {
        let result = sqlx::query(
            "UPDATE passwords SET encrypted=$1, updated_at=NOW()
             WHERE id=$2 AND user_id=$3 AND NOT is_deleted"
        )
        .bind(&pw.encrypted)
        .bind(pw.id)
        .bind(auth.user_id)
        .execute(&mut *tx).await?;
        updated += result.rows_affected();
    }
    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(auth.user_id).bind("passwords.bulk_reencrypted")
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({ "updated": updated })))
}