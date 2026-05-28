// src/routes/sharing.rs
// Compartir contraseñas individuales entre usuarios.
//
// Flujo:
// 1. Alice busca a Bob por RV-XXXX-XXXX → obtiene su pub_key
// 2. Alice re-cifra la contraseña con la pub_key de Bob (ECIES X25519)
// 3. Bob recibe la notificación y puede:
//    a. Aceptar → se guarda como copia propia en su tabla passwords
//    b. Ver temporalmente → descifra on-the-fly sin guardar
//    c. Rechazar → se marca como rejected

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::{
    errors::{AppError, Result},
    middleware::AuthUser,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/send",          post(send_share))
        .route("/inbox",         get(list_inbox))
        .route("/sent",          get(list_sent))
        .route("/:id/accept",    post(accept_share))
        .route("/:id/view",      get(view_share))
        .route("/:id/reject",    post(reject_share))
}

// ── Tipos ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SendShareRequest {
    pub password_id:             Uuid,
    pub recipient_invite_code:   String,
    pub encrypted_for_recipient: JsonValue,  // ECIES: { ephemeral_pub, nonce, ciphertext }
    pub title_hint:              Option<String>,
    pub message:                 Option<String>,
    pub permission:              Option<String>, // "view" | "copy"
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SharedPassword {
    pub id:                      Uuid,
    pub password_id:             Uuid,
    pub sender_id:               Uuid,
    pub recipient_id:            Uuid,
    pub title_hint:              Option<String>,
    pub message:                 Option<String>,
    pub permission:              String,
    pub status:                  String,
    pub expires_at:              DateTime<Utc>,
    pub created_at:              DateTime<Utc>,
    pub responded_at:            Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct InboxItem {
    pub id:          Uuid,
    pub sender_email_hint: String,
    pub title_hint:  Option<String>,
    pub message:     Option<String>,
    pub permission:  String,
    pub status:      String,
    pub expires_at:  DateTime<Utc>,
    pub created_at:  DateTime<Utc>,
}

#[derive(Serialize)]
pub struct SentItem {
    pub id:                   Uuid,
    pub recipient_email_hint: String,
    pub title_hint:           Option<String>,
    pub permission:           String,
    pub status:               String,
    pub expires_at:           DateTime<Utc>,
    pub created_at:           DateTime<Utc>,
}

// ── Enviar ────────────────────────────────────────────────────────

async fn send_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<SendShareRequest>,
) -> Result<Json<SharedPassword>> {
    // Verificar que la contraseña pertenece al usuario
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM passwords WHERE id=$1 AND user_id=$2 AND NOT is_deleted)"
    )
    .bind(req.password_id).bind(auth.user_id)
    .fetch_one(&state.db).await?;

    if !exists { return Err(AppError::NotFound) }

    // Buscar destinatario por invite_code
    let recipient = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        "SELECT id, LEFT(email,3)||'***' AS email_hint, pub_key
         FROM users WHERE upper(invite_code)=upper($1) AND id!=$2 AND deleted_at IS NULL"
    )
    .bind(req.recipient_invite_code.trim())
    .bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let (recipient_id, _, pub_key) = recipient;

    // Verificar que el destinatario tiene clave pública
    if pub_key.is_none() {
        return Err(AppError::Validation(
            "El destinatario no tiene clave pública — debe iniciar sesión en la app al menos una vez".into()
        ))
    }

    let permission = req.permission.unwrap_or_else(|| "view".into());
    if !["view", "copy"].contains(&permission.as_str()) {
        return Err(AppError::Validation("Permiso inválido".into()))
    }

    // Crear el compartido
    let shared = sqlx::query_as::<_, SharedPassword>(
        r#"
        INSERT INTO shared_passwords
            (password_id, sender_id, recipient_id, encrypted_for_recipient,
             title_hint, message, permission)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(req.password_id)
    .bind(auth.user_id)
    .bind(recipient_id)
    .bind(&req.encrypted_for_recipient)
    .bind(req.title_hint.as_deref())
    .bind(req.message.as_deref())
    .bind(&permission)
    .fetch_one(&state.db).await?;

    audit(&state.db, auth.user_id, "password.shared").await;
    Ok(Json(shared))
}

// ── Bandeja de entrada ────────────────────────────────────────────

async fn list_inbox(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<InboxItem>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Option<String>, String, String, DateTime<Utc>, DateTime<Utc>)>(
        r#"
        SELECT
            sp.id,
            LEFT(u.email, 3) || '***' AS sender_email_hint,
            sp.title_hint,
            sp.message,
            sp.permission,
            sp.status,
            sp.expires_at,
            sp.created_at
        FROM shared_passwords sp
        JOIN users u ON u.id = sp.sender_id
        WHERE sp.recipient_id = $1
          AND sp.status = 'pending'
          AND sp.expires_at > NOW()
        ORDER BY sp.created_at DESC
        "#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.db).await?;

    let items = rows.into_iter().map(|(id, sender_email_hint, title_hint, message, permission, status, expires_at, created_at)| {
        InboxItem { id, sender_email_hint, title_hint, message, permission, status, expires_at, created_at }
    }).collect();

    Ok(Json(items))
}

// ── Enviados ──────────────────────────────────────────────────────

async fn list_sent(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SentItem>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, String, String, DateTime<Utc>, DateTime<Utc>)>(
        r#"
        SELECT
            sp.id,
            LEFT(u.email, 3) || '***' AS recipient_email_hint,
            sp.title_hint,
            sp.permission,
            sp.status,
            sp.expires_at,
            sp.created_at
        FROM shared_passwords sp
        JOIN users u ON u.id = sp.recipient_id
        WHERE sp.sender_id = $1
        ORDER BY sp.created_at DESC
        LIMIT 50
        "#,
    )
    .bind(auth.user_id)
    .fetch_all(&state.db).await?;

    let items = rows.into_iter().map(|(id, recipient_email_hint, title_hint, permission, status, expires_at, created_at)| {
        SentItem { id, recipient_email_hint, title_hint, permission, status, expires_at, created_at }
    }).collect();

    Ok(Json(items))
}

// ── Ver temporalmente (sin guardar) ──────────────────────────────

async fn view_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>> {
    let shared = sqlx::query_as::<_, (Uuid, String, String, JsonValue, DateTime<Utc>)>(
        r#"
        SELECT id, permission, status, encrypted_for_recipient, expires_at
        FROM shared_passwords
        WHERE id=$1 AND recipient_id=$2
        "#,
    )
    .bind(id).bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let (_, permission, status, encrypted, expires_at) = shared;

    if status == "rejected" {
        return Err(AppError::Validation("Esta contraseña fue rechazada".into()))
    }
    if expires_at < Utc::now() {
        return Err(AppError::Validation("Esta contraseña compartida ha expirado".into()))
    }

    // Devolver el blob cifrado — el cliente lo descifra con su clave privada
    Ok(Json(serde_json::json!({
        "id":         id,
        "permission": permission,
        "encrypted":  encrypted,  // cliente descifra con su priv_key X25519
    })))
}

// ── Aceptar (guardar como copia propia) ──────────────────────────

async fn accept_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let shared = sqlx::query_as::<_, (Uuid, String, String, JsonValue, Option<String>, DateTime<Utc>)>(
        r#"
        SELECT id, permission, status, encrypted_for_recipient, title_hint, expires_at
        FROM shared_passwords
        WHERE id=$1 AND recipient_id=$2
        "#,
    )
    .bind(id).bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let (_, permission, status, encrypted, title_hint, expires_at) = shared;

    if permission != "copy" {
        return Err(AppError::Validation(
            "Esta contraseña solo tiene permiso de vista — no se puede copiar".into()
        ))
    }
    if status != "pending" {
        return Err(AppError::Validation("Esta invitación ya fue procesada".into()))
    }
    if expires_at < Utc::now() {
        return Err(AppError::Validation("Esta contraseña compartida ha expirado".into()))
    }

    // Marcar como aceptada
    sqlx::query(
        "UPDATE shared_passwords SET status='accepted', responded_at=NOW() WHERE id=$1"
    ).bind(id).execute(&state.db).await?;

    // El cliente debe re-cifrar con su MUK y llamar a POST /api/passwords
    // Devolvemos el blob cifrado para que el cliente lo procese
    audit(&state.db, auth.user_id, "password.share.accepted").await;

    Ok(Json(serde_json::json!({
        "accepted":  true,
        "encrypted": encrypted,   // cliente descifra con priv_key y guarda con su MUK
        "title_hint": title_hint,
    })))
}

// ── Rechazar ──────────────────────────────────────────────────────

async fn reject_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let r = sqlx::query(
        "UPDATE shared_passwords SET status='rejected', responded_at=NOW()
         WHERE id=$1 AND recipient_id=$2 AND status='pending'"
    ).bind(id).bind(auth.user_id).execute(&state.db).await?;

    if r.rows_affected() == 0 { return Err(AppError::NotFound) }

    audit(&state.db, auth.user_id, "password.share.rejected").await;
    Ok(Json(serde_json::json!({ "rejected": true })))
}

// ── Audit ─────────────────────────────────────────────────────────

async fn audit(db: &sqlx::PgPool, user_id: Uuid, action: &str) {
    let _ = sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1, $2)")
        .bind(user_id).bind(action).execute(db).await;
}
