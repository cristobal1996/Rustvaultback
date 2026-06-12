// src/routes/sharing.rs
// Compartir contraseñas individuales entre usuarios.
//
// Tres modos:
//   - permanent: sin caducidad, el receptor puede aceptarla como copia propia
//   - temporary: caducidad fija elegida por el emisor (15min, 1h, 24h, 7d, 30d)
//                Se borra físicamente de BD al expirar.
//   - one_shot:  se borra al verla por primera vez (máx 7 días si nadie la abre)
//
// Flujo común:
// 1. Alice busca a Bob por RV-XXXX-XXXX → obtiene su pub_key
// 2. Alice re-cifra la contraseña con la pub_key de Bob (ECIES X25519)
// 3. Bob recibe la notificación. Según el modo:
//    - permanent → aceptar/rechazar normalmente
//    - temporary → ver mientras dure, se borra al expirar
//    - one_shot  → ver UNA vez, se borra inmediatamente tras la lectura

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
    pub domain_hint:             Option<String>,   // ← NUEVO: dominio en claro para mostrar en la bandeja
    pub message:                 Option<String>,
    pub permission:              Option<String>,   // "view" | "copy"
    pub share_mode:              Option<String>,   // "permanent" | "temporary" | "one_shot"
    pub duration_minutes:        Option<i64>,      // solo si share_mode == "temporary"
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SharedPassword {
    pub id:                      Uuid,
    pub password_id:             Uuid,
    pub sender_id:               Uuid,
    pub recipient_id:            Uuid,
    pub title_hint:              Option<String>,
    pub domain_hint:             Option<String>,
    pub message:                 Option<String>,
    pub permission:              String,
    pub share_mode:              String,
    pub status:                  String,
    pub expires_at:              Option<DateTime<Utc>>,
    pub created_at:              DateTime<Utc>,
    pub responded_at:            Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct InboxItem {
    pub id:                Uuid,
    pub sender_email_hint: String,
    pub title_hint:        Option<String>,
    pub domain_hint:       Option<String>,
    pub message:           Option<String>,
    pub permission:        String,
    pub share_mode:        String,
    pub status:            String,
    pub expires_at:        Option<DateTime<Utc>>,
    pub created_at:        DateTime<Utc>,
}

#[derive(Serialize)]
pub struct SentItem {
    pub id:                   Uuid,
    pub recipient_email_hint: String,
    pub title_hint:           Option<String>,
    pub domain_hint:          Option<String>,
    pub permission:           String,
    pub share_mode:           String,
    pub status:               String,
    pub expires_at:           Option<DateTime<Utc>>,
    pub created_at:           DateTime<Utc>,
}

// ── Enviar ────────────────────────────────────────────────────────

async fn send_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<SendShareRequest>,
) -> Result<Json<SharedPassword>> {
    // ─── Validar share_mode ─────────────────────────────────────
    let share_mode = req.share_mode.unwrap_or_else(|| "permanent".to_string());
    if !["permanent", "temporary", "one_shot"].contains(&share_mode.as_str()) {
        return Err(AppError::Validation(
            "share_mode inválido (debe ser permanent, temporary o one_shot)".into()
        ));
    }

    // ─── Calcular expires_at según el modo ──────────────────────
    // permanent: NULL (sin caducidad)
    // temporary: NOW + duration_minutes (solo valores predefinidos)
    // one_shot:  NOW + 7 días (máx de seguridad si nadie la abre)
    let expires_at: Option<DateTime<Utc>> = match share_mode.as_str() {
        "permanent" => None,
        "temporary" => {
            let minutes = req.duration_minutes.ok_or_else(|| {
                AppError::Validation(
                    "duration_minutes es obligatorio para share_mode temporary".into()
                )
            })?;
            // Valores permitidos: 15min, 1h, 24h, 7d, 30d
            let allowed = [15i64, 60, 1440, 10080, 43200];
            if !allowed.contains(&minutes) {
                return Err(AppError::Validation(
                    "duration_minutes debe ser 15, 60, 1440, 10080 o 43200".into()
                ));
            }
            Some(Utc::now() + chrono::Duration::minutes(minutes))
        }
        "one_shot" => Some(Utc::now() + chrono::Duration::days(7)),
        _ => unreachable!(),
    };

    // ─── Verificar que la contraseña pertenece al usuario ───────
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM passwords WHERE id=$1 AND user_id=$2 AND NOT is_deleted)"
    )
    .bind(req.password_id).bind(auth.user_id)
    .fetch_one(&state.db).await?;

    if !exists { return Err(AppError::NotFound) }

    // ─── Buscar destinatario por invite_code ────────────────────
    let recipient = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        "SELECT id, LEFT(email,3)||'***' AS email_hint, pub_key
         FROM users WHERE upper(invite_code)=upper($1) AND id!=$2 AND deleted_at IS NULL"
    )
    .bind(req.recipient_invite_code.trim())
    .bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let (recipient_id, _, pub_key) = recipient;

    if pub_key.is_none() {
        return Err(AppError::Validation(
            "El destinatario no tiene clave pública — debe iniciar sesión en la app al menos una vez".into()
        ))
    }

    let permission = req.permission.unwrap_or_else(|| "view".into());
    if !["view", "copy"].contains(&permission.as_str()) {
        return Err(AppError::Validation("Permiso inválido".into()))
    }

    // ─── Insertar en BD ─────────────────────────────────────────
    let shared = sqlx::query_as::<_, SharedPassword>(
        r#"
        INSERT INTO shared_passwords
            (password_id, sender_id, recipient_id, encrypted_for_recipient,
             title_hint, domain_hint, message, permission, share_mode, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, password_id, sender_id, recipient_id,
                  title_hint, domain_hint, message, permission, share_mode, status,
                  expires_at, created_at, responded_at
        "#,
    )
    .bind(req.password_id)
    .bind(auth.user_id)
    .bind(recipient_id)
    .bind(&req.encrypted_for_recipient)
    .bind(req.title_hint.as_deref())
    .bind(req.domain_hint.as_deref())
    .bind(req.message.as_deref())
    .bind(&permission)
    .bind(&share_mode)
    .bind(expires_at)
    .fetch_one(&state.db).await?;

    audit_with_meta(&state.db, auth.user_id, "password.shared", Some(serde_json::json!({
        "share_mode": share_mode,
        "expires_at": expires_at,
    }))).await;

    Ok(Json(shared))
}

// ── Bandeja de entrada ────────────────────────────────────────────
// Limpia las temporales/one_shot expiradas antes de devolver la lista.
// Usa una transacción con REPEATABLE READ para que el DELETE y el SELECT
// vean el mismo snapshot temporal — así no hay ventanas de race condition.

async fn list_inbox(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<InboxItem>>> {
    let mut tx = state.db.begin().await?;

    // Borrado físico de temporales/one_shot expiradas (oportunista)
    let _ = sqlx::query(
        "DELETE FROM shared_passwords
         WHERE recipient_id = $1
           AND share_mode IN ('temporary', 'one_shot')
           AND expires_at IS NOT NULL
           AND expires_at < NOW()
           AND status = 'pending'"
    )
    .bind(auth.user_id)
    .execute(&mut *tx)
    .await;

    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Option<String>, Option<String>, String, String, String, Option<DateTime<Utc>>, DateTime<Utc>)>(
        r#"
        SELECT
            sp.id,
            LEFT(u.email, 3) || '***' AS sender_email_hint,
            sp.title_hint,
            sp.domain_hint,
            sp.message,
            sp.permission,
            sp.share_mode,
            sp.status,
            sp.expires_at,
            sp.created_at
        FROM shared_passwords sp
        JOIN users u ON u.id = sp.sender_id
        WHERE sp.recipient_id = $1
          AND sp.status = 'pending'
          AND (sp.expires_at IS NULL OR sp.expires_at > NOW())
        ORDER BY sp.created_at DESC
        "#,
    )
    .bind(auth.user_id)
    .fetch_all(&mut *tx).await?;

    tx.commit().await?;

    let items = rows.into_iter().map(|(id, sender_email_hint, title_hint, domain_hint, message, permission, share_mode, status, expires_at, created_at)| {
        InboxItem { id, sender_email_hint, title_hint, domain_hint, message, permission, share_mode, status, expires_at, created_at }
    }).collect();

    Ok(Json(items))
}

// ── Enviados ──────────────────────────────────────────────────────

async fn list_sent(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SentItem>>> {
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Option<String>, String, String, String, Option<DateTime<Utc>>, DateTime<Utc>)>(
        r#"
        SELECT
            sp.id,
            LEFT(u.email, 3) || '***' AS recipient_email_hint,
            sp.title_hint,
            sp.domain_hint,
            sp.permission,
            sp.share_mode,
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

    let items = rows.into_iter().map(|(id, recipient_email_hint, title_hint, domain_hint, permission, share_mode, status, expires_at, created_at)| {
        SentItem { id, recipient_email_hint, title_hint, domain_hint, permission, share_mode, status, expires_at, created_at }
    }).collect();

    Ok(Json(items))
}

// ── Ver compartido ────────────────────────────────────────────────
// Devuelve el blob cifrado para que el cliente lo descifre.
// Si es one_shot → BORRA la fila atómicamente con un DELETE ... RETURNING
// para evitar race conditions entre múltiples llamadas concurrentes.

async fn view_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>> {
    // Primero, leer el modo SIN bloquear (solo para saber qué tipo es)
    let row = sqlx::query_as::<_, (String, String, String, JsonValue, Option<DateTime<Utc>>)>(
        r#"
        SELECT permission, share_mode, status, encrypted_for_recipient, expires_at
        FROM shared_passwords
        WHERE id=$1 AND recipient_id=$2
        "#,
    )
    .bind(id).bind(auth.user_id)
    .fetch_optional(&state.db).await?;

    let (permission, share_mode, status, encrypted, expires_at) = match row {
        Some(r) => r,
        None    => return Err(AppError::Validation(
            "Esta contraseña compartida ya no está disponible (puede haber expirado o haberse visto previamente)".into()
        )),
    };

    if status == "rejected" {
        return Err(AppError::Validation("Esta contraseña fue rechazada".into()))
    }

    // Comprobar expiración (solo aplica si tiene expires_at)
    if let Some(exp) = expires_at {
        if exp < Utc::now() {
            if share_mode == "temporary" || share_mode == "one_shot" {
                let _ = sqlx::query("DELETE FROM shared_passwords WHERE id=$1")
                    .bind(id)
                    .execute(&state.db)
                    .await;
            }
            return Err(AppError::Validation("Esta contraseña compartida ha expirado".into()))
        }
    }

    // ─── One-shot: borrado ATÓMICO con DELETE ... RETURNING ──────
    // Solo el primer cliente que llegue obtiene los datos. Los demás
    // verán "ya no existe" (0 filas afectadas → mensaje claro).
    if share_mode == "one_shot" {
        let deleted = sqlx::query_as::<_, (JsonValue,)>(
            "DELETE FROM shared_passwords
             WHERE id=$1 AND recipient_id=$2
             RETURNING encrypted_for_recipient"
        )
        .bind(id)
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await?;

        let encrypted_atomic = match deleted {
            Some((e,)) => e,
            None       => return Err(AppError::Validation(
                "Esta contraseña ya fue vista anteriormente".into()
            )),
        };

        audit(&state.db, auth.user_id, "password.share.one_shot_viewed").await;

        return Ok(Json(serde_json::json!({
            "id":         id,
            "permission": permission,
            "share_mode": share_mode,
            "encrypted":  encrypted_atomic,
        })));
    }

    Ok(Json(serde_json::json!({
        "id":         id,
        "permission": permission,
        "share_mode": share_mode,
        "encrypted":  encrypted,  // cliente descifra con su priv_key X25519
    })))
}

// ── Aceptar (solo permanentes) ───────────────────────────────────
// Las temporales y one_shot NO se pueden aceptar como copia permanente.

async fn accept_share(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let shared = sqlx::query_as::<_, (Uuid, String, String, String, JsonValue, Option<String>, Option<DateTime<Utc>>)>(
        r#"
        SELECT id, permission, share_mode, status, encrypted_for_recipient, title_hint, expires_at
        FROM shared_passwords
        WHERE id=$1 AND recipient_id=$2
        "#,
    )
    .bind(id).bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let (_, permission, share_mode, status, encrypted, title_hint, expires_at) = shared;

    // Solo se pueden aceptar las permanentes
    if share_mode != "permanent" {
        return Err(AppError::Validation(
            "Solo las contraseñas permanentes se pueden aceptar como copia propia".into()
        ))
    }
    if permission != "copy" {
        return Err(AppError::Validation(
            "Esta contraseña solo tiene permiso de vista — no se puede copiar".into()
        ))
    }
    if status != "pending" {
        return Err(AppError::Validation("Esta invitación ya fue procesada".into()))
    }
    // Las permanentes no tienen expires_at, pero por si acaso (legacy)
    if let Some(exp) = expires_at {
        if exp < Utc::now() {
            return Err(AppError::Validation("Esta contraseña compartida ha expirado".into()))
        }
    }

    // Marcar como aceptada
    sqlx::query(
        "UPDATE shared_passwords SET status='accepted', responded_at=NOW() WHERE id=$1"
    ).bind(id).execute(&state.db).await?;

    audit(&state.db, auth.user_id, "password.share.accepted").await;

    Ok(Json(serde_json::json!({
        "accepted":   true,
        "encrypted":  encrypted,
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

async fn audit_with_meta(db: &sqlx::PgPool, user_id: Uuid, action: &str, metadata: Option<JsonValue>) {
    let _ = sqlx::query("INSERT INTO audit_log (user_id, action, metadata) VALUES ($1, $2, $3)")
        .bind(user_id).bind(action).bind(metadata).execute(db).await;
}
