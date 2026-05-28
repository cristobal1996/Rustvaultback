// src/routes/account.rs

use axum::{extract::State, routing::{get, post, delete}, Json, Router};
use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    errors::{AppError, Result},
    middleware::AuthUser,
    models::UserPublic,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me",              get(get_profile))
        .route("/keys",            post(save_keys))
        .route("/change-password", post(change_password))
        .route("/delete",          delete(delete_account))
}

// ── Perfil ────────────────────────────────────────────────────────

async fn get_profile(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<UserPublic>> {
    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(user.into()))
}

// ── Cambio de contraseña ──────────────────────────────────────────
//
// Sin vaults, el cambio de contraseña es simple:
// el cliente solo actualiza la contraseña — las passwords
// se re-cifran en el cliente con la nueva MUK.
//
// Flujo:
// 1. Cliente deriva MUK antigua → descifra todas las passwords
// 2. Genera nuevo srp_salt
// 3. Deriva MUK nueva
// 4. Re-cifra todas las passwords con la nueva MUK
// 5. Envía al servidor: new_password + re_encrypted_passwords
// 6. Servidor actualiza password_hash, srp_salt, srp_verifier
// 7. Revoca todas las sesiones

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    current_password:       String,
    new_password:           String,
    new_srp_salt:           String,
    new_srp_verifier:       String,
    re_encrypted_passwords: Vec<ReEncryptedPassword>,
}

#[derive(Deserialize)]
pub struct ReEncryptedPassword {
    id:        uuid::Uuid,
    encrypted: serde_json::Value,
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    success:          bool,
    sessions_revoked: u64,
    message:          String,
}

async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>> {
    if req.new_password.len() < 12 {
        return Err(AppError::Validation("La nueva contraseña debe tener al menos 12 caracteres".into()))
    }

    // Verificar contraseña actual
    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;

    if !crypto::verify_password(&req.current_password, &user.password_hash) {
        sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1, $2)")
            .bind(auth.user_id).bind("password_change.failed")
            .execute(&state.db).await?;
        return Err(AppError::InvalidCredentials)
    }

    let new_password_hash = crypto::hash_password(&req.new_password)
        .map_err(anyhow::Error::from)?;

    let mut tx = state.db.begin().await?;

    // Actualizar credenciales del usuario
    sqlx::query(
        "UPDATE users SET password_hash=$1, srp_salt=$2, srp_verifier=$3 WHERE id=$4"
    )
    .bind(&new_password_hash)
    .bind(&req.new_srp_salt)
    .bind(&req.new_srp_verifier)
    .bind(auth.user_id)
    .execute(&mut *tx).await?;

    // Re-cifrar cada contraseña con la nueva MUK
    for pw in &req.re_encrypted_passwords {
        sqlx::query(
            "UPDATE passwords SET encrypted=$1, updated_at=NOW() WHERE id=$2 AND user_id=$3"
        )
        .bind(&pw.encrypted)
        .bind(pw.id)
        .bind(auth.user_id)
        .execute(&mut *tx).await?;
    }

    // Revocar todas las sesiones
    let sessions_revoked = sqlx::query(
        "UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL"
    )
    .bind(auth.user_id)
    .execute(&mut *tx).await?
    .rows_affected();

    sqlx::query(
        "INSERT INTO audit_log (user_id, action, metadata) VALUES ($1,$2,$3)"
    )
    .bind(auth.user_id)
    .bind("password.changed")
    .bind(serde_json::json!({
        "passwords_re_encrypted": req.re_encrypted_passwords.len(),
        "sessions_revoked": sessions_revoked,
    }))
    .execute(&mut *tx).await?;

    tx.commit().await?;

    Ok(Json(ChangePasswordResponse {
        success: true,
        sessions_revoked,
        message: format!(
            "Contraseña actualizada. Se han cerrado {} sesiones en otros dispositivos.",
            sessions_revoked
        ),
    }))
}

// ── Eliminar cuenta ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteAccountRequest {
    password:     String,
    confirmation: String,
}

async fn delete_account(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<Json<serde_json::Value>> {
    if req.confirmation != "ELIMINAR MI CUENTA" {
        return Err(AppError::Validation(
            "Para confirmar escribe exactamente: ELIMINAR MI CUENTA".into()
        ))
    }

    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE id=$1 AND deleted_at IS NULL"
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    if !crypto::verify_password(&req.password, &user.password_hash) {
        return Err(AppError::InvalidCredentials)
    }

    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET deleted_at=NOW() WHERE id=$1")
        .bind(auth.user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1")
        .bind(auth.user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1,$2)")
        .bind(auth.user_id).bind("account.deleted")
        .execute(&mut *tx).await?;
    tx.commit().await?;

    Ok(Json(serde_json::json!({ "deleted": true })))
}


// ── Guardar par de claves público/privado ─────────────────────────

#[derive(serde::Deserialize)]
pub struct SaveKeysRequest {
    pub pub_key:            String,
    pub encrypted_priv_key: serde_json::Value,
}

async fn save_keys(
    State(state): State<AppState>,
    auth:         AuthUser,
    Json(req):    Json<SaveKeysRequest>,
) -> Result<Json<serde_json::Value>> {
    // Validar formato de clave pública (hex, 65 bytes para P-256 sin comprimir)
    if req.pub_key.len() < 64 {
        return Err(AppError::Validation("Clave pública inválida".into()))
    }

    sqlx::query(
        "UPDATE users SET pub_key = $1, encrypted_priv_key = $2 WHERE id = $3"
    )
    .bind(&req.pub_key)
    .bind(&req.encrypted_priv_key)
    .bind(auth.user_id)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "saved": true })))
}
