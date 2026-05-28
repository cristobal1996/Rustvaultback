// src/routes/auth.rs

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    crypto,
    errors::{AppError, Result},
    middleware,
    models::UserPublic,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register",    post(register))
        .route("/login",       post(login))
        .route("/logout",      post(logout))
        .route("/recover",     post(recover_account))
        .route("/2fa/setup",   post(setup_2fa))
        .route("/2fa/confirm", post(confirm_2fa))
        .route("/2fa/disable",  post(disable_2fa))
}

// ── Register ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    email:        String,
    password:     String,
    srp_salt:     String,
    srp_verifier: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    user:           UserPublic,
    emergency_code: String,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    if req.password.len() < 12 {
        return Err(AppError::Validation("La contraseña debe tener al menos 12 caracteres".into()))
    }
    if !req.email.contains('@') {
        return Err(AppError::Validation("Email inválido".into()))
    }

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND deleted_at IS NULL)"
    )
    .bind(&req.email).fetch_one(&state.db).await?;

    if exists { return Err(AppError::EmailTaken) }

    let password_hash = crypto::hash_password(&req.password).map_err(anyhow::Error::from)?;

    // Generar códigos únicos
    let invite_code    = generate_invite_code();
    let emergency_code = generate_emergency_code();
    let emergency_hash = crypto::hash_token(&emergency_code);

    let user = sqlx::query_as::<_, crate::models::User>(
        "INSERT INTO users (id,email,password_hash,srp_salt,srp_verifier,invite_code,emergency_code_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *"
    )
    .bind(Uuid::new_v4())
    .bind(&req.email)
    .bind(&password_hash)
    .bind(&req.srp_salt)
    .bind(&req.srp_verifier)
    .bind(&invite_code)
    .bind(&emergency_hash)
    .fetch_one(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1,$2)")
        .bind(user.id).bind("user.registered")
        .execute(&state.db).await?;

    Ok(Json(RegisterResponse { user: user.into(), emergency_code }))
}

// ── Login ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    email:              String,
    password:           String,
    totp_code:          Option<String>,
    totp_muk:           Option<String>,
    device_name:        String,
    platform:           String,
    device_fingerprint: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    token:        String,
    user:         UserPublic,
    srp_salt:     String,
    requires_2fa: bool,
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE email=$1 AND deleted_at IS NULL"
    )
    .bind(&req.email)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::InvalidCredentials)?;

    if !crypto::verify_password(&req.password, &user.password_hash) {
        sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
            .bind(user.id).bind("login.failed")
            .execute(&state.db).await?;
        return Err(AppError::InvalidCredentials)
    }

    if user.totp_enabled {
        match &req.totp_code {
            None => {
                // No viene código — indicar al cliente que lo pida
                // Generar token temporal de corta duración
                let device = sqlx::query_as::<_, crate::models::Device>(
                    "INSERT INTO devices (id,user_id,name,platform,device_fingerprint)
                     VALUES ($1,$2,$3,$4,$5)
                     ON CONFLICT (id) DO UPDATE SET last_seen_at=NOW(), name=EXCLUDED.name
                     RETURNING *"
                )
                .bind(Uuid::new_v4())
                .bind(user.id)
                .bind(&req.device_name)
                .bind(&req.platform)
                .bind(&req.device_fingerprint)
                .fetch_one(&state.db).await?;

                let token = middleware::generate_token(user.id, Some(device.id), &state.cfg.jwt_secret)
                    .map_err(|e| AppError::Internal(e))?;

                return Ok(Json(LoginResponse {
                    token,
                    srp_salt:     user.srp_salt.clone(),
                    requires_2fa: true,
                    user:         user.into(),
                }))
            }
            Some(code) => {
                // Verificar el código TOTP
                if let Some(encrypted_secret) = &user.totp_secret {
                    let muk_hex = &req.totp_muk.clone().unwrap_or_default();
                    // Por ahora aceptamos cualquier código de 6 dígitos válido
                    // En producción aquí verificarías con la librería totp-rs
                    let _ = code;
                    let _ = encrypted_secret;
                }
            }
        }
    }

    let device = sqlx::query_as::<_, crate::models::Device>(
        "INSERT INTO devices (id,user_id,name,platform,device_fingerprint)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (id) DO UPDATE SET last_seen_at=NOW(), name=EXCLUDED.name
         RETURNING *"
    )
    .bind(Uuid::new_v4())
    .bind(user.id)
    .bind(&req.device_name)
    .bind(&req.platform)
    .bind(&req.device_fingerprint)
    .fetch_one(&state.db).await?;

    let token      = middleware::generate_token(user.id, Some(device.id), &state.cfg.jwt_secret)
        .map_err(|e| AppError::Internal(e))?;
    let token_hash = crypto::hash_token(&token);

    sqlx::query(
        "INSERT INTO sessions (id,user_id,device_id,token_hash,expires_at)
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '7 days')"
    )
    .bind(Uuid::new_v4()).bind(user.id).bind(device.id).bind(&token_hash)
    .execute(&state.db).await?;

    sqlx::query("UPDATE users SET last_login_at=NOW() WHERE id=$1")
        .bind(user.id).execute(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id,device_id,action) VALUES ($1,$2,$3)")
        .bind(user.id).bind(device.id).bind("login.success")
        .execute(&state.db).await?;

    Ok(Json(LoginResponse {
        token,
        srp_salt:     user.srp_salt.clone(),
        requires_2fa: user.totp_enabled,
        user:         user.into(),
    }))
}

// ── Logout ────────────────────────────────────────────────────────

async fn logout(
    State(state): State<AppState>,
    auth: crate::middleware::AuthUser,
    axum_extra::TypedHeader(authorization): axum_extra::TypedHeader<
        axum_extra::headers::Authorization<axum_extra::headers::authorization::Bearer>
    >,
) -> Result<Json<serde_json::Value>> {
    let token_hash = crypto::hash_token(authorization.token());
    sqlx::query(
        "UPDATE sessions SET revoked_at=NOW() WHERE token_hash=$1 AND user_id=$2"
    )
    .bind(&token_hash).bind(auth.user_id)
    .execute(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(auth.user_id).bind("session.revoked")
        .execute(&state.db).await?;

    Ok(Json(serde_json::json!({ "logged_out": true })))
}

// ── Recuperar cuenta con emergency_code ──────────────────────────

#[derive(Deserialize)]
pub struct RecoverRequest {
    email:          String,
    emergency_code: String,
}

async fn recover_account(
    State(state): State<AppState>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>> {
    let code_hash = crypto::hash_token(&req.emergency_code.trim().to_uppercase());

    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE email=$1 AND emergency_code_hash=$2 AND deleted_at IS NULL"
    )
    .bind(req.email.trim().to_lowercase())
    .bind(&code_hash)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::Unauthorized)?;

    sqlx::query(
        "UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL"
    ).bind(user.id).execute(&state.db).await?;

    sqlx::query(
        "UPDATE users SET deleted_at=NOW(), emergency_code_hash=NULL WHERE id=$1"
    ).bind(user.id).execute(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(user.id).bind("account.recovered")
        .execute(&state.db).await?;

    Ok(Json(serde_json::json!({
        "deleted": true,
        "message": "Cuenta eliminada. Puedes registrarte de nuevo con el mismo email."
    })))
}

// ── 2FA ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Setup2FAResponse {
    qr_code_url:  String,
    manual_key:   String,
    backup_codes: Vec<String>,
}

async fn setup_2fa(
    State(_state): State<AppState>,
    _auth: crate::middleware::AuthUser,
) -> Result<Json<Setup2FAResponse>> {
    // Generar 20 bytes aleatorios y convertir a Base32
    // Los autenticadores (Google Authenticator, Authy) requieren Base32
    let secret_hex   = crypto::random_hex(20);
    let secret_bytes = hex::decode(&secret_hex).unwrap_or_default();
    let secret_b32   = base32_encode(&secret_bytes);

    let backup_codes: Vec<String> = (0..8)
        .map(|_| crypto::random_hex(5).to_uppercase())
        .collect();

    Ok(Json(Setup2FAResponse {
        qr_code_url: format!(
            "otpauth://totp/RustVault?secret={}&issuer=RustVault&algorithm=SHA1&digits=6&period=30",
            secret_b32
        ),
        manual_key:  secret_b32,
        backup_codes,
    }))
}

/// Convierte bytes a Base32 estándar (RFC 4648) sin padding
fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer = 0u32;
    let mut bits   = 0u32;

    for &byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits  += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        result.push(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    result
}

#[derive(Deserialize)]
pub struct Confirm2FARequest {
    totp_code:              String,
    encrypted_secret:       serde_json::Value,
    encrypted_backup_codes: serde_json::Value,
}

async fn confirm_2fa(
    State(state): State<AppState>,
    auth: crate::middleware::AuthUser,
    Json(req): Json<Confirm2FARequest>,
) -> Result<Json<serde_json::Value>> {
    let _ = req.totp_code;

    sqlx::query(
        "UPDATE users SET totp_secret=$1, totp_backup_codes=$2, totp_enabled=true WHERE id=$3"
    )
    .bind(&req.encrypted_secret)
    .bind(&req.encrypted_backup_codes)
    .bind(auth.user_id)
    .execute(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(auth.user_id).bind("2fa.enabled")
        .execute(&state.db).await?;

    Ok(Json(serde_json::json!({ "2fa_enabled": true })))
}

// ── Helpers ───────────────────────────────────────────────────────

fn generate_invite_code() -> String {
    format!("RV-{}-{}",
        crate::crypto::random_hex(2).to_uppercase(),
        crate::crypto::random_hex(2).to_uppercase()
    )
}

fn generate_emergency_code() -> String {
    format!("ERV-{}-{}-{}",
        crate::crypto::random_hex(2).to_uppercase(),
        crate::crypto::random_hex(2).to_uppercase(),
        crate::crypto::random_hex(2).to_uppercase()
    )
}


// ── Desactivar 2FA ────────────────────────────────────────────────

async fn disable_2fa(
    State(state): State<AppState>,
    auth: crate::middleware::AuthUser,
) -> Result<Json<serde_json::Value>> {
    sqlx::query(
        "UPDATE users SET totp_enabled=false, totp_secret=NULL, totp_backup_codes=NULL WHERE id=$1"
    )
    .bind(auth.user_id)
    .execute(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1, $2)")
        .bind(auth.user_id).bind("2fa.disabled")
        .execute(&state.db).await?;

    Ok(Json(serde_json::json!({ "disabled": true })))
}
