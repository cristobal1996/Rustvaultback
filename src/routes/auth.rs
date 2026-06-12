// src/routes/auth.rs

use axum::{extract::{ConnectInfo, State}, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    crypto,
    errors::{AppError, Result},
    middleware,
    models::UserPublic,
    state::AppState,
    totp,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register",    post(register))
        .route("/login",       post(login))
        .route("/logout",      post(logout))
        .route("/recover",            post(recover_account))
        .route("/recover/verify",     post(verify_recover_code))
        .route("/recover/blob",       post(get_recovery_blob))
        .route("/recover/save-blob",  post(save_recovery_blob))
        .route("/recover-with-key",   post(recover_with_key))
        .route("/2fa/setup",   post(setup_2fa))
        .route("/2fa/confirm", post(confirm_2fa))
        .route("/2fa/disable", post(disable_2fa))
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
    token: String,
    user: UserPublic,
    emergency_code: String,
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    // Rate limit: 5 registros por hora por IP (anti spam de cuentas)
    state.rate_limiter.check(addr.ip(), "register", 5, Duration::from_secs(3600))?;

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
    let token = middleware::generate_token(user.id, None, &state.cfg.jwt_secret)
        .map_err(|e| AppError::Internal(e))?;
    Ok(Json(RegisterResponse { token, user: user.into(), emergency_code }))
}

// ── Login ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    email:              String,
    password:           String,
    totp_code:          Option<String>,
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Rate limit: 5 intentos por minuto por IP (anti fuerza-bruta de contraseñas)
    state.rate_limiter.check(addr.ip(), "login", 5, Duration::from_secs(60))?;

    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE email=$1 AND deleted_at IS NULL"
    )
    .bind(&req.email)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::InvalidCredentials)?;

    // 1. Verificar contraseña
    if !crypto::verify_password(&req.password, &user.password_hash) {
        sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
            .bind(user.id).bind("login.failed")
            .execute(&state.db).await?;
        return Err(AppError::InvalidCredentials)
    }

    // 2. Si el usuario tiene 2FA activado, comprobar el código TOTP
    if user.totp_enabled {
        match &req.totp_code {
            None => {
                // No viene código → pedirlo al cliente, NO crear sesión aún
                return Ok(Json(LoginResponse {
                    token:        String::new(),       // sin token
                    srp_salt:     user.srp_salt.clone(),
                    requires_2fa: true,
                    user:         user.into(),
                }))
            }
            Some(code) => {
                // Validar el código TOTP contra el secret guardado
                let secret_hex = user.totp_secret.as_ref()
                    .ok_or_else(|| AppError::Internal(anyhow::anyhow!(
                        "Usuario tiene totp_enabled=true pero totp_secret es NULL"
                    )))?;

                let valid = totp::verify_code(secret_hex, code.trim())
                    .map_err(|e| AppError::Internal(e))?;

                if !valid {
                    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
                        .bind(user.id).bind("login.totp_failed")
                        .execute(&state.db).await?;
                    return Err(AppError::InvalidCredentials);
                }
                // ✓ TOTP válido, continuamos al login normal
            }
        }
    }

    // 3. Login válido — crear dispositivo y sesión
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
        requires_2fa: false,  // ← false porque ya pasamos el 2FA (si aplicaba)
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>> {
    // Rate limit: 3 intentos por hora por IP (anti fuerza-bruta del emergency_code)
    state.rate_limiter.check(addr.ip(), "recover", 3, Duration::from_secs(3600))?;

    let code_hash = crypto::hash_token(&req.emergency_code.trim().to_uppercase());

    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE email=$1 AND emergency_code_hash=$2 AND deleted_at IS NULL"
    )
    .bind(req.email.trim().to_lowercase())
    .bind(&code_hash)
    .fetch_optional(&state.db).await?
    .ok_or(AppError::Unauthorized)?;

    let mut tx = state.db.begin().await?;

    sqlx::query(
        "UPDATE sessions SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL"
    )
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM audit_log WHERE user_id=$1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO audit_log (user_id, action, metadata)
         VALUES (NULL, 'account.emergency_deleted', $1)"
    )
    .bind(serde_json::json!({ "email_hash": crypto::hash_token(&user.email) }))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(serde_json::json!({
        "deleted": true,
        "message": "Cuenta eliminada. Puedes registrarte de nuevo con el mismo email."
    })))
}

// ── Verificar emergency_code sin borrar (validación previa) ─────

/// Comprueba si un email + emergency_code son válidos, sin borrar nada.
/// Sirve para que el frontend pueda validar antes de mostrar la pantalla
/// de confirmación final, dando feedback claro al usuario.
async fn verify_recover_code(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>> {
    // Rate limit: 3 intentos por hora por IP (mismo límite que recover_account)
    state.rate_limiter.check(addr.ip(), "recover_verify", 3, Duration::from_secs(3600))?;

    let code_hash = crypto::hash_token(&req.emergency_code.trim().to_uppercase());

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM users
             WHERE email = $1
               AND emergency_code_hash = $2
               AND deleted_at IS NULL
         )"
    )
    .bind(req.email.trim().to_lowercase())
    .bind(&code_hash)
    .fetch_one(&state.db)
    .await?;

    if !exists {
        return Err(AppError::Unauthorized);
    }

    Ok(Json(serde_json::json!({ "valid": true })))
}

// ── 2FA ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct Setup2FAResponse {
    pub secret_hex:   String,        // ← lo necesita el cliente para mandarlo en confirm
    pub qr_code_url:  String,
    pub manual_key:   String,
    pub backup_codes: Vec<String>,
}

async fn setup_2fa(
    State(state): State<AppState>,
    auth: crate::middleware::AuthUser,
) -> Result<Json<Setup2FAResponse>> {
    // Obtener el email del usuario para incluirlo en la URL otpauth
    let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id=$1")
        .bind(auth.user_id)
        .fetch_one(&state.db).await?;

    let data = totp::generate_setup(&email)
        .map_err(|e| AppError::Internal(e))?;

    Ok(Json(Setup2FAResponse {
        secret_hex:   data.secret_hex,
        qr_code_url:  data.otpauth_url,
        manual_key:   data.manual_key,
        backup_codes: data.backup_codes,
    }))
}

#[derive(Deserialize)]
pub struct Confirm2FARequest {
    pub secret_hex:    String,         // ← el secret que generamos en setup
    pub totp_code:     String,         // ← el código que el usuario ve en su app
    pub backup_codes:  Vec<String>,    // ← los códigos para hashear y guardar
}

async fn confirm_2fa(
    State(state): State<AppState>,
    auth: crate::middleware::AuthUser,
    Json(req): Json<Confirm2FARequest>,
) -> Result<Json<serde_json::Value>> {
    // 1. Validar que el código TOTP es correcto (demostrando que el usuario
    //    escaneó bien el QR antes de activar 2FA)
    let valid = totp::verify_code(&req.secret_hex, req.totp_code.trim())
        .map_err(|e| AppError::Internal(e))?;

    if !valid {
        return Err(AppError::Validation(
            "El código TOTP no es válido. Asegúrate de haber escaneado correctamente el QR.".into()
        ));
    }

    // 2. Hashear los backup codes con Argon2id
    let hashed_codes = totp::prepare_backup_codes(&req.backup_codes)
        .map_err(|e| AppError::Internal(e))?;

    // 3. Activar 2FA y guardar el secret + backup codes
    sqlx::query(
        "UPDATE users SET totp_secret=$1, totp_backup_codes=$2, totp_enabled=true WHERE id=$3"
    )
    .bind(&req.secret_hex)
    .bind(&hashed_codes)
    .bind(auth.user_id)
    .execute(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(auth.user_id).bind("2fa.enabled")
        .execute(&state.db).await?;

    Ok(Json(serde_json::json!({ "2fa_enabled": true })))
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

// ── Guardar recovery blob al registrarse ─────────────────────────

#[derive(serde::Deserialize)]
pub struct SaveRecoveryBlobRequest {
    pub recovery_blob: serde_json::Value,
}

async fn save_recovery_blob(
    State(state): State<AppState>,
    auth: crate::middleware::AuthUser,
    Json(req): Json<SaveRecoveryBlobRequest>,
) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE users SET recovery_blob=$1 WHERE id=$2")
        .bind(&req.recovery_blob)
        .bind(auth.user_id)
        .execute(&state.db).await?;

    Ok(Json(serde_json::json!({ "saved": true })))
}

// ── Obtener recovery blob para recuperar contraseña ───────────────

#[derive(serde::Deserialize)]
pub struct GetRecoveryBlobRequest {
    pub email: String,
}

#[derive(serde::Serialize)]
pub struct GetRecoveryBlobResponse {
    pub recovery_blob: serde_json::Value,
    pub srp_salt:      String,
}

async fn get_recovery_blob(
    State(state): State<AppState>,
    Json(req): Json<GetRecoveryBlobRequest>,
) -> Result<Json<GetRecoveryBlobResponse>> {
    let row = sqlx::query_as::<_, (serde_json::Value, String)>(
        "SELECT recovery_blob, srp_salt FROM users
         WHERE email=$1 AND deleted_at IS NULL AND recovery_blob IS NOT NULL"
    )
    .bind(req.email.trim().to_lowercase())
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    Ok(Json(GetRecoveryBlobResponse {
        recovery_blob: row.0,
        srp_salt:      row.1,
    }))
}

// ── Recuperar contraseña con Recovery Key ────────────────────────

#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct RecoverWithKeyRequest {
    pub email:            String,
    pub recovery_key:     String,
    pub new_password:     String,
    pub new_srp_salt:     String,
    pub new_srp_verifier: String,
}

async fn recover_with_key(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RecoverWithKeyRequest>,
) -> Result<Json<serde_json::Value>> {
    // Rate limit: 3 intentos por hora por IP (anti fuerza-bruta de la Recovery Key)
    state.rate_limiter.check(addr.ip(), "recover_with_key", 3, Duration::from_secs(3600))?;

    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE email=$1 AND deleted_at IS NULL AND recovery_blob IS NOT NULL"
    )
    .bind(req.email.trim().to_lowercase())
    .fetch_optional(&state.db).await?
    .ok_or(AppError::NotFound)?;

    let new_password_hash = crypto::hash_password(&req.new_password)
        .map_err(anyhow::Error::from)?;

    let mut tx = state.db.begin().await?;

    sqlx::query(
        "UPDATE users SET password_hash=$1, srp_salt=$2, srp_verifier=$3 WHERE id=$4"
    )
    .bind(&new_password_hash)
    .bind(&req.new_srp_salt)
    .bind(&req.new_srp_verifier)
    .bind(user.id)
    .execute(&mut *tx).await?;

    let device = sqlx::query_as::<_, crate::models::Device>(
        "INSERT INTO devices (id,user_id,name,platform)
         VALUES ($1,$2,$3,$4) RETURNING *"
    )
    .bind(uuid::Uuid::new_v4())
    .bind(user.id)
    .bind("Recuperación de cuenta")
    .bind("web")
    .fetch_one(&mut *tx).await?;

    let token      = middleware::generate_token(user.id, Some(device.id), &state.cfg.jwt_secret)
        .map_err(|e| AppError::Internal(e))?;
    let token_hash = crypto::hash_token(&token);

    sqlx::query(
        "INSERT INTO sessions (id,user_id,device_id,token_hash,expires_at)
         VALUES ($1,$2,$3,$4,NOW()+INTERVAL '1 day')"
    )
    .bind(uuid::Uuid::new_v4())
    .bind(user.id)
    .bind(device.id)
    .bind(&token_hash)
    .execute(&mut *tx).await?;

    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(user.id).bind("account.recovered_with_key")
        .execute(&mut *tx).await?;

    tx.commit().await?;

    Ok(Json(serde_json::json!({
        "token":    token,
        "srp_salt": user.srp_salt,
        "user":     { "id": user.id, "email": user.email }
    })))
}
