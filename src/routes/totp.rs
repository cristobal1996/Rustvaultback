// src/routes/totp.rs
//
// Endpoints HTTP para los códigos 2FA de SERVICIOS EXTERNOS
// (GitHub, Google, AWS, etc.) que el usuario guarda en RustVault.
//
// Estos NO son el 2FA del propio login de RustVault (eso está en
// routes/auth.rs). El contenido aquí SÍ se guarda cifrado con la MUK
// del usuario (zero-knowledge).

use axum::{
    extract::{Path, State},
    routing::{get, post, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::{AppError, Result},
    middleware::AuthUser,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/",       get(list).post(create))
        .route("/parse",  post(parse_otpauth))
        .route("/:id",    delete(delete_one))
}

// ── Modelos de respuesta ──────────────────────────────────────────

#[derive(Serialize)]
pub struct TotpCredentialResponse {
    pub id:               Uuid,
    pub issuer:           Option<String>,
    pub account:          Option<String>,
    pub algorithm:        String,
    pub digits:           i32,
    pub period:           i32,
    pub encrypted_secret: serde_json::Value,
}

// ── GET /api/totp — listar credenciales del usuario ──────────────

async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<TotpCredentialResponse>>> {
    let rows = sqlx::query_as::<_, crate::models::TotpCredential>(
        "SELECT * FROM totp_credentials WHERE user_id = $1 ORDER BY created_at DESC"
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await?;

    let out: Vec<TotpCredentialResponse> = rows.into_iter().map(|t| TotpCredentialResponse {
        id:               t.id,
        issuer:           t.issuer,
        account:          t.account,
        algorithm:        t.algorithm,
        digits:           t.digits,
        period:           t.period,
        encrypted_secret: t.encrypted_secret,
    }).collect();

    Ok(Json(out))
}

// ── POST /api/totp — crear credencial ─────────────────────────────

#[derive(Deserialize)]
pub struct CreateRequest {
    pub issuer:           Option<String>,
    pub account:          Option<String>,
    pub algorithm:        Option<String>,
    pub digits:           Option<i32>,
    pub period:           Option<i32>,
    pub encrypted_secret: serde_json::Value,
}

async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateRequest>,
) -> Result<Json<TotpCredentialResponse>> {
    // Validar el blob cifrado
    if !req.encrypted_secret.is_object() {
        return Err(AppError::Validation("encrypted_secret debe ser objeto JSON".into()));
    }

    let algorithm = req.algorithm.unwrap_or_else(|| "SHA1".to_string());
    let digits    = req.digits.unwrap_or(6);
    let period    = req.period.unwrap_or(30);

    // Validar rangos (los mismos CHECK del esquema)
    if !(6..=8).contains(&digits) {
        return Err(AppError::Validation("digits debe estar entre 6 y 8".into()));
    }
    if !(15..=120).contains(&period) {
        return Err(AppError::Validation("period debe estar entre 15 y 120".into()));
    }

    let cred = sqlx::query_as::<_, crate::models::TotpCredential>(
        "INSERT INTO totp_credentials
             (user_id, issuer, account, encrypted_secret, algorithm, digits, period)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *"
    )
    .bind(auth.user_id)
    .bind(req.issuer)
    .bind(req.account)
    .bind(&req.encrypted_secret)
    .bind(&algorithm)
    .bind(digits)
    .bind(period)
    .fetch_one(&state.db)
    .await?;

    // Auditoría
    let _ = sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1, $2)")
        .bind(auth.user_id)
        .bind("totp.created")
        .execute(&state.db)
        .await;

    Ok(Json(TotpCredentialResponse {
        id:               cred.id,
        issuer:           cred.issuer,
        account:          cred.account,
        algorithm:        cred.algorithm,
        digits:           cred.digits,
        period:           cred.period,
        encrypted_secret: cred.encrypted_secret,
    }))
}

// ── DELETE /api/totp/:id — eliminar credencial ────────────────────

async fn delete_one(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<axum::http::StatusCode> {
    let rows = sqlx::query(
        "DELETE FROM totp_credentials WHERE id = $1 AND user_id = $2"
    )
    .bind(id)
    .bind(auth.user_id)
    .execute(&state.db)
    .await?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound);
    }

    let _ = sqlx::query("INSERT INTO audit_log (user_id, action) VALUES ($1, $2)")
        .bind(auth.user_id)
        .bind("totp.deleted")
        .execute(&state.db)
        .await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ── POST /api/totp/parse — parsear URL otpauth:// ────────────────

#[derive(Deserialize)]
pub struct ParseRequest {
    pub otpauth_url: String,
}

#[derive(Serialize)]
pub struct ParseResponse {
    pub issuer:     String,
    pub account:    String,
    pub secret_b32: String,
    pub algorithm:  String,
    pub digits:     String,
    pub period:     String,
}

async fn parse_otpauth(
    _auth: AuthUser,
    Json(req): Json<ParseRequest>,
) -> Result<Json<ParseResponse>> {
    let url = req.otpauth_url.trim();

    if !url.to_lowercase().starts_with("otpauth://totp/") {
        return Err(AppError::Validation(
            "La URL debe empezar por otpauth://totp/".into()
        ));
    }

    // Quitar el prefijo "otpauth://totp/"
    let rest = &url["otpauth://totp/".len()..];

    // Separar label de la query string
    let (label, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None         => (rest, ""),
    };

    // El label puede ser "Issuer:Account" o solo "Account"
    let label_decoded = url_decode(label);
    let (label_issuer, account) = match label_decoded.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
        None         => (None, label_decoded.trim().to_string()),
    };

    // Parsear parámetros de la query
    let mut secret    = String::new();
    let mut issuer    = label_issuer.unwrap_or_default();
    let mut algorithm = "SHA1".to_string();
    let mut digits    = "6".to_string();
    let mut period    = "30".to_string();

    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(p) => p,
            None    => continue,
        };
        let v = url_decode(v);
        match k.to_lowercase().as_str() {
            "secret"    => secret    = v,
            "issuer"    => issuer    = v,   // El issuer de la query tiene prioridad
            "algorithm" => algorithm = v.to_uppercase(),
            "digits"    => digits    = v,
            "period"    => period    = v,
            _ => {}
        }
    }

    if secret.is_empty() {
        return Err(AppError::Validation("La URL otpauth no contiene secret".into()));
    }

    if issuer.is_empty() {
        issuer = "Desconocido".to_string();
    }

    Ok(Json(ParseResponse {
        issuer,
        account,
        secret_b32: secret,
        algorithm,
        digits,
        period,
    }))
}

// ── Helper: decodificar URL-encoded ──────────────────────────────

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((h1 << 4) | h2) as u8);
                i += 3;
                continue;
            }
        }
        if b == b'+' {
            out.push(b' ');
        } else {
            out.push(b);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
