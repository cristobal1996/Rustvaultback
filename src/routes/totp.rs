// src/routes/totp.rs — TOTP directo del usuario, sin vault_id ni entry_id

use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::{
    errors::{AppError, Result},
    middleware::AuthUser,
    models::TotpCredential,
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/",      get(list_totp).post(create_totp))
        .route("/:id",   delete(delete_totp))
        .route("/parse", post(parse_otpauth))
}

#[derive(Deserialize)]
pub struct CreateRequest {
    pub issuer:           Option<String>,
    pub account:          Option<String>,
    pub algorithm:        Option<String>,
    pub digits:           Option<i32>,
    pub period:           Option<i32>,
    pub encrypted_secret: JsonValue,
}

async fn list_totp(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<TotpCredential>>> {
    let creds = sqlx::query_as::<_, TotpCredential>(
        "SELECT * FROM totp_credentials WHERE user_id=$1 ORDER BY issuer ASC NULLS LAST, account ASC"
    )
    .bind(auth.user_id)
    .fetch_all(&state.db).await?;
    Ok(Json(creds))
}

async fn create_totp(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateRequest>,
) -> Result<Json<TotpCredential>> {
    let algorithm = req.algorithm.unwrap_or_else(|| "SHA1".into());
    if !["SHA1","SHA256","SHA512"].contains(&algorithm.as_str()) {
        return Err(AppError::Validation("Algoritmo inválido".into()))
    }

    let digits = req.digits.unwrap_or(6);
    let period = req.period.unwrap_or(30);

    let cred = sqlx::query_as::<_, TotpCredential>(
        "INSERT INTO totp_credentials (user_id,issuer,account,encrypted_secret,algorithm,digits,period)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *"
    )
    .bind(auth.user_id)
    .bind(req.issuer.as_deref())
    .bind(req.account.as_deref())
    .bind(&req.encrypted_secret)
    .bind(&algorithm)
    .bind(digits)
    .bind(period)
    .fetch_one(&state.db).await?;

    sqlx::query("INSERT INTO audit_log (user_id,action) VALUES ($1,$2)")
        .bind(auth.user_id).bind("totp.created")
        .execute(&state.db).await?;

    Ok(Json(cred))
}

async fn delete_totp(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let r = sqlx::query(
        "DELETE FROM totp_credentials WHERE id=$1 AND user_id=$2"
    ).bind(id).bind(auth.user_id).execute(&state.db).await?;

    if r.rows_affected() == 0 { return Err(AppError::NotFound) }
    Ok(Json(serde_json::json!({ "deleted": true })))
}

// ── Parser otpauth:// ─────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ParseRequest {
    pub otpauth_url: String,
}

#[derive(Serialize)]
pub struct ParsedOTPAuth {
    pub issuer:     Option<String>,
    pub account:    Option<String>,
    pub secret_b32: String,
    pub algorithm:  String,
    pub digits:     u32,
    pub period:     u32,
}

async fn parse_otpauth(
    Json(req): Json<ParseRequest>,
) -> Result<Json<ParsedOTPAuth>> {
    let url = req.otpauth_url.trim();
    if !url.starts_with("otpauth://totp/") {
        return Err(AppError::Validation("URL otpauth inválida".into()))
    }

    let rest  = &url["otpauth://totp/".len()..];
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = url_decode(label);

    let (issuer_label, account) = if let Some((i, a)) = label.split_once(':') {
        (Some(i.trim().to_string()), a.trim().to_string())
    } else {
        (None, label)
    };

    let mut secret    = String::new();
    let mut issuer    = issuer_label;
    let mut algorithm = "SHA1".to_string();
    let mut digits    = 6u32;
    let mut period    = 30u32;

    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            let v = url_decode(v);
            match k {
                "secret"    => secret    = v,
                "issuer"    => issuer    = Some(v),
                "algorithm" => algorithm = v,
                "digits"    => digits    = v.parse().unwrap_or(6),
                "period"    => period    = v.parse().unwrap_or(30),
                _ => {}
            }
        }
    }

    if secret.is_empty() {
        return Err(AppError::Validation("Falta el campo secret".into()))
    }

    Ok(Json(ParsedOTPAuth {
        issuer,
        account: if account.is_empty() { None } else { Some(account) },
        secret_b32: secret,
        algorithm,
        digits,
        period,
    }))
}

fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars  = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            if let Ok(b) = u8::from_str_radix(&format!("{}{}", h1, h2), 16) {
                result.push(b as char);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}
