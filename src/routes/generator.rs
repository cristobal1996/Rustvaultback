// src/routes/generator.rs
use axum::{extract::State, routing::{get, post, put, delete}, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use rand::RngCore;
use aes_gcm::aead::OsRng;

use crate::{errors::Result, middleware::AuthUser, models::GeneratorProfile, state::AppState};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/profiles",      get(list_profiles).post(create_profile))
        .route("/profiles/:id",  put(update_profile).delete(delete_profile))
        .route("/generate",      post(generate_password))
}

async fn list_profiles(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<GeneratorProfile>>> {
    let profiles = sqlx::query_as::<_, GeneratorProfile>(
        "SELECT * FROM generator_profiles WHERE user_id = $1 ORDER BY is_default DESC, name"
    )
    .bind(auth.user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(profiles))
}

#[derive(Deserialize)]
pub struct CreateProfileRequest {
    name:             String,
    is_default:       Option<bool>,
    length:           Option<i32>,
    use_uppercase:    Option<bool>,
    use_lowercase:    Option<bool>,
    use_digits:       Option<bool>,
    use_symbols:      Option<bool>,
    symbols_allowed:  Option<String>,
    exclude_ambiguous: Option<bool>,
    use_passphrase:   Option<bool>,
    word_count:       Option<i32>,
    word_separator:   Option<String>,
}

async fn create_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateProfileRequest>,
) -> Result<Json<GeneratorProfile>> {
    // Si es default, quitar el default anterior
    if req.is_default.unwrap_or(false) {
        sqlx::query(
            "UPDATE generator_profiles SET is_default = false WHERE user_id = $1"
        )
        .bind(auth.user_id)
        .execute(&state.db)
        .await?;
    }

    let profile = sqlx::query_as::<_, GeneratorProfile>(
        r#"
        INSERT INTO generator_profiles
            (id, user_id, name, is_default, length, use_uppercase, use_lowercase,
             use_digits, use_symbols, symbols_allowed, exclude_ambiguous,
             use_passphrase, word_count, word_separator)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(auth.user_id)
    .bind(&req.name)
    .bind(req.is_default.unwrap_or(false))
    .bind(req.length.unwrap_or(20))
    .bind(req.use_uppercase.unwrap_or(true))
    .bind(req.use_lowercase.unwrap_or(true))
    .bind(req.use_digits.unwrap_or(true))
    .bind(req.use_symbols.unwrap_or(true))
    .bind(req.symbols_allowed.as_deref().unwrap_or("!@#$%^&*()-_=+[]{}|;:,.<>?"))
    .bind(req.exclude_ambiguous.unwrap_or(false))
    .bind(req.use_passphrase.unwrap_or(false))
    .bind(req.word_count.unwrap_or(4))
    .bind(req.word_separator.as_deref().unwrap_or("-"))
    .fetch_one(&state.db)
    .await?;

    Ok(Json(profile))
}

async fn update_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Path(profile_id): axum::extract::Path<Uuid>,
    Json(req): Json<CreateProfileRequest>,
) -> Result<Json<GeneratorProfile>> {
    if req.is_default.unwrap_or(false) {
        sqlx::query("UPDATE generator_profiles SET is_default = false WHERE user_id = $1")
            .bind(auth.user_id)
            .execute(&state.db)
            .await?;
    }

    let profile = sqlx::query_as::<_, GeneratorProfile>(
        r#"
        UPDATE generator_profiles SET
            name = $1, is_default = $2, length = $3,
            use_uppercase = $4, use_lowercase = $5, use_digits = $6,
            use_symbols = $7, symbols_allowed = $8, exclude_ambiguous = $9,
            use_passphrase = $10, word_count = $11, word_separator = $12,
            updated_at = NOW()
        WHERE id = $13 AND user_id = $14
        RETURNING *
        "#,
    )
    .bind(&req.name)
    .bind(req.is_default.unwrap_or(false))
    .bind(req.length.unwrap_or(20))
    .bind(req.use_uppercase.unwrap_or(true))
    .bind(req.use_lowercase.unwrap_or(true))
    .bind(req.use_digits.unwrap_or(true))
    .bind(req.use_symbols.unwrap_or(true))
    .bind(req.symbols_allowed.as_deref().unwrap_or("!@#$%^&*()-_=+[]{}|;:,.<>?"))
    .bind(req.exclude_ambiguous.unwrap_or(false))
    .bind(req.use_passphrase.unwrap_or(false))
    .bind(req.word_count.unwrap_or(4))
    .bind(req.word_separator.as_deref().unwrap_or("-"))
    .bind(profile_id)
    .bind(auth.user_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(profile))
}

async fn delete_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Path(profile_id): axum::extract::Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    sqlx::query("DELETE FROM generator_profiles WHERE id = $1 AND user_id = $2")
        .bind(profile_id)
        .bind(auth.user_id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

// ── Generador de contraseñas ──────────────────────────────────────

#[derive(Deserialize)]
pub struct GenerateRequest {
    profile_id:      Option<Uuid>,  // usar perfil guardado
    // O parámetros directos:
    length:          Option<i32>,
    use_uppercase:   Option<bool>,
    use_lowercase:   Option<bool>,
    use_digits:      Option<bool>,
    use_symbols:     Option<bool>,
    symbols_allowed: Option<String>,
    exclude_ambiguous: Option<bool>,
}

#[derive(Serialize)]
pub struct GenerateResponse {
    password: String,
    entropy:  f64,        // bits de entropía — útil para mostrar la fortaleza
}

async fn generate_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<GenerateRequest>,
) -> Result<Json<GenerateResponse>> {
    // Si se especifica un perfil, cargamos su configuración
    let (length, uppercase, lowercase, digits, symbols, syms_allowed, exclude_ambiguous) =
    if let Some(profile_id) = req.profile_id {
        let p = sqlx::query_as::<_, GeneratorProfile>(
            "SELECT * FROM generator_profiles WHERE id = $1 AND user_id = $2"
        )
        .bind(profile_id)
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(crate::errors::AppError::NotFound)?;

        (p.length, p.use_uppercase, p.use_lowercase, p.use_digits,
         p.use_symbols, p.symbols_allowed, p.exclude_ambiguous)
    } else {
        (
            req.length.unwrap_or(20),
            req.use_uppercase.unwrap_or(true),
            req.use_lowercase.unwrap_or(true),
            req.use_digits.unwrap_or(true),
            req.use_symbols.unwrap_or(true),
            req.symbols_allowed.unwrap_or_else(|| "!@#$%^&*()-_=+".into()),
            req.exclude_ambiguous.unwrap_or(false),
        )
    };

    let password = generate(length as usize, uppercase, lowercase, digits, symbols,
                            &syms_allowed, exclude_ambiguous);
    let charset_size = charset_size(uppercase, lowercase, digits, symbols, syms_allowed.len());
    let entropy = (length as f64) * (charset_size as f64).log2();

    Ok(Json(GenerateResponse { password, entropy }))
}

fn generate(
    length: usize,
    uppercase: bool, lowercase: bool,
    digits: bool, symbols: bool,
    syms_allowed: &str,
    exclude_ambiguous: bool,
) -> String {
    let ambiguous = "0O1lI";
    let mut charset = String::new();

    if uppercase { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if lowercase { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
    if digits    { charset.push_str("0123456789"); }
    if symbols   { charset.push_str(syms_allowed); }

    if exclude_ambiguous {
        charset = charset.chars().filter(|c| !ambiguous.contains(*c)).collect();
    }

    if charset.is_empty() { charset = "abcdefghijklmnopqrstuvwxyz".into(); }

    let chars: Vec<char> = charset.chars().collect();
    let mut result = Vec::with_capacity(length);
    let mut rng_bytes = vec![0u8; length * 4];
    OsRng.fill_bytes(&mut rng_bytes);

    for i in 0..length {
        let idx = u32::from_le_bytes([
            rng_bytes[i*4], rng_bytes[i*4+1], rng_bytes[i*4+2], rng_bytes[i*4+3]
        ]) as usize % chars.len();
        result.push(chars[idx]);
    }

    result.into_iter().collect()
}

fn charset_size(up: bool, low: bool, dig: bool, sym: bool, sym_len: usize) -> usize {
    let mut n = 0;
    if up  { n += 26; }
    if low { n += 26; }
    if dig { n += 10; }
    if sym { n += sym_len; }
    n.max(1)
}
