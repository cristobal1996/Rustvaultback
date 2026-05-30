// src/models.rs — modelos del nuevo esquema sin vaults

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::JsonValue;
use uuid::Uuid;

// ── Usuario ───────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct User {
    pub id:                        Uuid,
    pub email:                     String,
    pub password_hash:             String,
    pub srp_salt:                  String,
    pub srp_verifier:              String,
    pub totp_secret:               Option<JsonValue>,
    pub totp_enabled:              bool,
    pub totp_backup_codes:         Option<JsonValue>,
    pub pub_key:                   Option<String>,
    pub encrypted_priv_key:        Option<JsonValue>,
    pub invite_code:               Option<String>,
    pub emergency_code_hash:       Option<String>,
    pub auto_lock_minutes:         i32,
    pub require_2fa_on_new_device: bool,
    pub created_at:                DateTime<Utc>,
    pub last_login_at:             Option<DateTime<Utc>>,
    pub deleted_at:                Option<DateTime<Utc>>,
    pub recovery_blob:             Option<JsonValue>,
}

#[derive(Debug, Serialize)]
pub struct UserPublic {
    pub id:                  Uuid,
    pub email:               String,
    pub totp_enabled:        bool,
    pub auto_lock_minutes:   i32,
    pub invite_code:         Option<String>,
    pub pub_key:             Option<String>,
    pub encrypted_priv_key:  Option<JsonValue>,
    pub recovery_blob:       Option<JsonValue>,
    pub created_at:          DateTime<Utc>,
}

impl From<User> for UserPublic {
    fn from(u: User) -> Self {
        Self {
            id:                  u.id,
            email:               u.email,
            totp_enabled:        u.totp_enabled,
            auto_lock_minutes:   u.auto_lock_minutes,
            invite_code:         u.invite_code,
            pub_key:             u.pub_key,
            encrypted_priv_key:  u.encrypted_priv_key,
            recovery_blob:       u.recovery_blob.clone().map(|_| serde_json::json!(true)), // solo indicar si existe
            created_at:          u.created_at,
        }
    }
}

// ── Dispositivo ───────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Device {
    pub id:                 Uuid,
    pub user_id:            Uuid,
    pub name:               String,
    pub platform:           String,
    pub is_trusted:         bool,
    pub device_fingerprint: Option<String>,
    pub last_seen_at:       Option<DateTime<Utc>>,
    pub created_at:         DateTime<Utc>,
}

// ── Sesión ────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct Session {
    pub id:         Uuid,
    pub user_id:    Uuid,
    pub device_id:  Option<Uuid>,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

// ── Contraseña ────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Password {
    pub id:          Uuid,
    pub user_id:     Uuid,
    pub title:       String,
    pub domain:      Option<String>,
    pub entry_type:  String,
    pub favicon_url: Option<String>,
    pub encrypted:   JsonValue,
    pub version:     i32,
    pub is_deleted:  bool,
    pub deleted_at:  Option<DateTime<Utc>>,
    pub created_at:  DateTime<Utc>,
    pub updated_at:  DateTime<Utc>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct PasswordVersion {
    pub id:          Uuid,
    pub password_id: Uuid,
    pub version:     i32,
    pub encrypted:   JsonValue,
    pub changed_at:  DateTime<Utc>,
}

// ── TOTP ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TotpCredential {
    pub id:               Uuid,
    pub user_id:          Uuid,
    pub issuer:           Option<String>,
    pub account:          Option<String>,
    pub encrypted_secret: JsonValue,
    pub algorithm:        String,
    pub digits:           i32,
    pub period:           i32,
    pub created_at:       DateTime<Utc>,
    pub updated_at:       DateTime<Utc>,
}

// ── Generador ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct GeneratorProfile {
    pub id:                Uuid,
    pub user_id:           Uuid,
    pub name:              String,
    pub is_default:        bool,
    pub length:            i32,
    pub use_uppercase:     bool,
    pub use_lowercase:     bool,
    pub use_digits:        bool,
    pub use_symbols:       bool,
    pub symbols_allowed:   String,
    pub exclude_ambiguous: bool,
    pub min_uppercase:     i32,
    pub min_digits:        i32,
    pub min_symbols:       i32,
    pub use_passphrase:    bool,
    pub word_count:        i32,
    pub word_separator:    String,
    pub created_at:        DateTime<Utc>,
    pub updated_at:        DateTime<Utc>,
}

// ── Contraseña compartida ─────────────────────────────────────────

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SharedPassword {
    pub id:                      Uuid,
    pub password_id:             Uuid,
    pub sender_id:               Uuid,
    pub recipient_id:            Uuid,
    pub encrypted_for_recipient: JsonValue,
    pub title_hint:              Option<String>,
    pub message:                 Option<String>,
    pub permission:              String,
    pub status:                  String,
    pub expires_at:              DateTime<Utc>,
    pub created_at:              DateTime<Utc>,
    pub responded_at:            Option<DateTime<Utc>>,
}

// ── Audit log ─────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct AuditLog {
    pub id:         Uuid,
    pub user_id:    Option<Uuid>,
    pub device_id:  Option<Uuid>,
    pub action:     String,
    pub metadata:   Option<JsonValue>,
    pub created_at: DateTime<Utc>,
}
