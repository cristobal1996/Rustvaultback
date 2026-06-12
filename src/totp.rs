// src/totp.rs
//
// Implementación de TOTP (RFC 6238) usando totp-rs.
//
// MODELO DE SEGURIDAD:
// El secret TOTP se almacena en BD en formato hex sin cifrar con MUK.
// Este es un compromiso intencional con el modelo zero-knowledge:
// para validar el código en el login, el servidor necesita el secret
// (no puede recibir la MUK del cliente sin romper zero-knowledge en
// otros aspectos). Esto es coherente con la práctica industrial:
// Bitwarden, 1Password y AWS hacen lo mismo.
//
// El resto del modelo zero-knowledge se mantiene intacto:
//   - Las contraseñas guardadas siguen cifradas con MUK
//   - Las claves privadas X25519 siguen cifradas con MUK
//   - Los TOTP de servicios externos (totp_credentials) siguen cifrados con MUK
//
// Flujo de setup:
//   1. POST /api/auth/2fa/setup    → genera secret + QR + backup codes
//   2. Usuario escanea QR en su app autenticadora
//   3. POST /api/auth/2fa/confirm  → usuario envía un código de prueba
//                                    si es correcto, se guarda el secret
//
// Flujo de login con 2FA activo:
//   1. POST /api/auth/login        → verifica contraseña
//   2. Si totp_enabled=true        → responde requires_2fa=true
//   3. POST /api/auth/login        → segunda llamada con el código
//   4. Servidor valida con totp-rs directamente

use anyhow::Result;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, TOTP};

// ── Configuración TOTP ────────────────────────────────────────────

const TOTP_DIGITS: usize = 6;
const TOTP_STEP:   u64 = 30;   // segundos por código
const TOTP_SKEW:   u8 = 1;     // ventana de tolerancia: ±1 paso (±30s)
const APP_NAME:    &str = "RustVault";

// ── Structs ───────────────────────────────────────────────────────

/// Datos del setup que devolvemos al cliente
#[derive(Serialize)]
pub struct TotpSetupData {
    pub secret_hex:   String,       // secret en hex (el cliente lo manda en confirm)
    pub otpauth_url:  String,       // para generar el QR
    pub manual_key:   String,       // base32 para entrada manual
    pub backup_codes: Vec<String>,  // 8 códigos — mostrar UNA sola vez
}

/// Un backup code tal como se almacena en el JSON
#[derive(Serialize, Deserialize, Clone)]
#[allow(dead_code)]
pub struct BackupCode {
    pub hash: String,   // Argon2id del código
    pub used: bool,
}

// ── Setup ─────────────────────────────────────────────────────────

/// Genera un nuevo secret TOTP, la URL para el QR y 8 backup codes.
pub fn generate_setup(email: &str) -> Result<TotpSetupData> {
    // Secret de 160 bits (20 bytes) — recomendado por RFC 4226
    let secret_hex   = crate::crypto::random_hex(20);
    let secret_bytes = hex::decode(&secret_hex)?;
    let secret_b32   = base32_encode(&secret_bytes);

    // URL otpauth estándar — compatible con Google Authenticator, Authy, etc.
    let otpauth_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        APP_NAME,
        urlencode(email),
        secret_b32,
        APP_NAME,
        TOTP_DIGITS,
        TOTP_STEP,
    );

    // 8 backup codes alfanuméricos sin ambigüedades
    let backup_codes: Vec<String> = (0..8)
        .map(|_| generate_backup_code())
        .collect();

    Ok(TotpSetupData {
        secret_hex,
        otpauth_url,
        manual_key: secret_b32,
        backup_codes,
    })
}

// ── Verificación de código TOTP ───────────────────────────────────

/// Verifica un código TOTP de 6 dígitos contra el secret en hex.
/// Acepta el código del paso anterior y siguiente (TOTP_SKEW=1)
/// para tolerar pequeñas diferencias de reloj.
pub fn verify_code(secret_hex: &str, code: &str) -> Result<bool> {
    let secret_bytes = hex::decode(secret_hex)?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS,
        TOTP_SKEW,
        TOTP_STEP,
        secret_bytes,
    ).map_err(|e| anyhow::anyhow!("TOTP error: {:?}", e))?;

    Ok(totp.check_current(code)
        .map_err(|e| anyhow::anyhow!("TOTP check error: {:?}", e))?)
}

// ── Backup codes ──────────────────────────────────────────────────

/// Genera un backup code de 10 caracteres (sin ambigüedades: sin 0,O,1,I,l)
fn generate_backup_code() -> String {
    let charset: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let mut bytes = vec![0u8; 10];
    use aes_gcm::aead::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut bytes);

    bytes.iter()
        .map(|b| charset[*b as usize % charset.len()])
        .collect()
}

/// Hashea un backup code con Argon2id para almacenamiento seguro.
pub fn hash_backup_code(code: &str) -> Result<String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let mut salt = [0u8; 16];
    use aes_gcm::aead::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut salt);

    let params = Params::new(8192, 1, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params: {:?}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut hash = [0u8; 32];
    argon2.hash_password_into(code.as_bytes(), &salt, &mut hash)
        .map_err(|e| anyhow::anyhow!("Argon2 hash: {:?}", e))?;

    Ok(format!("{}${}", hex::encode(salt), hex::encode(hash)))
}

/// Verifica un backup code contra su hash almacenado.
#[allow(dead_code)]
pub fn verify_backup_code(code: &str, stored_hash: &str) -> bool {
    use argon2::{Algorithm, Argon2, Params, Version};

    let parts: Vec<&str> = stored_hash.splitn(2, '$').collect();
    if parts.len() != 2 { return false; }

    let Ok(salt)     = hex::decode(parts[0]) else { return false; };
    let Ok(expected) = hex::decode(parts[1]) else { return false; };

    let Ok(params) = Params::new(8192, 1, 1, Some(32)) else { return false; };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut actual = [0u8; 32];
    if argon2.hash_password_into(code.as_bytes(), &salt, &mut actual).is_err() {
        return false;
    }

    // Comparación en tiempo constante
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Prepara los backup codes para almacenamiento:
/// hashea cada uno y construye el JSON.
pub fn prepare_backup_codes(codes: &[String]) -> Result<serde_json::Value> {
    let hashed: Result<Vec<_>> = codes.iter().map(|code| {
        Ok(serde_json::json!({
            "hash": hash_backup_code(code)?,
            "used": false,
        }))
    }).collect();

    Ok(serde_json::Value::Array(hashed?))
}

// ── Utilidades ────────────────────────────────────────────────────

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

fn urlencode(s: &str) -> String {
    s.chars().map(|c| match c {
        'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
        '@' => "%40".to_string(),
        _ => format!("%{:02X}", c as u32),
    }).collect()
}
