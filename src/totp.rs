// src/totp.rs
//
// Implementación completa de TOTP (RFC 6238) usando totp-rs.
//
// Flujo de setup:
//   1. POST /api/auth/2fa/setup   → genera secret + QR + backup codes
//   2. Usuario escanea QR en Google Authenticator / Authy
//   3. POST /api/auth/2fa/confirm → verifica que el código es correcto
//                                   guarda secret cifrado en BD
//
// Flujo de login con 2FA activo:
//   1. POST /api/auth/login       → verifica contraseña
//   2. Si totp_enabled=true       → requiere totp_code en el mismo request
//   3. Se descifra el secret con la MUK y se verifica el código
//
// Backup codes:
//   - 8 códigos de un solo uso generados en el setup
//   - Se hashean con Argon2id antes de guardar
//   - Si se usa uno, se marca como used=true

use anyhow::Result;
use serde::{Deserialize, Serialize};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::crypto::{self, EncryptedBlob, SecretKey};

// ── Configuración TOTP ────────────────────────────────────────────

const TOTP_DIGITS: u8 = 6;
const TOTP_STEP:   u64 = 30;   // segundos por código
const TOTP_SKEW:   u8 = 1;     // ventana de tolerancia: ±1 paso (±30s)
const APP_NAME:    &str = "VaultApp";

// ── Structs ───────────────────────────────────────────────────────

/// Datos devueltos al cliente durante el setup
#[derive(Serialize)]
pub struct TotpSetupData {
    pub otpauth_url:  String,       // para generar el QR en el cliente
    pub manual_key:   String,       // para entrada manual en el autenticador
    pub backup_codes: Vec<String>,  // 8 códigos en claro — mostrar UNA sola vez
}

/// Lo que se guarda en BD (todo cifrado)
#[derive(Serialize, Deserialize)]
pub struct TotpStorageData {
    pub encrypted_secret:       serde_json::Value,  // secret cifrado con MUK
    pub encrypted_backup_codes: serde_json::Value,  // [{hash, used}] cifrado con MUK
}

/// Un backup code tal como se almacena en el JSON cifrado
#[derive(Serialize, Deserialize, Clone)]
pub struct BackupCode {
    pub hash: String,   // Argon2id del código
    pub used: bool,
}

// ── Setup ─────────────────────────────────────────────────────────

/// Genera un nuevo secret TOTP, la URL para el QR y 8 backup codes.
/// El secret se devuelve en claro para que el CLIENTE lo cifre con su MUK
/// antes de enviarlo al servidor. El servidor nunca ve el secret en claro.
pub fn generate_setup(email: &str) -> Result<(String, TotpSetupData)> {
    // Secret de 160 bits (20 bytes) — recomendado por RFC 4226
    let secret_bytes = crypto::random_hex(20);
    let secret_b32 = base32_encode(
        &hex::decode(&secret_bytes)?
    );

    // Construir la URL otpauth:// estándar
    // Compatible con Google Authenticator, Authy, Bitwarden, etc.
    let otpauth_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        APP_NAME,
        urlenccode(email),
        secret_b32,
        APP_NAME,
        TOTP_DIGITS,
        TOTP_STEP,
    );

    // 8 backup codes de 10 caracteres alfanuméricos en claro
    let backup_codes: Vec<String> = (0..8)
        .map(|_| generate_backup_code())
        .collect();

    Ok((
        secret_bytes.clone(), // secret en claro — el cliente lo cifra
        TotpSetupData {
            otpauth_url,
            manual_key: secret_b32,
            backup_codes,
        }
    ))
}

// ── Verificación de código TOTP ───────────────────────────────────

/// Verifica un código TOTP de 6 dígitos contra el secret en claro.
/// Acepta el código del paso anterior y siguiente (TOTP_SKEW=1)
/// para tolerar pequeñas diferencias de reloj.
pub fn verify_code(secret_hex: &str, code: &str) -> Result<bool> {
    let secret_bytes = hex::decode(secret_hex)?;
    let secret_b32 = base32_encode(&secret_bytes);

    let totp = TOTP::new(
        Algorithm::SHA1,
        TOTP_DIGITS as usize,
        TOTP_SKEW,
        TOTP_STEP,
        Secret::Encoded(secret_b32).to_bytes()
            .map_err(|e| anyhow::anyhow!("TOTP secret error: {:?}", e))?,
    ).map_err(|e| anyhow::anyhow!("TOTP error: {:?}", e))?;

    Ok(totp.check_current(code)
        .map_err(|e| anyhow::anyhow!("TOTP check error: {:?}", e))?)
}

// ── Verificación con secret cifrado ──────────────────────────────

/// Descifra el secret con la MUK del usuario y verifica el código.
/// Esta es la función que se llama en el login cuando totp_enabled=true.
pub fn verify_code_encrypted(
    encrypted_secret: &serde_json::Value,
    muk: &SecretKey,
    code: &str,
) -> Result<bool> {
    let blob = EncryptedBlob::from_json(encrypted_secret)
        .ok_or_else(|| anyhow::anyhow!("blob TOTP malformado"))?;

    // Descifrar el secret con la MUK — ocurre en el servidor solo durante login
    let secret_bytes = crypto::decrypt(&blob, muk)?;
    let secret_hex = hex::encode(&secret_bytes);

    verify_code(&secret_hex, code)
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
/// Parámetros más ligeros que para contraseñas — los backup codes
/// son largos y aleatorios, no susceptibles a diccionario.
pub fn hash_backup_code(code: &str) -> Result<String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let mut salt = [0u8; 16];
    use aes_gcm::aead::OsRng;
    use rand::RngCore;
    OsRng.fill_bytes(&mut salt);

    let params = Params::new(8192, 1, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params: {:?}", e))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = [0u8; 32];
    argon2.hash_password_into(code.as_bytes(), &salt, &mut hash)
        .map_err(|e| anyhow::anyhow!("Argon2 hash: {:?}", e))?;

    Ok(format!("{}${}", hex::encode(salt), hex::encode(hash)))
}

/// Verifica un backup code contra su hash almacenado.
pub fn verify_backup_code(code: &str, stored_hash: &str) -> bool {
    use argon2::{Algorithm, Argon2, Params, Version};

    let parts: Vec<&str> = stored_hash.splitn(2, '$').collect();
    if parts.len() != 2 { return false; }

    let Ok(salt) = hex::decode(parts[0]) else { return false; };
    let Ok(expected) = hex::decode(parts[1]) else { return false; };

    let Ok(params) = Params::new(8192, 1, 1, Some(32)) else { return false; };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut actual = [0u8; 32];
    if argon2.hash_password_into(code.as_bytes(), &salt, &mut actual).is_err() {
        return false;
    }

    // Tiempo constante
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Prepara los backup codes para almacenamiento:
/// hashea cada uno y construye el JSON que se cifrará con la MUK.
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
    // Base32 estándar (RFC 4648) sin padding
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;

    for &byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
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

fn urlenccode(s: &str) -> String {
    s.chars().map(|c| match c {
        'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
        '@' => "%40".to_string(),
        _ => format!("%{:02X}", c as u32),
    }).collect()
}
