#![allow(dead_code)]

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Tipos ─────────────────────────────────────────────────────────

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Some(Self(arr))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce:      String,
    pub ciphertext: String,
}

impl EncryptedBlob {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "nonce": self.nonce, "ciphertext": self.ciphertext })
    }

    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        Some(Self {
            nonce:      v["nonce"].as_str()?.to_string(),
            ciphertext: v["ciphertext"].as_str()?.to_string(),
        })
    }
}

// ── AES-256-GCM ───────────────────────────────────────────────────

pub fn encrypt(plaintext: &[u8], key: &SecretKey) -> anyhow::Result<EncryptedBlob> {
    let cipher     = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce      = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Cifrado AES-GCM fallido: {}", e))?;
    Ok(EncryptedBlob { nonce: hex::encode(nonce), ciphertext: hex::encode(ciphertext) })
}

pub fn decrypt(blob: &EncryptedBlob, key: &SecretKey) -> anyhow::Result<Vec<u8>> {
    let cipher      = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce_bytes = hex::decode(&blob.nonce)?;
    let nonce       = Nonce::from_slice(&nonce_bytes);
    let ciphertext  = hex::decode(&blob.ciphertext)?;
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Descifrado fallido: blob modificado o clave incorrecta"))
}

// ── Argon2id ──────────────────────────────────────────────────────

fn make_argon2() -> anyhow::Result<(Argon2<'static>, Params)> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params error: {:?}", e))?;
    Ok((Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone()), params))
}

pub fn derive_muk(
    master_password: &str,
    secret_key:      &str,
    salt_hex:        &str,
) -> anyhow::Result<SecretKey> {
    let salt            = hex::decode(salt_hex)?;
    let mut combined    = format!("{}:{}", master_password, secret_key);
    let (argon2, _)     = make_argon2()?;
    let mut muk_bytes   = [0u8; 32];
    argon2.hash_password_into(combined.as_bytes(), &salt, &mut muk_bytes)
        .map_err(|e| anyhow::anyhow!("Argon2 derive_muk error: {:?}", e))?;
    combined.zeroize();
    Ok(SecretKey(muk_bytes))
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let mut salt    = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let (argon2, _) = make_argon2()?;
    let mut hash    = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut hash)
        .map_err(|e| anyhow::anyhow!("Argon2 hash_password error: {:?}", e))?;
    Ok(format!("{}${}", hex::encode(salt), hex::encode(hash)))
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    let parts: Vec<&str> = stored.splitn(2, '$').collect();
    if parts.len() != 2 { return false; }
    let Ok(salt)     = hex::decode(parts[0]) else { return false; };
    let Ok(expected) = hex::decode(parts[1]) else { return false; };
    let Ok((argon2, _)) = make_argon2() else { return false; };
    let mut actual = [0u8; 32];
    if argon2.hash_password_into(password.as_bytes(), &salt, &mut actual).is_err() {
        return false;
    }
    use std::hint::black_box;
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(expected.iter()) {
        diff |= black_box(a ^ b);
    }
    diff == 0
}

// ── Utilidades ────────────────────────────────────────────────────

pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
