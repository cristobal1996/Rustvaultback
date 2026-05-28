// src/crypto_asymmetric.rs
//
// Criptografía asimétrica para vaults compartidos.
// Algoritmo: X25519 (ECDH) + AES-256-GCM
//
// ¿Por qué X25519?
//   - Diseñado por Daniel J. Bernstein — resistente a ataques de canal lateral
//   - Claves compactas: 32 bytes (vs 256+ bytes de RSA-2048)
//   - Sin parámetros que configurar mal (a diferencia de RSA/ECDSA)
//   - Usado por WhatsApp, Signal, WireGuard, TLS 1.3
//
// Flujo ECIES (Elliptic Curve Integrated Encryption Scheme):
//   Cifrar para Bob:
//     1. Generar par efímero (ephemeral_priv, ephemeral_pub)
//     2. shared_secret = ECDH(ephemeral_priv, bob_pub)
//     3. key = HKDF(shared_secret) → 32 bytes
//     4. ciphertext = AES-256-GCM(plaintext, key, nonce)
//     5. Enviar: { ephemeral_pub, nonce, ciphertext }
//
//   Descifrar (Bob):
//     1. shared_secret = ECDH(bob_priv, ephemeral_pub)
//     2. key = HKDF(shared_secret) → 32 bytes
//     3. plaintext = AES-256-GCM-Decrypt(ciphertext, key, nonce)

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// ── Tipos ─────────────────────────────────────────────────────────

/// Par de claves X25519 del usuario.
/// priv_key se borra de memoria automáticamente al hacer drop.
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    pub pub_key:  [u8; 32],
    priv_key:     [u8; 32],
}

impl KeyPair {
    /// Genera un nuevo par de claves X25519 aleatorio.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            pub_key:  public.to_bytes(),
            priv_key: secret.to_bytes(),
        }
    }

    pub fn pub_key_hex(&self) -> String {
        hex::encode(self.pub_key)
    }

    pub fn priv_key_bytes(&self) -> &[u8; 32] {
        &self.priv_key
    }
}

/// Blob cifrado con ECIES (para transferir la Vault Key entre usuarios).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECIESBlob {
    pub ephemeral_pub: String,  // hex, 32 bytes — clave pública efímera
    pub nonce:         String,  // hex, 12 bytes
    pub ciphertext:    String,  // hex — Vault Key cifrada + auth tag
}

impl ECIESBlob {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ephemeral_pub": self.ephemeral_pub,
            "nonce":         self.nonce,
            "ciphertext":    self.ciphertext,
        })
    }

    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        Some(Self {
            ephemeral_pub: v["ephemeral_pub"].as_str()?.to_string(),
            nonce:         v["nonce"].as_str()?.to_string(),
            ciphertext:    v["ciphertext"].as_str()?.to_string(),
        })
    }
}

// ── ECIES Cifrado ─────────────────────────────────────────────────

/// Cifra `plaintext` para el destinatario con pub_key_hex.
/// Solo el poseedor de la clave privada correspondiente puede descifrar.
///
/// Se usa para transferir la Vault Key de Alice a Bob:
///   encrypt_for_recipient(vault_key, bob_pub_key)
pub fn encrypt_for_recipient(
    plaintext: &[u8],
    recipient_pub_hex: &str,
) -> anyhow::Result<ECIESBlob> {
    // 1. Parsear clave pública del destinatario
    let pub_bytes = hex::decode(recipient_pub_hex)?;
    if pub_bytes.len() != 32 {
        anyhow::bail!("Clave pública inválida: debe ser 32 bytes");
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let recipient_pub = PublicKey::from(pub_arr);

    // 2. Generar par efímero — se usa una sola vez, luego se descarta
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pub    = PublicKey::from(&ephemeral_secret);

    // 3. ECDH: shared_secret = ephemeral_priv × recipient_pub
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);

    // 4. Derivar clave AES de 32 bytes desde el shared_secret con HKDF
    let aes_key = hkdf_derive(shared_secret.as_bytes())?;

    // 5. Cifrar con AES-256-GCM
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce   = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Cifrado ECIES fallido: {}", e))?;

    Ok(ECIESBlob {
        ephemeral_pub: hex::encode(ephemeral_pub.as_bytes()),
        nonce:         hex::encode(nonce),
        ciphertext:    hex::encode(ciphertext),
    })
}

/// Descifra un ECIESBlob usando la clave privada del destinatario.
///
/// Bob usa esto para obtener la Vault Key que Alice le envió:
///   decrypt_with_private_key(blob, bob_priv_key)
pub fn decrypt_with_private_key(
    blob: &ECIESBlob,
    priv_key_bytes: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    // 1. Reconstruir la clave pública efímera del emisor
    let eph_bytes = hex::decode(&blob.ephemeral_pub)?;
    if eph_bytes.len() != 32 {
        anyhow::bail!("ephemeral_pub inválido");
    }
    let mut eph_arr = [0u8; 32];
    eph_arr.copy_from_slice(&eph_bytes);
    let ephemeral_pub = PublicKey::from(eph_arr);

    // 2. ECDH: shared_secret = recipient_priv × ephemeral_pub
    let recipient_secret = StaticSecret::from(*priv_key_bytes);
    let shared_secret    = recipient_secret.diffie_hellman(&ephemeral_pub);

    // 3. Derivar la misma clave AES
    let aes_key = hkdf_derive(shared_secret.as_bytes())?;

    // 4. Descifrar
    let cipher     = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce_bytes = hex::decode(&blob.nonce)?;
    let nonce       = Nonce::from_slice(&nonce_bytes);
    let ciphertext  = hex::decode(&blob.ciphertext)?;

    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Descifrado ECIES fallido: clave incorrecta o blob modificado"))
}

// ── HKDF ─────────────────────────────────────────────────────────

/// Deriva 32 bytes seguros desde un shared_secret usando HKDF-SHA256.
/// Necesario porque el output de ECDH no es directamente una clave AES —
/// puede tener sesgos. HKDF lo normaliza en una clave uniforme.
fn hkdf_derive(shared_secret: &[u8]) -> anyhow::Result<[u8; 32]> {
    use sha2::Sha256;
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"vault-key-sharing-v1", &mut key)
        .map_err(|e| anyhow::anyhow!("HKDF error: {}", e))?;
    Ok(key)
}

// ── Utilidades para el servidor ───────────────────────────────────

/// Verifica que una clave pública X25519 tiene el formato correcto.
pub fn validate_pub_key(pub_key_hex: &str) -> bool {
    hex::decode(pub_key_hex)
        .map(|b| b.len() == 32)
        .unwrap_or(false)
}
