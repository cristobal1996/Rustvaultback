// client/sharing-client.ts
// Criptografía asimétrica para vaults compartidos (X25519 + ECIES)

import {
  encryptAESGCM,
  decryptAESGCM,
  bytesToHex,
  hexToBytes,
  generateRandomHex,
  type EncryptedBlob,
  type ECIESBlob,
} from "./crypto"

// ── Tipos ─────────────────────────────────────────────────────────

export interface KeyPair {
  pubKeyHex:     string
  privKeyBytes:  Uint8Array
}

export interface VaultMember {
  user_id:   string
  email:     string
  pub_key:   string
  role:      string
  joined_at: string
}

export interface PendingInvitation {
  id:                  string
  vault_id:            string
  vault_name:          string
  invited_by_email:    string
  role:                string
  expires_at:          string
  encrypted_vault_key: ECIESBlob
  encrypted_priv_key:  EncryptedBlob | null
}

// ── Par de claves X25519 ──────────────────────────────────────────

/**
 * Genera un par de claves X25519.
 * La clave pública se sube al servidor.
 * La privada se cifra con la MUK antes de subirla.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveKey"]
  )

  const pubKeyRaw  = await crypto.subtle.exportKey("raw",   keyPair.publicKey)
  const privKeyRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)

  return {
    pubKeyHex:    bytesToHex(new Uint8Array(pubKeyRaw)),
    privKeyBytes: new Uint8Array(privKeyRaw),
  }
}

/**
 * Registra la clave pública en el servidor y sube la privada cifrada.
 */
export async function setupKeyPair(
  muk:      Uint8Array,
  apiToken: string
): Promise<KeyPair> {
  const keyPair          = await generateKeyPair()
  const encryptedPrivKey = await encryptAESGCM(keyPair.privKeyBytes, muk)

  const res = await fetch("/api/sharing/keys", {
    method:  "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${apiToken}`,
    },
    body: JSON.stringify({
      pub_key:            keyPair.pubKeyHex,
      encrypted_priv_key: encryptedPrivKey,
    }),
  })

  if (!res.ok) throw new Error(await res.text())
  return keyPair
}

// ── ECIES: cifrado para un destinatario ──────────────────────────

/**
 * Cifra datos para el destinatario con su clave pública X25519.
 * Solo el poseedor de la clave privada puede descifrar.
 */
export async function eciesEncrypt(
  plaintext:          Uint8Array,
  recipientPubKeyHex: string
): Promise<ECIESBlob> {
  const recipientPubKey = await crypto.subtle.importKey(
    "raw",
    hexToBytes(recipientPubKeyHex),
    { name: "X25519" },
    false,
    []
  )

  // Par efímero — de un solo uso
  const ephemeralPair = await crypto.subtle.generateKey(
    { name: "X25519" }, true, ["deriveKey"]
  )

  // ECDH → clave AES compartida
  const sharedAESKey = await crypto.subtle.deriveKey(
    { name: "X25519", public: recipientPubKey },
    ephemeralPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  )

  const nonce      = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    sharedAESKey,
    plaintext
  )

  const ephemeralPubRaw = await crypto.subtle.exportKey("raw", ephemeralPair.publicKey)

  return {
    ephemeral_pub: bytesToHex(new Uint8Array(ephemeralPubRaw)),
    nonce:         bytesToHex(nonce),
    ciphertext:    bytesToHex(new Uint8Array(ciphertext)),
  }
}

/**
 * Descifra un ECIESBlob con la clave privada del destinatario.
 */
export async function eciesDecrypt(
  blob:          ECIESBlob,
  privKeyBytes:  Uint8Array
): Promise<Uint8Array> {
  const privKey = await crypto.subtle.importKey(
    "pkcs8",
    privKeyBytes,
    { name: "X25519" },
    false,
    ["deriveKey"]
  )

  const ephemeralPub = await crypto.subtle.importKey(
    "raw",
    hexToBytes(blob.ephemeral_pub),
    { name: "X25519" },
    false,
    []
  )

  const sharedAESKey = await crypto.subtle.deriveKey(
    { name: "X25519", public: ephemeralPub },
    privKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  )

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(blob.nonce) },
    sharedAESKey,
    hexToBytes(blob.ciphertext)
  )

  return new Uint8Array(plaintext)
}

// ── Invitar a un miembro ──────────────────────────────────────────

/**
 * Alice invita a Bob a su vault.
 * Descifra la Vault Key con su MUK, la cifra con la pub_key de Bob.
 */
export async function inviteMember(
  vaultId:            string,
  invitedEmail:       string,
  role:               string,
  encryptedVaultKey:  EncryptedBlob,
  aliceMUK:           Uint8Array,
  apiToken:           string
): Promise<void> {
  // Obtener pub_key de Bob
  const keyRes = await fetch(
    `/api/sharing/keys/${encodeURIComponent(invitedEmail)}`,
    { headers: { Authorization: `Bearer ${apiToken}` } }
  )
  if (!keyRes.ok) throw new Error(`${invitedEmail} no tiene clave pública registrada`)
  const { pub_key: bobPubKeyHex }: { pub_key: string } = await keyRes.json()

  // Descifrar Vault Key con MUK de Alice
  const vaultKeyBytes = await decryptAESGCM(encryptedVaultKey, aliceMUK)

  // Cifrar Vault Key con pub_key de Bob (ECIES)
  const eciesBlob = await eciesEncrypt(vaultKeyBytes, bobPubKeyHex)

  // Limpiar de memoria
  vaultKeyBytes.fill(0)

  // Enviar al servidor
  const res = await fetch("/api/sharing/invite", {
    method:  "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${apiToken}`,
    },
    body: JSON.stringify({
      vault_id:            vaultId,
      invited_email:       invitedEmail,
      role,
      encrypted_vault_key: eciesBlob,
    }),
  })

  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.error ?? "Error al enviar invitación")
  }
}

// ── Aceptar invitación ────────────────────────────────────────────

/**
 * Bob acepta la invitación.
 * Descifra su priv_key con su MUK, descifra la Vault Key con la priv_key,
 * re-cifra la Vault Key con su MUK y la sube al servidor.
 */
export async function acceptInvitation(
  invitationId:       string,
  encryptedVaultKey:  ECIESBlob,
  encryptedPrivKey:   EncryptedBlob,
  bobMUK:             Uint8Array,
  apiToken:           string
): Promise<void> {
  // Descifrar clave privada con MUK de Bob
  const privKeyBytes = await decryptAESGCM(encryptedPrivKey, bobMUK)

  // Descifrar Vault Key con la clave privada (ECIES)
  const vaultKeyBytes = await eciesDecrypt(encryptedVaultKey, privKeyBytes)

  // Limpiar clave privada
  privKeyBytes.fill(0)

  // Re-cifrar Vault Key con MUK de Bob
  const vaultKeyForMe = await encryptAESGCM(vaultKeyBytes, bobMUK)

  // Limpiar Vault Key
  vaultKeyBytes.fill(0)

  // Enviar al servidor
  const res = await fetch(`/api/sharing/accept/${invitationId}`, {
    method:  "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${apiToken}`,
    },
    body: JSON.stringify({
      vault_key_encrypted_with_muk: vaultKeyForMe,
    }),
  })

  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.error ?? "Error al aceptar invitación")
  }
}
