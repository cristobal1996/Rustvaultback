// client/crypto.ts
// Tipos y funciones criptográficas base usadas por todos los módulos

// ── Tipos ─────────────────────────────────────────────────────────

export interface EncryptedBlob {
  nonce:      string  // hex, 12 bytes
  ciphertext: string  // hex, datos + auth tag
}

export interface ECIESBlob {
  ephemeral_pub: string  // hex, 32 bytes
  nonce:         string  // hex, 12 bytes
  ciphertext:    string  // hex
}

// ── AES-256-GCM ───────────────────────────────────────────────────

export async function encryptAESGCM(
  plaintext: Uint8Array,
  key:       Uint8Array
): Promise<EncryptedBlob> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "AES-GCM" }, false, ["encrypt"]
  )
  const nonce      = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, cryptoKey, plaintext
  )
  return {
    nonce:      bytesToHex(nonce),
    ciphertext: bytesToHex(new Uint8Array(ciphertext)),
  }
}

export async function decryptAESGCM(
  blob: EncryptedBlob,
  key:  Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw", key, { name: "AES-GCM" }, false, ["decrypt"]
  )
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: hexToBytes(blob.nonce) },
    cryptoKey,
    hexToBytes(blob.ciphertext)
  )
  return new Uint8Array(plaintext)
}

// ── Utilidades ────────────────────────────────────────────────────

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

export function generateRandomHex(byteCount: number): string {
  const arr = new Uint8Array(byteCount)
  crypto.getRandomValues(arr)
  return bytesToHex(arr)
}
