// client/totp-client.ts
// Generación de códigos TOTP en el navegador (RFC 6238)
// La contraseña nunca sale del dispositivo

import { decryptAESGCM, hexToBytes, bytesToHex, type EncryptedBlob } from "./crypto"

// ── Tipos ─────────────────────────────────────────────────────────

export type TOTPAlgorithm = "SHA-1" | "SHA-256" | "SHA-512"

export interface TOTPCredential {
  id:               string
  vault_id:         string
  entry_id:         string
  issuer:           string | null
  account:          string | null
  encrypted_secret: EncryptedBlob
  algorithm:        string   // "SHA1" | "SHA256" | "SHA512" (formato del servidor)
  digits:           number   // 6 u 8
  period:           number   // 30 o 60
}

export interface TOTPState {
  code:      string   // "482 916"
  remaining: number   // segundos restantes
  progress:  number   // 0.0 → 1.0
}

// ── Descifrar y generar código ────────────────────────────────────

/**
 * Descifra el secreto TOTP con la Vault Key y genera el código actual.
 */
export async function generateTOTPCode(
  credential: TOTPCredential,
  vaultKey:   Uint8Array
): Promise<string> {
  const secretBytes = await decryptAESGCM(credential.encrypted_secret, vaultKey)
  const secretB32   = bytesToBase32(secretBytes)
  const algorithm   = toWebCryptoAlg(credential.algorithm)
  return generateTOTP(secretB32, algorithm, credential.digits, credential.period)
}

/**
 * Inicia un timer que recalcula el código cada segundo.
 * Devuelve una función para detenerlo (llamar al desmontar el componente).
 */
export function startTOTPTimer(
  credential: TOTPCredential,
  vaultKey:   Uint8Array,
  onUpdate:   (state: TOTPState) => void
): () => void {
  let running = true
  const algorithm = toWebCryptoAlg(credential.algorithm)

  async function tick(): Promise<void> {
    if (!running) return

    try {
      const secretBytes = await decryptAESGCM(credential.encrypted_secret, vaultKey)
      const secretB32   = bytesToBase32(secretBytes)
      const code        = await generateTOTP(secretB32, algorithm, credential.digits, credential.period)
      const remaining   = secondsRemaining(credential.period)
      const progress    = remaining / credential.period

      // Formatear con espacio en el medio: "482 916"
      const formatted = credential.digits === 6
        ? `${code.slice(0, 3)} ${code.slice(3)}`
        : `${code.slice(0, 4)} ${code.slice(4)}`

      onUpdate({ code: formatted, remaining, progress })
    } catch (err) {
      console.error("Error generando código TOTP:", err)
    }

    setTimeout(tick, 1000)
  }

  tick()
  return () => { running = false }
}

/**
 * Segundos restantes hasta que el código actual expire.
 */
export function secondsRemaining(period: number): number {
  return period - (Math.floor(Date.now() / 1000) % period)
}

// ── Algoritmo TOTP (RFC 6238) ─────────────────────────────────────

async function generateTOTP(
  secretB32: string,
  algorithm: TOTPAlgorithm,
  digits:    number,
  period:    number
): Promise<string> {
  const secretBytes = base32Decode(secretB32)
  const counter     = Math.floor(Date.now() / 1000 / period)
  return hotp(secretBytes, counter, algorithm, digits)
}

async function hotp(
  secret:    Uint8Array,
  counter:   number,
  algorithm: TOTPAlgorithm,
  digits:    number
): Promise<string> {
  // Contador a 8 bytes big-endian
  const counterBytes = new Uint8Array(8)
  let c = counter
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff
    c = Math.floor(c / 256)
  }

  const key = await crypto.subtle.importKey(
    "raw", secret,
    { name: "HMAC", hash: algorithm },
    false, ["sign"]
  )
  const hmac  = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes))
  const offset = hmac[hmac.length - 1] & 0x0f
  const code   = (
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) <<  8) |
    ((hmac[offset + 3] & 0xff))
  )
  return String(code % Math.pow(10, digits)).padStart(digits, "0")
}

// ── Parsear URL otpauth:// ────────────────────────────────────────

export interface ParsedOTPAuth {
  issuer:     string | null
  account:    string | null
  secretB32:  string
  algorithm:  string
  digits:     number
  period:     number
}

export function parseOTPAuthURL(url: string): ParsedOTPAuth | null {
  if (!url.startsWith("otpauth://totp/")) return null

  const rest = url.slice("otpauth://totp/".length)
  const [labelEncoded, paramsStr] = rest.split("?")
  if (!paramsStr) return null

  const label = urlDecode(labelEncoded)
  let issuer:  string | null = null
  let account: string | null = null

  if (label.includes(":")) {
    const [i, a] = label.split(":", 2)
    issuer  = i.trim()
    account = a.trim()
  } else {
    account = label.trim()
  }

  let secretB32 = ""
  let algorithm = "SHA1"
  let digits    = 6
  let period    = 30

  for (const param of paramsStr.split("&")) {
    const [key, value] = param.split("=", 2)
    switch (key) {
      case "secret":    secretB32 = value.toUpperCase(); break
      case "issuer":    issuer    = urlDecode(value);    break
      case "algorithm": algorithm = value.toUpperCase(); break
      case "digits":    digits    = parseInt(value) || 6; break
      case "period":    period    = parseInt(value) || 30; break
    }
  }

  if (!secretB32) return null
  return { issuer, account, secretB32, algorithm, digits, period }
}

// ── Utilidades ────────────────────────────────────────────────────

function toWebCryptoAlg(serverAlg: string): TOTPAlgorithm {
  const map: Record<string, TOTPAlgorithm> = {
    SHA1:   "SHA-1",
    SHA256: "SHA-256",
    SHA512: "SHA-512",
  }
  return map[serverAlg] ?? "SHA-1"
}

function base32Decode(str: string): Uint8Array {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  const clean    = str.toUpperCase().replace(/=+$/, "")
  let bits    = 0
  let value   = 0
  const output: number[] = []

  for (const char of clean) {
    const idx = ALPHABET.indexOf(char)
    if (idx < 0) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return new Uint8Array(output)
}

function bytesToBase32(bytes: Uint8Array): string {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let result  = ""
  let buffer  = 0
  let bitsLeft = 0

  for (const byte of bytes) {
    buffer    = (buffer << 8) | byte
    bitsLeft += 8
    while (bitsLeft >= 5) {
      result   += ALPHABET[(buffer >>> (bitsLeft - 5)) & 31]
      bitsLeft -= 5
    }
  }
  if (bitsLeft > 0) {
    result += ALPHABET[(buffer << (5 - bitsLeft)) & 31]
  }
  return result
}

function urlDecode(s: string): string {
  let result  = ""
  let i = 0
  while (i < s.length) {
    if (s[i] === "%" && i + 2 < s.length) {
      result += String.fromCharCode(parseInt(s.slice(i + 1, i + 3), 16))
      i += 3
    } else if (s[i] === "+") {
      result += " "
      i++
    } else {
      result += s[i++]
    }
  }
  return result
}
