// client/change-password.ts
// Cambio de contraseña maestra — todo el trabajo cripto ocurre aquí

import { encryptAESGCM, decryptAESGCM, bytesToHex, hexToBytes, generateRandomHex, type EncryptedBlob } from "./crypto"

// ── Tipos ─────────────────────────────────────────────────────────

export interface VaultForRekey {
  id:                  string
  encrypted_vault_key: EncryptedBlob
}

export interface RekeyedVault {
  vault_id:            string
  encrypted_vault_key: EncryptedBlob
}

export interface ChangePasswordResult {
  success:        boolean
  message:        string
  vaults_rekeyed: number
}

// ── Cambio de contraseña ──────────────────────────────────────────

/**
 * Cambia la contraseña maestra del usuario.
 *
 * 1. Deriva MUK antigua con la contraseña actual
 * 2. Genera nuevo salt y deriva MUK nueva
 * 3. Re-cifra todas las Vault Keys con la MUK nueva
 * 4. Envía todo al servidor en una transacción atómica
 */
export async function changePassword(
  currentPassword: string,
  newPassword:     string,
  secretKeyHex:    string,
  currentSaltHex:  string,
  vaults:          VaultForRekey[],
  apiToken:        string,
  totpCode?:       string,
  mukHex?:         string,
): Promise<ChangePasswordResult> {
  // Derivar MUK antigua
  const oldMUK = await deriveMUK(currentPassword, secretKeyHex, currentSaltHex)

  // Generar nuevo salt y derivar MUK nueva
  const newSalt    = generateRandomHex(16)
  const newSRPSalt = generateRandomHex(16)
  const newMUK     = await deriveMUK(newPassword, secretKeyHex, newSalt)

  // Re-cifrar todas las Vault Keys
  const rekeyedVaults: RekeyedVault[] = []

  for (const vault of vaults) {
    const vaultKeyBytes    = await decryptAESGCM(vault.encrypted_vault_key, oldMUK)
    const newEncryptedKey  = await encryptAESGCM(vaultKeyBytes, newMUK)
    vaultKeyBytes.fill(0)
    rekeyedVaults.push({ vault_id: vault.id, encrypted_vault_key: newEncryptedKey })
  }

  // Limpiar MUK antigua
  oldMUK.fill(0)

  // Enviar al servidor
  const res = await fetch("/api/account/change-password", {
    method:  "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${apiToken}`,
    },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password:     newPassword,
      new_srp_salt:     newSRPSalt,
      new_srp_verifier: await generateSRPVerifier(newPassword, newSRPSalt),
      rekeyed_vaults:   rekeyedVaults,
      totp_code:        totpCode ?? null,
      muk_hex:          mukHex   ?? null,
    }),
  })

  // Limpiar MUK nueva
  newMUK.fill(0)

  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.error ?? "Error al cambiar la contraseña")
  }

  return res.json()
}

// ── Derivación de MUK ─────────────────────────────────────────────

/**
 * Deriva la Master Unlock Key con Argon2id.
 * Requiere la librería argon2-browser: npm install argon2-browser
 */
export async function deriveMUK(
  password:     string,
  secretKeyHex: string,
  saltHex:      string
): Promise<Uint8Array> {
  // Importación dinámica para que no rompa el bundle si no está instalada
  const argon2 = await import("argon2-browser")

  const combined = `${password}:${secretKeyHex}`
  const salt     = hexToBytes(saltHex)

  const result = await argon2.hash({
    pass:        combined,
    salt,
    type:        argon2.ArgonType.Argon2id,
    mem:         65536,   // 64 MB — mismo valor que el servidor
    time:        3,
    parallelism: 4,
    hashLen:     32,
  })

  return result.hash
}

// ── SRP Verifier ──────────────────────────────────────────────────

async function generateSRPVerifier(password: string, salt: string): Promise<string> {
  // Placeholder — en producción usar una librería SRP como secure-remote-password
  const combined   = new TextEncoder().encode(`${password}:${salt}`)
  const hashBuffer = await crypto.subtle.digest("SHA-256", combined)
  return bytesToHex(new Uint8Array(hashBuffer))
}
