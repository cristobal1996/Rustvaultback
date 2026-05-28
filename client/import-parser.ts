// client/import-parser.ts
// Parsea archivos de otros gestores y cifra las entradas antes de importar

import { encryptAESGCM, decryptAESGCM, type EncryptedBlob } from "./crypto"

// ── Tipos ─────────────────────────────────────────────────────────

export type EntryType = "login" | "card" | "identity" | "note" | "ssh_key" | "api_key"
export type ImportFormat = "csv" | "json" | "1password" | "bitwarden" | "vault-app-v1"

export interface ParsedEntryPlaintext {
  title:    string
  username: string
  password: string
  url:      string
  notes:    string
  totp?:    string | null
}

export interface ParsedEntry {
  entry_type:     EntryType
  title_hint:     string | null
  domains:        string[]
  original_id?:   string
  // Datos en claro — el cliente los cifrará antes de enviar
  plaintext?:     ParsedEntryPlaintext
  // Para re-importación de backups propios (ya cifrados)
  raw_encrypted?: EncryptedBlob
}

export interface ImportEntry {
  entry_type:   EntryType
  title_hint:   string | null
  domains:      string[]
  encrypted:    EncryptedBlob
  original_id?: string
}

// Formato del archivo exportado por esta aplicación
interface OwnExportFormat {
  format:      string
  exported_at: string
  vault:       { id: string; name: string }
  entries:     OwnExportEntry[]
}

interface OwnExportEntry {
  id:          string
  entry_type:  string
  title_hint:  string | null
  domains:     string[] | null
  encrypted:   EncryptedBlob
  created_at:  string
  updated_at:  string
}

// Formato Bitwarden
interface BitwardenExport {
  encrypted: boolean
  items:     BitwardenItem[]
}

interface BitwardenItem {
  id:    string
  type:  number
  name:  string
  notes: string | null
  login?: {
    username: string | null
    password: string | null
    uris:     Array<{ uri: string }> | null
    totp:     string | null
  }
}

// ── Parser principal ──────────────────────────────────────────────

/**
 * Detecta el formato y parsea el archivo.
 * Todo ocurre en el navegador — ningún dato sale al exterior.
 */
export async function parseImportFile(file: File): Promise<ParsedEntry[]> {
  const text = await file.text()
  const name = file.name.toLowerCase()

  if (name.endsWith(".csv")) {
    return parseCSV(text)
  }

  if (name.endsWith(".json")) {
    const data = JSON.parse(text)
    if (data.format === "vault-app-v1")               return parseOwnFormat(data as OwnExportFormat)
    if (data.encrypted === false && data.items)        return parseBitwarden(data as BitwardenExport)
    if (data.accounts !== undefined || data.vaults)    return parse1Password(data)
  }

  throw new Error(`Formato no reconocido: ${name}. Formatos soportados: CSV, JSON (propio), Bitwarden, 1Password`)
}

// ── Formatos ──────────────────────────────────────────────────────

function parseOwnFormat(data: OwnExportFormat): ParsedEntry[] {
  return data.entries.map(e => ({
    entry_type:    (e.entry_type as EntryType) ?? "login",
    title_hint:    e.title_hint,
    domains:       e.domains ?? [],
    original_id:   e.id,
    raw_encrypted: e.encrypted,
  }))
}

function parseCSV(text: string): ParsedEntry[] {
  const lines  = text.split("\n").filter(l => l.trim())
  if (lines.length < 2) return []

  const header = parseCSVLine(lines[0]).map(h =>
    h.trim().toLowerCase().replace(/"/g, "")
  )
  const entries: ParsedEntry[] = []

  for (let i = 1; i < lines.length; i++) {
    const values = parseCSVLine(lines[i])
    if (!values.length) continue

    const row: Record<string, string> = {}
    header.forEach((h, idx) => {
      row[h] = (values[idx] ?? "").replace(/^"|"$/g, "").trim()
    })

    const name     = row.name     || row.title    || row.site          || ""
    const url      = row.url      || row.website  || row.login_uri      || ""
    const username = row.username || row.email    || row.login_username || ""
    const password = row.password || row.login_password               || ""
    const notes    = row.notes    || row.note     || row.extra          || ""

    if (!password && !notes) continue

    entries.push({
      entry_type: "login",
      title_hint: name || extractDomain(url) || "Sin nombre",
      domains:    url ? [extractDomain(url)].filter((d): d is string => Boolean(d)) : [],
      plaintext:  { title: name, username, password, url, notes },
    })
  }

  return entries
}

function parseBitwarden(data: BitwardenExport): ParsedEntry[] {
  return (data.items ?? []).map(item => {
    const type: EntryType =
      item.type === 1 ? "login"    :
      item.type === 2 ? "note"     :
      item.type === 3 ? "card"     :
      item.type === 4 ? "identity" : "login"

    const domains: string[] = []
    for (const uri of item.login?.uris ?? []) {
      const d = extractDomain(uri.uri)
      if (d) domains.push(d)
    }

    return {
      entry_type:  type,
      title_hint:  item.name || "Sin nombre",
      domains,
      original_id: item.id,
      plaintext: {
        title:    item.name,
        username: item.login?.username ?? "",
        password: item.login?.password ?? "",
        url:      item.login?.uris?.[0]?.uri ?? "",
        notes:    item.notes ?? "",
        totp:     item.login?.totp ?? null,
      },
    }
  })
}

function parse1Password(data: Record<string, unknown>): ParsedEntry[] {
  const items = (data.items as Record<string, unknown>[]) ?? []
  const entries: ParsedEntry[] = []

  for (const item of items) {
    if (item.trashed === "Y") continue

    const fields: Record<string, string> = {}
    for (const field of (item.fields as Array<{ id?: string; label?: string; value?: string }> ?? [])) {
      const key = field.id ?? field.label?.toLowerCase() ?? ""
      fields[key] = field.value ?? ""
    }

    const urls    = ((item.urls as Array<{ href: string }>) ?? [])
      .map(u => extractDomain(u.href))
      .filter((d): d is string => Boolean(d))

    const category = item.category as string ?? ""
    const type: EntryType =
      category === "LOGIN"       ? "login"    :
      category === "SECURE_NOTE" ? "note"     :
      category === "CREDIT_CARD" ? "card"     : "login"

    entries.push({
      entry_type:  type,
      title_hint:  (item.title as string) || "Sin nombre",
      domains:     urls,
      original_id: item.uuid as string,
      plaintext: {
        title:    item.title as string,
        username: fields.username || fields.email || "",
        password: fields.password || "",
        url:      ((item.urls as Array<{ href: string }>)?.[0]?.href) ?? "",
        notes:    (item.notes as string) ?? "",
      },
    })
  }

  return entries
}

// ── Cifrar antes de importar ──────────────────────────────────────

/**
 * Cifra las entradas parseadas con la Vault Key.
 * Solo entonces están listas para enviar al servidor.
 */
export async function encryptParsedEntries(
  entries:  ParsedEntry[],
  vaultKey: Uint8Array
): Promise<ImportEntry[]> {
  const result: ImportEntry[] = []

  for (const entry of entries) {
    let encryptedBlob: EncryptedBlob

    if (entry.plaintext) {
      const plaintextBytes = new TextEncoder().encode(JSON.stringify(entry.plaintext))
      encryptedBlob        = await encryptAESGCM(plaintextBytes, vaultKey)
    } else if (entry.raw_encrypted) {
      // Re-importación de backup propio: blob ya en formato correcto
      encryptedBlob = entry.raw_encrypted
    } else {
      continue
    }

    result.push({
      entry_type:  entry.entry_type,
      title_hint:  entry.title_hint,
      domains:     entry.domains,
      encrypted:   encryptedBlob,
      original_id: entry.original_id,
    })
  }

  return result
}

// ── Exportar y descargar ──────────────────────────────────────────

interface ExportData {
  exported_at: string
  vault:       { id: string; name: string }
  entries:     OwnExportEntry[]
}

/**
 * Descifra el backup y lo descarga como JSON legible.
 */
export async function decryptAndDownload(
  exportData: ExportData,
  vaultKey:   Uint8Array
): Promise<void> {
  const decrypted: unknown[] = []

  for (const entry of exportData.entries) {
    try {
      const plaintextBytes = await decryptAESGCM(entry.encrypted, vaultKey)
      const plaintext      = JSON.parse(new TextDecoder().decode(plaintextBytes))
      decrypted.push({
        id:         entry.id,
        type:       entry.entry_type,
        title:      entry.title_hint,
        domains:    entry.domains,
        ...plaintext,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
      })
    } catch {
      console.warn(`No se pudo descifrar la entrada ${entry.id}`)
    }
  }

  const output = {
    exported_at: exportData.exported_at,
    vault:       exportData.vault.name,
    entries:     decrypted,
  }

  const blob     = new Blob([JSON.stringify(output, null, 2)], { type: "application/json" })
  const url      = URL.createObjectURL(blob)
  const link     = document.createElement("a")
  const date     = new Date().toISOString().split("T")[0]
  link.href      = url
  link.download  = `backup-${exportData.vault.name}-${date}.json`
  link.click()
  URL.revokeObjectURL(url)
}

// ── Utilidades ────────────────────────────────────────────────────

function extractDomain(url: string | null | undefined): string | null {
  if (!url) return null
  try {
    const u = new URL(url.startsWith("http") ? url : `https://${url}`)
    return u.hostname
  } catch {
    return null
  }
}

function parseCSVLine(line: string): string[] {
  const values: string[] = []
  let current  = ""
  let inQuotes = false

  for (const char of line) {
    if (char === '"') {
      inQuotes = !inQuotes
    } else if (char === "," && !inQuotes) {
      values.push(current)
      current = ""
    } else {
      current += char
    }
  }
  values.push(current)
  return values
}
