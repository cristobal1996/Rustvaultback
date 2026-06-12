#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# Limpieza automática de warnings del backend RustVault
# ════════════════════════════════════════════════════════════════════
# 
# Uso (desde la raíz del proyecto):
#   chmod +x fix_warnings.sh
#   ./fix_warnings.sh
# 
# El script:
#   1. Hace backup de los archivos a /tmp/rustvault-backup-TIMESTAMP/
#   2. Aplica fixes de imports (3 archivos)
#   3. Añade #![allow(dead_code)] como atributo global a 5 archivos
#   4. Añade #[allow(dead_code)] a structs/enums específicos
#   5. Recompila para verificar
# ════════════════════════════════════════════════════════════════════

set -e

SRC="src"
if [ ! -d "$SRC" ]; then
    echo "ERROR: no se encuentra el directorio 'src/'. Ejecuta desde la raíz del proyecto."
    exit 1
fi

# Backup por si algo falla
BACKUP="/tmp/rustvault-backup-$(date +%Y%m%d-%H%M%S)"
echo "Backup en: $BACKUP"
cp -r "$SRC" "$BACKUP"
echo

# ── 1. FIXES DE IMPORTS ──────────────────────────────────────────────
echo "1. Aplicando fixes de imports..."

# generator.rs: quitar 'delete'
sed -i 's|routing::{get, post, put, delete}|routing::{get, post, put}|' "$SRC/routes/generator.rs"

# passwords.rs: quitar 'delete' y 'put'
sed -i 's|routing::{delete, get, post, put}|routing::{get, post}|' "$SRC/routes/passwords.rs"

# totp.rs: quitar 'Secret'
sed -i 's|use totp_rs::{Algorithm, Secret, TOTP};|use totp_rs::{Algorithm, TOTP};|' "$SRC/totp.rs"

echo "   ✓ Imports corregidos"
echo

# ── 2. ARCHIVOS CON #![allow(dead_code)] GLOBAL ──────────────────────
echo "2. Añadiendo #![allow(dead_code)] a archivos completos..."

for FILE in "$SRC/crypto.rs" "$SRC/crypto_asymmetric.rs" "$SRC/validation.rs" \
            "$SRC/pagination.rs" "$SRC/models.rs"; do
    # Solo añadir si NO está ya
    if ! head -5 "$FILE" | grep -q "allow(dead_code)"; then
        # Añadir al principio del archivo, antes del primer 'use' o código
        sed -i '1i #![allow(dead_code)]\n' "$FILE"
        echo "   ✓ $FILE"
    else
        echo "   - $FILE (ya tenía allow)"
    fi
done
echo

# ── 3. STRUCTS/ENUMS CON #[allow(dead_code)] PUNTUAL ─────────────────
echo "3. Añadiendo #[allow(dead_code)] a structs/enums específicos..."

# errors.rs: enum AppError
if ! grep -B1 "^pub enum AppError" "$SRC/errors.rs" | grep -q "allow(dead_code)"; then
    sed -i 's|^pub enum AppError|#[allow(dead_code)]\npub enum AppError|' "$SRC/errors.rs"
    echo "   ✓ errors.rs (AppError)"
fi

# middleware.rs: struct AuthUser
if ! grep -B1 "^pub struct AuthUser" "$SRC/middleware.rs" | grep -q "allow(dead_code)"; then
    sed -i 's|^pub struct AuthUser|#[allow(dead_code)]\npub struct AuthUser|' "$SRC/middleware.rs"
    echo "   ✓ middleware.rs (AuthUser)"
fi

# config.rs: struct Config + impl Config
if ! grep -B1 "^pub struct Config" "$SRC/config.rs" | grep -q "allow(dead_code)"; then
    sed -i 's|^pub struct Config|#[allow(dead_code)]\npub struct Config|' "$SRC/config.rs"
    sed -i 's|^impl Config|#[allow(dead_code)]\nimpl Config|' "$SRC/config.rs"
    echo "   ✓ config.rs (Config)"
fi

# totp.rs: BackupCode + verify_backup_code
if ! grep -B1 "^pub struct BackupCode" "$SRC/totp.rs" | grep -q "allow(dead_code)"; then
    sed -i 's|^pub struct BackupCode|#[allow(dead_code)]\npub struct BackupCode|' "$SRC/totp.rs"
    sed -i 's|^pub fn verify_backup_code|#[allow(dead_code)]\npub fn verify_backup_code|' "$SRC/totp.rs"
    echo "   ✓ totp.rs (BackupCode, verify_backup_code)"
fi

# routes/auth.rs: RecoverWithKeyRequest
if ! grep -B1 "^pub struct RecoverWithKeyRequest" "$SRC/routes/auth.rs" | grep -q "allow(dead_code)"; then
    sed -i 's|^pub struct RecoverWithKeyRequest|#[allow(dead_code)]\npub struct RecoverWithKeyRequest|' "$SRC/routes/auth.rs"
    echo "   ✓ routes/auth.rs (RecoverWithKeyRequest)"
fi

# routes/passwords.rs: ListQuery
if ! grep -B1 "^pub struct ListQuery" "$SRC/routes/passwords.rs" | grep -q "allow(dead_code)"; then
    sed -i 's|^pub struct ListQuery|#[allow(dead_code)]\npub struct ListQuery|' "$SRC/routes/passwords.rs"
    echo "   ✓ routes/passwords.rs (ListQuery)"
fi
echo

# ── 4. RECOMPILAR ────────────────────────────────────────────────────
echo "4. Recompilando para verificar..."
echo

cargo build 2>&1 | tail -20

echo
echo "════════════════════════════════════════════════════════"
echo "Si todo compila sin warnings, ya está hecho."
echo "Si algo falla, puedes restaurar desde:"
echo "  $BACKUP"
echo "  cp -r $BACKUP/* src/"
echo "════════════════════════════════════════════════════════"
