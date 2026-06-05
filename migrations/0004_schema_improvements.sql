-- ════════════════════════════════════════════════════════════════════
-- Migración 0004 — Mejoras de esquema (sin pérdida de datos)
-- ════════════════════════════════════════════════════════════════════
--
-- Aplica los cambios del schema mejorado SIN recrear las tablas.
-- Seguro de ejecutar sobre una BD con datos.
--
-- Aplicar:
--   docker exec -i rustvault-postgres-1 \
--     psql -U rustvaultuser -d rustvaultdb < 0004_schema_improvements.sql
-- ════════════════════════════════════════════════════════════════════

BEGIN;

-- ──────────────────────────────────────────────────────────────────
-- 1. UNIQUE de email convertido en parcial
-- ──────────────────────────────────────────────────────────────────
-- Permite reutilizar email tras soft-delete (deleted_at IS NOT NULL).

-- Quitar el UNIQUE constraint actual (creado automáticamente por NOT NULL UNIQUE)
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;

-- El antiguo idx_users_email también es parcial, lo mantenemos pero lo renombramos
-- para indicar que es el UNIQUE activo.
DROP INDEX IF EXISTS idx_users_email;

-- Crear el nuevo UNIQUE parcial: solo aplica a usuarios activos
CREATE UNIQUE INDEX idx_users_email_active
    ON users(email) WHERE deleted_at IS NULL;


-- ──────────────────────────────────────────────────────────────────
-- 2. audit_log: cambiar políticas ON DELETE a SET NULL
-- ──────────────────────────────────────────────────────────────────
-- Permite borrado físico de usuarios sin perder el rastro de auditoría.

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_user_id_fkey;
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_device_id_fkey;
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_device_id_fkey
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL;


-- ──────────────────────────────────────────────────────────────────
-- 3. Añadir columna updated_at a users (si no existe)
-- ──────────────────────────────────────────────────────────────────

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Trigger para actualizar updated_at automáticamente
DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ──────────────────────────────────────────────────────────────────
-- 4. Nuevos índices para acelerar el limpiador (cleanup.rs)
-- ──────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_sessions_expires
    ON sessions(expires_at) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_shared_expires
    ON shared_passwords(expires_at) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_passwords_deleted
    ON passwords(deleted_at) WHERE is_deleted = true;

CREATE INDEX IF NOT EXISTS idx_audit_created
    ON audit_log(created_at DESC);


-- ──────────────────────────────────────────────────────────────────
-- 5. Constraints adicionales en TOTP y generator (validación más estricta)
-- ──────────────────────────────────────────────────────────────────

-- TOTP: digits entre 6 y 8
ALTER TABLE totp_credentials
    DROP CONSTRAINT IF EXISTS totp_credentials_digits_check;
ALTER TABLE totp_credentials
    ADD CONSTRAINT totp_credentials_digits_check
    CHECK (digits BETWEEN 6 AND 8);

-- TOTP: period entre 15 y 120 segundos
ALTER TABLE totp_credentials
    DROP CONSTRAINT IF EXISTS totp_credentials_period_check;
ALTER TABLE totp_credentials
    ADD CONSTRAINT totp_credentials_period_check
    CHECK (period BETWEEN 15 AND 120);

-- Generator: word_count razonable
ALTER TABLE generator_profiles
    DROP CONSTRAINT IF EXISTS generator_profiles_word_count_check;
ALTER TABLE generator_profiles
    ADD CONSTRAINT generator_profiles_word_count_check
    CHECK (word_count BETWEEN 3 AND 12);


-- ──────────────────────────────────────────────────────────────────
-- 6. Vista de estadísticas globales
-- ──────────────────────────────────────────────────────────────────

CREATE OR REPLACE VIEW v_stats AS
SELECT
    (SELECT COUNT(*) FROM users WHERE deleted_at IS NULL)                    AS active_users,
    (SELECT COUNT(*) FROM users WHERE deleted_at IS NOT NULL)                AS deleted_users,
    (SELECT COUNT(*) FROM passwords WHERE NOT is_deleted)                    AS active_passwords,
    (SELECT COUNT(*) FROM totp_credentials)                                  AS totp_credentials,
    (SELECT COUNT(*) FROM shared_passwords WHERE status = 'pending')         AS pending_shares,
    (SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL
                                     AND expires_at > now())                 AS active_sessions;


COMMIT;


-- ══════════════════════════════════════════════════════════════════
-- VERIFICACIÓN POST-MIGRACIÓN
-- ══════════════════════════════════════════════════════════════════
-- Ejecuta estas queries para confirmar que todo está bien:

-- 1. Ver estadísticas globales
SELECT * FROM v_stats;

-- 2. Comprobar constraints de audit_log
SELECT
    tc.constraint_name,
    tc.constraint_type,
    rc.delete_rule
FROM information_schema.table_constraints tc
LEFT JOIN information_schema.referential_constraints rc
    ON tc.constraint_name = rc.constraint_name
WHERE tc.table_name = 'audit_log';

-- 3. Comprobar el nuevo índice parcial de email
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'users' AND indexname LIKE '%email%';
