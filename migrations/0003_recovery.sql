-- Migración 0003 — Recovery Key para recuperación sin pérdida de datos
-- Aplicar sobre BD existente: docker exec -i rustvault-postgres-1 psql -U rustvault -d rustvault < 0003_recovery.sql

-- Columna para guardar la MUK cifrada con la Recovery Key
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS recovery_blob JSONB;

-- Índice para buscar por email en recuperación
CREATE INDEX IF NOT EXISTS idx_users_email_recovery
  ON users(email) WHERE deleted_at IS NULL AND recovery_blob IS NOT NULL;
