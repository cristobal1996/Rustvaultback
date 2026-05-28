-- ================================================================
-- RustVault — Schema limpio sin vaults
-- PostgreSQL 16
--
-- Nuevo enfoque: las contraseñas se guardan directamente
-- asociadas al usuario, cifradas con su MUK.
-- Sin vaults intermedios — más simple y directo.
-- ================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ================================================================
-- 1. USUARIOS
-- ================================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    srp_salt        TEXT NOT NULL,
    srp_verifier    TEXT NOT NULL,

    -- 2FA para login en la app
    totp_secret       JSONB,
    totp_enabled      BOOLEAN NOT NULL DEFAULT false,
    totp_backup_codes JSONB,

    -- Clave pública X25519 para compartir contraseñas
    pub_key              TEXT,
    encrypted_priv_key   JSONB,

    -- Código de invitación único: RV-XXXX-XXXX
    invite_code          TEXT UNIQUE,

    -- Código de emergencia (hash SHA-256) para recuperar cuenta
    emergency_code_hash  TEXT,

    -- Preferencias
    auto_lock_minutes         INTEGER NOT NULL DEFAULT 15,
    require_2fa_on_new_device BOOLEAN NOT NULL DEFAULT false,

    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    deleted_at    TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_invite_code ON users(invite_code) WHERE invite_code IS NOT NULL;

-- ================================================================
-- 2. DISPOSITIVOS
-- ================================================================

CREATE TABLE devices (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    platform           TEXT NOT NULL,
    is_trusted         BOOLEAN NOT NULL DEFAULT false,
    device_fingerprint TEXT,
    last_seen_at       TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_user ON devices(user_id);

-- ================================================================
-- 3. SESIONES
-- ================================================================

CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id  UUID REFERENCES devices(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_token ON sessions(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_user  ON sessions(user_id)    WHERE revoked_at IS NULL;

-- ================================================================
-- 4. CONTRASEÑAS
-- Directamente del usuario, cifradas con su MUK.
-- Sin vaults intermedios.
-- ================================================================

CREATE TABLE passwords (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Metadatos en claro (para buscar sin descifrar)
    title       TEXT NOT NULL,
    domain      TEXT,
    entry_type  TEXT NOT NULL DEFAULT 'login'
                CHECK (entry_type IN ('login','card','note','identity','ssh_key','api_key')),
    favicon_url TEXT,

    -- Contenido cifrado con la MUK del usuario
    -- { username, password, url, notes, extra }
    encrypted   JSONB NOT NULL,

    -- Historial
    version    INTEGER NOT NULL DEFAULT 1,
    is_deleted BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_passwords_user   ON passwords(user_id) WHERE NOT is_deleted;
CREATE INDEX idx_passwords_domain ON passwords(user_id, domain) WHERE NOT is_deleted;
CREATE INDEX idx_passwords_type   ON passwords(user_id, entry_type) WHERE NOT is_deleted;
CREATE INDEX idx_passwords_search ON passwords USING gin(to_tsvector('simple', title));

-- Versiones anteriores
CREATE TABLE password_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    password_id UUID NOT NULL REFERENCES passwords(id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    encrypted   JSONB NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pw_versions_id ON password_versions(password_id, version DESC);

-- ================================================================
-- 5. TOTP (códigos 2FA guardados por el usuario)
-- Directamente del usuario, cifrados con su MUK.
-- ================================================================

CREATE TABLE totp_credentials (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer           TEXT,
    account          TEXT,
    encrypted_secret JSONB NOT NULL,
    algorithm        TEXT NOT NULL DEFAULT 'SHA1'
                     CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    digits           INTEGER NOT NULL DEFAULT 6,
    period           INTEGER NOT NULL DEFAULT 30,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_totp_user ON totp_credentials(user_id);

-- ================================================================
-- 6. PERFILES DEL GENERADOR
-- ================================================================

CREATE TABLE generator_profiles (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    is_default       BOOLEAN NOT NULL DEFAULT false,
    length           INTEGER NOT NULL DEFAULT 20 CHECK (length BETWEEN 8 AND 128),
    use_uppercase    BOOLEAN NOT NULL DEFAULT true,
    use_lowercase    BOOLEAN NOT NULL DEFAULT true,
    use_digits       BOOLEAN NOT NULL DEFAULT true,
    use_symbols      BOOLEAN NOT NULL DEFAULT true,
    symbols_allowed  TEXT NOT NULL DEFAULT '!@#$%^&*()-_=+[]{}|;:,.<>?',
    exclude_ambiguous BOOLEAN NOT NULL DEFAULT false,
    min_uppercase    INTEGER NOT NULL DEFAULT 1,
    min_digits       INTEGER NOT NULL DEFAULT 1,
    min_symbols      INTEGER NOT NULL DEFAULT 1,
    use_passphrase   BOOLEAN NOT NULL DEFAULT false,
    word_count       INTEGER NOT NULL DEFAULT 4,
    word_separator   TEXT NOT NULL DEFAULT '-',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_generator_user ON generator_profiles(user_id);
CREATE UNIQUE INDEX idx_generator_default ON generator_profiles(user_id) WHERE is_default = true;

-- ================================================================
-- 7. CONTRASEÑAS COMPARTIDAS
-- Alice comparte una contraseña individual con Bob.
-- El contenido va re-cifrado con la clave pública X25519 de Bob.
-- Bob puede aceptarla (copia propia) o verla temporalmente.
-- ================================================================

CREATE TABLE shared_passwords (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    password_id     UUID NOT NULL REFERENCES passwords(id) ON DELETE CASCADE,
    sender_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Contenido re-cifrado con la clave pública X25519 del destinatario
    -- { ephemeral_pub, nonce, ciphertext }
    encrypted_for_recipient JSONB NOT NULL,

    -- Metadatos en claro
    title_hint      TEXT,           -- título para mostrar en la bandeja
    message         TEXT,           -- mensaje opcional del remitente
    permission      TEXT NOT NULL DEFAULT 'view'
                    CHECK (permission IN ('view', 'copy')),

    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'rejected', 'expired')),

    expires_at      TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '7 days',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    responded_at    TIMESTAMPTZ
);

CREATE INDEX idx_shared_recipient ON shared_passwords(recipient_id, status);
CREATE INDEX idx_shared_sender    ON shared_passwords(sender_id);
CREATE INDEX idx_shared_password  ON shared_passwords(password_id);

-- ================================================================
-- 8. AUDIT LOG
-- ================================================================

CREATE TABLE audit_log (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES users(id),
    device_id  UUID REFERENCES devices(id),
    action     TEXT NOT NULL,
    metadata   JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user   ON audit_log(user_id,  created_at DESC);
CREATE INDEX idx_audit_action ON audit_log(action,   created_at DESC);

-- ================================================================
-- FUNCIONES Y TRIGGERS
-- ================================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_passwords_updated_at
    BEFORE UPDATE ON passwords
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_totp_updated_at
    BEFORE UPDATE ON totp_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_generator_updated_at
    BEFORE UPDATE ON generator_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

