// src/validation.rs
//
// Validación centralizada de todos los inputs que llegan al servidor.
//
// Cada función valida un conjunto de campos relacionados y devuelve
// un AppError::Validation con un mensaje claro si algo falla.
//
// USO en un handler:
//   validate_register(&req.email, &req.password)?;
//   // si llega aquí, los datos son correctos

use crate::errors::{AppError, Result};

// ── Constantes ────────────────────────────────────────────────────

const EMAIL_MAX:        usize = 254;  // RFC 5321
const PASSWORD_MIN:     usize = 12;
const PASSWORD_MAX:     usize = 128;
const NAME_MIN:         usize = 1;
const NAME_MAX:         usize = 100;
const NOTE_MAX:         usize = 10_000;
const CHANGE_NOTE_MAX:  usize = 500;
const DOMAIN_MAX:       usize = 253;  // RFC 1035
const DOMAINS_MAX:      usize = 20;   // máximo dominios por entrada
const SEARCH_MIN:       usize = 3;
const SEARCH_MAX:       usize = 100;

// ── Auth ──────────────────────────────────────────────────────────

/// Valida email y contraseña en el registro.
pub fn validate_register(email: &str, password: &str) -> Result<()> {
    validate_email(email)?;
    validate_password(password)?;
    Ok(())
}

/// Valida el email en el login (no validamos la contraseña aquí
/// porque el mensaje de error sería demasiado informativo para atacantes).
pub fn validate_login(email: &str) -> Result<()> {
    validate_email(email)?;
    Ok(())
}

/// Valida el cambio de contraseña maestra.
pub fn validate_change_password(
    current_password: &str,
    new_password: &str,
) -> Result<()> {
    if current_password.is_empty() {
        return Err(AppError::Validation(
            "La contraseña actual es obligatoria".into()
        ));
    }
    validate_password(new_password)?;
    if current_password == new_password {
        return Err(AppError::Validation(
            "La nueva contraseña debe ser diferente a la actual".into()
        ));
    }
    Ok(())
}

// ── Vaults ────────────────────────────────────────────────────────

/// Valida los campos al crear o actualizar un vault.
pub fn validate_vault(name: &str, vault_type: &str) -> Result<()> {
    validate_name("El nombre del vault", name)?;

    if !["personal", "shared"].contains(&vault_type) {
        return Err(AppError::Validation(
            "El tipo de vault debe ser 'personal' o 'shared'".into()
        ));
    }
    Ok(())
}

// ── Entries ───────────────────────────────────────────────────────

/// Valida los campos al crear una entrada.
pub fn validate_entry(
    entry_type: &str,
    title_hint: Option<&str>,
    domains: Option<&[String]>,
    change_note: Option<&str>,
) -> Result<()> {
    let valid_types = ["login", "card", "identity", "note", "ssh_key", "api_key"];
    if !valid_types.contains(&entry_type) {
        return Err(AppError::Validation(format!(
            "Tipo de entrada inválido. Válidos: {}",
            valid_types.join(", ")
        )));
    }

    if let Some(hint) = title_hint {
        if hint.len() > NAME_MAX {
            return Err(AppError::Validation(format!(
                "El título no puede superar {} caracteres", NAME_MAX
            )));
        }
    }

    if let Some(domains) = domains {
        if domains.len() > DOMAINS_MAX {
            return Err(AppError::Validation(format!(
                "Máximo {} dominios por entrada", DOMAINS_MAX
            )));
        }
        for domain in domains {
            validate_domain(domain)?;
        }
    }

    if let Some(note) = change_note {
        if note.len() > CHANGE_NOTE_MAX {
            return Err(AppError::Validation(format!(
                "La nota de cambio no puede superar {} caracteres", CHANGE_NOTE_MAX
            )));
        }
    }

    Ok(())
}

/// Valida los campos al actualizar una entrada.
pub fn validate_entry_update(
    expected_version: i32,
    change_note: Option<&str>,
) -> Result<()> {
    if expected_version < 1 {
        return Err(AppError::Validation(
            "La versión esperada debe ser mayor que 0".into()
        ));
    }

    if let Some(note) = change_note {
        if note.len() > CHANGE_NOTE_MAX {
            return Err(AppError::Validation(format!(
                "La nota de cambio no puede superar {} caracteres", CHANGE_NOTE_MAX
            )));
        }
    }

    Ok(())
}

// ── Generator ─────────────────────────────────────────────────────

/// Valida la configuración del generador de contraseñas.
pub fn validate_generator(
    name: &str,
    length: i32,
    min_uppercase: i32,
    min_digits: i32,
    min_symbols: i32,
    word_count: i32,
) -> Result<()> {
    validate_name("El nombre del perfil", name)?;

    if !(8..=128).contains(&length) {
        return Err(AppError::Validation(
            "La longitud debe estar entre 8 y 128 caracteres".into()
        ));
    }

    if min_uppercase < 0 || min_digits < 0 || min_symbols < 0 {
        return Err(AppError::Validation(
            "Los mínimos de caracteres no pueden ser negativos".into()
        ));
    }

    let total_min = min_uppercase + min_digits + min_symbols;
    if total_min > length {
        return Err(AppError::Validation(
            "La suma de mínimos no puede superar la longitud total".into()
        ));
    }

    if !(2..=10).contains(&word_count) {
        return Err(AppError::Validation(
            "El número de palabras debe estar entre 2 y 10".into()
        ));
    }

    Ok(())
}

// ── TOTP ──────────────────────────────────────────────────────────

/// Valida los parámetros de un TOTP.
pub fn validate_totp(
    algorithm: &str,
    digits: i32,
    period: i32,
) -> Result<()> {
    if !["SHA1", "SHA256", "SHA512"].contains(&algorithm) {
        return Err(AppError::Validation(
            "Algoritmo TOTP inválido. Válidos: SHA1, SHA256, SHA512".into()
        ));
    }

    if ![6, 8].contains(&digits) {
        return Err(AppError::Validation(
            "Los dígitos TOTP deben ser 6 u 8".into()
        ));
    }

    if ![30, 60].contains(&period) {
        return Err(AppError::Validation(
            "El período TOTP debe ser 30 o 60 segundos".into()
        ));
    }

    Ok(())
}

// ── Autofill ──────────────────────────────────────────────────────

/// Valida una regla de autofill.
pub fn validate_autofill(domain: &str, priority: i32) -> Result<()> {
    validate_domain(domain)?;

    if !(-100..=100).contains(&priority) {
        return Err(AppError::Validation(
            "La prioridad debe estar entre -100 y 100".into()
        ));
    }

    Ok(())
}

// ── Búsqueda de usuarios ──────────────────────────────────────────

/// Valida el término de búsqueda de usuarios.
pub fn validate_user_search(q: &str) -> Result<()> {
    let q = q.trim();

    if q.len() < SEARCH_MIN {
        return Err(AppError::Validation(format!(
            "La búsqueda debe tener al menos {} caracteres", SEARCH_MIN
        )));
    }

    if q.len() > SEARCH_MAX {
        return Err(AppError::Validation(format!(
            "La búsqueda no puede superar {} caracteres", SEARCH_MAX
        )));
    }

    Ok(())
}

// ── Sharing ───────────────────────────────────────────────────────

/// Valida una invitación a vault.
pub fn validate_invitation(invited_email: &str, role: &str) -> Result<()> {
    validate_email(invited_email)?;

    if !["admin", "editor", "viewer"].contains(&role) {
        return Err(AppError::Validation(
            "Rol inválido. Válidos: admin, editor, viewer".into()
        ));
    }

    Ok(())
}

/// Valida un cambio de rol.
pub fn validate_role(role: &str) -> Result<()> {
    if !["admin", "editor", "viewer"].contains(&role) {
        return Err(AppError::Validation(
            "Rol inválido. Válidos: admin, editor, viewer".into()
        ));
    }
    Ok(())
}

// ── Paginación ────────────────────────────────────────────────────

/// Valida y normaliza los parámetros de paginación.
/// Devuelve (page, limit) normalizados.
pub fn validate_pagination(page: Option<i64>, limit: Option<i64>) -> Result<(i64, i64)> {
    let page = page.unwrap_or(1);
    let limit = limit.unwrap_or(50);

    if page < 1 {
        return Err(AppError::Validation(
            "La página debe ser mayor que 0".into()
        ));
    }

    if !(1..=100).contains(&limit) {
        return Err(AppError::Validation(
            "El límite debe estar entre 1 y 100".into()
        ));
    }

    Ok((page, limit))
}

// ── Importación ───────────────────────────────────────────────────

/// Valida el formato de importación.
pub fn validate_import_format(format: &str) -> Result<()> {
    if !["csv", "json", "1password", "bitwarden"].contains(&format) {
        return Err(AppError::Validation(
            "Formato de importación inválido. Válidos: csv, json, 1password, bitwarden".into()
        ));
    }
    Ok(())
}

// ── Funciones internas ────────────────────────────────────────────

/// Valida un email según las reglas básicas del RFC 5321.
fn validate_email(email: &str) -> Result<()> {
    let email = email.trim();

    if email.is_empty() {
        return Err(AppError::Validation("El email es obligatorio".into()));
    }

    if email.len() > EMAIL_MAX {
        return Err(AppError::Validation(format!(
            "El email no puede superar {} caracteres", EMAIL_MAX
        )));
    }

    // Verificar que tiene exactamente un @
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return Err(AppError::Validation("El email debe contener @".into()));
    }

    let (local, domain) = (parts[0], parts[1]);

    if local.is_empty() {
        return Err(AppError::Validation(
            "El email debe tener texto antes del @".into()
        ));
    }

    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err(AppError::Validation(
            "El dominio del email no es válido".into()
        ));
    }

    // Caracteres básicos válidos en email
    let invalid_chars: Vec<char> = email
        .chars()
        .filter(|c| !c.is_alphanumeric() && !matches!(c, '@' | '.' | '-' | '_' | '+'))
        .collect();

    if !invalid_chars.is_empty() {
        return Err(AppError::Validation(format!(
            "El email contiene caracteres no válidos: {}",
            invalid_chars.iter().collect::<String>()
        )));
    }

    Ok(())
}

/// Valida una contraseña maestra.
fn validate_password(password: &str) -> Result<()> {
    if password.len() < PASSWORD_MIN {
        return Err(AppError::Validation(format!(
            "La contraseña debe tener al menos {} caracteres", PASSWORD_MIN
        )));
    }

    if password.len() > PASSWORD_MAX {
        return Err(AppError::Validation(format!(
            "La contraseña no puede superar {} caracteres", PASSWORD_MAX
        )));
    }

    // Verificar que tiene al menos un dígito o símbolo
    let has_digit  = password.chars().any(|c| c.is_ascii_digit());
    let has_upper  = password.chars().any(|c| c.is_uppercase());
    let has_lower  = password.chars().any(|c| c.is_lowercase());

    if !has_digit {
        return Err(AppError::Validation(
            "La contraseña debe contener al menos un número".into()
        ));
    }
    if !has_upper {
        return Err(AppError::Validation(
            "La contraseña debe contener al menos una mayúscula".into()
        ));
    }
    if !has_lower {
        return Err(AppError::Validation(
            "La contraseña debe contener al menos una minúscula".into()
        ));
    }

    Ok(())
}

/// Valida un nombre genérico (vault, perfil...).
fn validate_name(field: &str, name: &str) -> Result<()> {
    let name = name.trim();

    if name.len() < NAME_MIN {
        return Err(AppError::Validation(format!(
            "{} no puede estar vacío", field
        )));
    }

    if name.len() > NAME_MAX {
        return Err(AppError::Validation(format!(
            "{} no puede superar {} caracteres", field, NAME_MAX
        )));
    }

    Ok(())
}

/// Valida un nombre de dominio.
fn validate_domain(domain: &str) -> Result<()> {
    let domain = domain.trim();

    if domain.is_empty() {
        return Err(AppError::Validation("El dominio no puede estar vacío".into()));
    }

    if domain.len() > DOMAIN_MAX {
        return Err(AppError::Validation(format!(
            "El dominio no puede superar {} caracteres", DOMAIN_MAX
        )));
    }

    // Solo letras, números, puntos y guiones
    let invalid: Vec<char> = domain
        .chars()
        .filter(|c| !c.is_alphanumeric() && !matches!(c, '.' | '-' | '*'))
        .collect();

    if !invalid.is_empty() {
        return Err(AppError::Validation(format!(
            "El dominio '{}' contiene caracteres no válidos", domain
        )));
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(AppError::Validation(
            "El dominio no puede empezar ni terminar con punto".into()
        ));
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_valido() {
        assert!(validate_register("alice@example.com", "Password123!").is_ok());
        assert!(validate_register("alice+tag@example.co.uk", "Password123!").is_ok());
    }

    #[test]
    fn test_email_invalido() {
        assert!(validate_register("noarroba.com", "Password123!").is_err());
        assert!(validate_register("", "Password123!").is_err());
        assert!(validate_register("@example.com", "Password123!").is_err());
        assert!(validate_register("alice@", "Password123!").is_err());
    }

    #[test]
    fn test_password_invalida() {
        assert!(validate_register("a@b.com", "corta").is_err());          // muy corta
        assert!(validate_register("a@b.com", "sinNumeros!!Abc").is_err()); // sin dígitos
        assert!(validate_register("a@b.com", "sinmayusculas1!").is_err()); // sin mayúsculas
        assert!(validate_register("a@b.com", "SINMINUSCULAS1!").is_err()); // sin minúsculas
    }

    #[test]
    fn test_password_valida() {
        assert!(validate_register("a@b.com", "MiPassword123!").is_ok());
        assert!(validate_register("a@b.com", "correct-Horse-Battery-1").is_ok());
    }

    #[test]
    fn test_paginacion() {
        assert!(validate_pagination(Some(1), Some(50)).is_ok());
        assert!(validate_pagination(None, None).is_ok()); // usa defaults
        assert!(validate_pagination(Some(0), Some(50)).is_err()); // página 0
        assert!(validate_pagination(Some(1), Some(200)).is_err()); // límite > 100
    }

    #[test]
    fn test_totp() {
        assert!(validate_totp("SHA1", 6, 30).is_ok());
        assert!(validate_totp("SHA256", 8, 60).is_ok());
        assert!(validate_totp("MD5", 6, 30).is_err());   // algoritmo inválido
        assert!(validate_totp("SHA1", 7, 30).is_err());  // dígitos inválidos
        assert!(validate_totp("SHA1", 6, 45).is_err());  // período inválido
    }

    #[test]
    fn test_dominio() {
        assert!(validate_autofill("github.com", 0).is_ok());
        assert!(validate_autofill("*.github.com", 0).is_ok());
        assert!(validate_autofill("api.github.com", 5).is_ok());
        assert!(validate_autofill("", 0).is_err());                // vacío
        assert!(validate_autofill(".github.com", 0).is_err());     // empieza con punto
        assert!(validate_autofill("github com", 0).is_err());      // espacio
        assert!(validate_autofill("github.com", 200).is_err());    // prioridad fuera de rango
    }

    #[test]
    fn test_generator() {
        assert!(validate_generator("Estándar", 20, 1, 1, 1, 4).is_ok());
        assert!(validate_generator("Test", 5, 1, 1, 1, 4).is_err());   // longitud < 8
        assert!(validate_generator("Test", 20, 10, 10, 5, 4).is_err()); // suma > longitud
        assert!(validate_generator("Test", 20, 1, 1, 1, 1).is_err());  // word_count < 2
    }
}
