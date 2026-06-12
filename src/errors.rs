use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("No autenticado")]
    Unauthorized,

    #[error("Sin permisos para esta acción")]
    Forbidden,

    #[error("Recurso no encontrado")]
    NotFound,

    #[error("Credenciales incorrectas")]
    InvalidCredentials,

    #[error("Email ya registrado")]
    EmailTaken,

    #[error("Token de invitación inválido o expirado")]
    InvalidInvitation,

    #[error("Conflicto de versión — re-sincroniza antes de actualizar")]
    VersionConflict,

    #[error("2FA requerido")]
    TwoFactorRequired,

    #[error("Código 2FA inválido")]
    InvalidTOTP,

    #[error("Error de validación: {0}")]
    Validation(String),

    #[error("Error de base de datos")]
    Database(#[from] sqlx::Error),

    #[error("Error interno")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized        => (StatusCode::UNAUTHORIZED,            self.to_string()),
            AppError::Forbidden           => (StatusCode::FORBIDDEN,               self.to_string()),
            AppError::NotFound            => (StatusCode::NOT_FOUND,               self.to_string()),
            AppError::InvalidCredentials  => (StatusCode::UNAUTHORIZED,            self.to_string()),
            AppError::EmailTaken          => (StatusCode::CONFLICT,                self.to_string()),
            AppError::InvalidInvitation   => (StatusCode::GONE,                    self.to_string()),
            AppError::VersionConflict     => (StatusCode::CONFLICT,                self.to_string()),
            AppError::TwoFactorRequired   => (StatusCode::UNAUTHORIZED,            self.to_string()),
            AppError::InvalidTOTP         => (StatusCode::UNAUTHORIZED,            self.to_string()),
            AppError::Validation(msg)     => (StatusCode::UNPROCESSABLE_ENTITY,    msg.clone()),
            AppError::Database(e) => {
                tracing::error!("DB error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Error interno".into())
            }
            AppError::Internal(e) => {
                tracing::error!("Internal error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Error interno".into())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
