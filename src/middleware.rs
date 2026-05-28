use axum::{
    async_trait,
    extract::FromRequestParts,
    http::request::Parts,
    RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::Utc;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::AppError, state::AppState};

/// Claims del JWT
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub:       String,   // user_id
    pub device_id: Option<String>,
    pub exp:       i64,
}

/// Extractor de Axum: cualquier handler que declare `AuthUser`
/// requiere automáticamente un JWT válido.
/// El compilador garantiza que no puedes olvidar proteger una ruta.
pub struct AuthUser {
    pub user_id:   Uuid,
    pub device_id: Option<Uuid>,
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AppError::Unauthorized)?;

        let mut validation = Validation::default();
        validation.validate_exp = true;

        let token_data = decode::<Claims>(
            bearer.token(),
            &DecodingKey::from_secret(state.cfg.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|_| AppError::Unauthorized)?;

        // Verificar que el token no está revocado en BD
        let token_hash = crate::crypto::hash_token(bearer.token());
        let revoked = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash = $1 AND revoked_at IS NOT NULL)"
        )
        .bind(&token_hash)
        .fetch_one(&state.db)
        .await
        .map_err(AppError::Database)?;

        if revoked {
            return Err(AppError::Unauthorized);
        }

        // Actualizar last_seen_at del dispositivo
        if let Some(did) = &token_data.claims.device_id {
            if let Ok(device_uuid) = Uuid::parse_str(did) {
                let _ = sqlx::query(
                    "UPDATE devices SET last_seen_at = NOW() WHERE id = $1"
                )
                .bind(device_uuid)
                .execute(&state.db)
                .await;
            }
        }

        Ok(AuthUser {
            user_id:   Uuid::parse_str(&token_data.claims.sub)
                           .map_err(|_| AppError::Unauthorized)?,
            device_id: token_data.claims.device_id
                           .as_deref()
                           .and_then(|s| Uuid::parse_str(s).ok()),
        })
    }
}

/// Genera un JWT firmado con expiración de 7 días
pub fn generate_token(
    user_id: Uuid,
    device_id: Option<Uuid>,
    secret: &str,
) -> anyhow::Result<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};

    let exp = (Utc::now() + chrono::Duration::days(7)).timestamp();
    let claims = Claims {
        sub:       user_id.to_string(),
        device_id: device_id.map(|d| d.to_string()),
        exp,
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?)
}
