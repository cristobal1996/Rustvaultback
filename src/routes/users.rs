// src/routes/users.rs — búsqueda por invite_code

use axum::{extract::{Query, State}, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{errors::{AppError, Result}, middleware::AuthUser, state::AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/search", get(search_by_invite_code))
}

#[derive(Deserialize)]
pub struct SearchQuery { q: String }

#[derive(Serialize)]
pub struct UserSearchResult {
    pub id:          Uuid,
    pub email_hint:  String,
    pub pub_key:     Option<String>,
    pub invite_code: Option<String>,
}

async fn search_by_invite_code(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<SearchQuery>,
) -> Result<Json<Vec<UserSearchResult>>> {
    let code = q.q.trim().to_uppercase();
    if code.len() < 3 {
        return Err(AppError::Validation("El código debe tener al menos 3 caracteres".into()))
    }

    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Option<String>)>(
        "SELECT id, LEFT(email,3)||'***' AS email_hint, pub_key, invite_code
         FROM users
         WHERE upper(invite_code)=upper($1) AND id!=$2 AND deleted_at IS NULL
         LIMIT 1"
    )
    .bind(&code).bind(auth.user_id)
    .fetch_all(&state.db).await?;

    let results = rows.into_iter().map(|(id, email_hint, pub_key, invite_code)| {
        UserSearchResult { id, email_hint, pub_key, invite_code }
    }).collect();

    Ok(Json(results))
}
