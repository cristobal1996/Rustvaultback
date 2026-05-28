// src/pagination.rs
//
// Módulo de paginación reutilizable para todos los endpoints que
// devuelven listas de datos.
//
// USO:
//   async fn list_entries(Query(params): Query<PaginationParams>, ...) {
//       let (page, limit) = params.validated()?;
//       let offset = (page - 1) * limit;
//
//       let total = sqlx::query_scalar!("SELECT COUNT(*) FROM entries WHERE vault_id = $1", vault_id)
//           .fetch_one(&db).await?;
//
//       let items = sqlx::query_as!(Entry,
//           "SELECT * FROM entries WHERE vault_id = $1 LIMIT $2 OFFSET $3",
//           vault_id, limit, offset)
//           .fetch_all(&db).await?;
//
//       Ok(Json(Paginated::new(items, total, page, limit)))
//   }

use serde::{Deserialize, Serialize};
use crate::errors::Result;

// ── Parámetros de entrada ─────────────────────────────────────────

/// Parámetros de paginación que llegan como query params en la URL.
/// Ejemplo: ?page=2&limit=25
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page:  Option<i64>,
    pub limit: Option<i64>,
}

impl PaginationParams {
    /// Valida y normaliza los parámetros.
    /// Devuelve (page, limit) listos para usar en las queries SQL.
    pub fn validated(&self) -> Result<(i64, i64)> {
        crate::validation::validate_pagination(self.page, self.limit)
    }

    /// Calcula el OFFSET para la query SQL.
    pub fn offset(&self) -> Result<i64> {
        let (page, limit) = self.validated()?;
        Ok((page - 1) * limit)
    }
}

// ── Respuesta paginada ────────────────────────────────────────────

/// Metadata de paginación que se incluye en cada respuesta.
#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub page:        i64,
    pub limit:       i64,
    pub total:       i64,   // total de elementos (no de páginas)
    pub total_pages: i64,
    pub has_next:    bool,
    pub has_prev:    bool,
}

/// Respuesta envuelta con paginación.
/// T es el tipo de los elementos (Entry, Vault, AuditLog...)
#[derive(Debug, Serialize)]
pub struct Paginated<T: Serialize> {
    pub data:       Vec<T>,
    pub pagination: PaginationMeta,
}

impl<T: Serialize> Paginated<T> {
    pub fn new(data: Vec<T>, total: i64, page: i64, limit: i64) -> Self {
        let total_pages = if limit > 0 { (total + limit - 1) / limit } else { 0 };

        Self {
            data,
            pagination: PaginationMeta {
                page,
                limit,
                total,
                total_pages,
                has_next: page < total_pages,
                has_prev: page > 1,
            },
        }
    }
}
