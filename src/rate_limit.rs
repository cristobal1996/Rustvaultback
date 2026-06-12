// src/rate_limit.rs
//
// Rate limiter por IP con ventana deslizante en memoria.
//
// No usa dependencias externas. Mantiene un HashMap<(IP, accion), Vec<Instant>>
// con los timestamps de las últimas peticiones. Cuando llega una petición:
//   1. Filtra los timestamps fuera de la ventana
//   2. Si quedan >= limit, rechaza
//   3. Si quedan < limit, añade el timestamp actual y permite
//
// Limpieza periódica: una tarea en background elimina entradas viejas para
// que el HashMap no crezca indefinidamente.
//
// Coste: O(N) por petición donde N es el número de intentos recientes de
// esa IP+acción. Para los límites que usamos (≤5 por hora) es despreciable.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::errors::{AppError, Result};

/// Clave del rate limiter: par (IP, acción).
/// "acción" identifica el endpoint protegido (p.ej. "login", "register").
type Key = (IpAddr, &'static str);

#[derive(Clone, Default)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<Key, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Comprueba si la petición puede pasar. Si supera el límite, devuelve
    /// un error 429 (TooManyRequests). Si pasa, registra el intento.
    ///
    /// Parámetros:
    /// - ip:      dirección IP del cliente
    /// - action:  identificador del endpoint (literal estático)
    /// - limit:   número máximo de peticiones permitidas en la ventana
    /// - window:  duración de la ventana deslizante
    pub fn check(
        &self,
        ip: IpAddr,
        action: &'static str,
        limit: usize,
        window: Duration,
    ) -> Result<()> {
        let now      = Instant::now();
        let cutoff   = now.checked_sub(window).unwrap_or(now);
        let key      = (ip, action);
        let mut map  = self.inner.lock().unwrap();

        let entries  = map.entry(key).or_insert_with(Vec::new);
        // Quitar timestamps fuera de la ventana
        entries.retain(|t| *t > cutoff);

        if entries.len() >= limit {
            // Calcular cuánto falta para que se pueda reintentar
            let oldest_in_window = entries.first().copied().unwrap_or(now);
            let retry_after_secs = window
                .saturating_sub(now.duration_since(oldest_in_window))
                .as_secs()
                .max(1);

            tracing::warn!(
                "Rate limit superado: ip={} action={} (intentos={}/{}, reintentar en {}s)",
                ip, action, entries.len(), limit, retry_after_secs
            );

            return Err(AppError::Validation(format!(
                "Demasiados intentos. Inténtalo de nuevo en {} segundos.",
                retry_after_secs
            )));
        }

        // Registrar el intento actual
        entries.push(now);
        Ok(())
    }

    /// Limpia entradas antiguas para evitar crecimiento ilimitado del HashMap.
    /// Se llama periódicamente desde una tarea en background.
    pub fn cleanup(&self, max_age: Duration) {
        let now      = Instant::now();
        let cutoff   = now.checked_sub(max_age).unwrap_or(now);
        let mut map  = self.inner.lock().unwrap();

        // Para cada entrada: quitar timestamps viejos; si quedan vacíos, quitar la clave
        map.retain(|_, entries| {
            entries.retain(|t| *t > cutoff);
            !entries.is_empty()
        });
    }
}

/// Arranca la tarea de limpieza periódica en background.
/// Cada `interval`, llama a `cleanup` para purgar entradas más viejas que `max_age`.
pub fn start_cleanup_task(limiter: RateLimiter, interval: Duration, max_age: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            limiter.cleanup(max_age);
        }
    });
}

// ─────────────────────────────────────────────────────────────────
// Helper para extraer la IP del cliente desde un handler de Axum.
// ─────────────────────────────────────────────────────────────────

use std::net::SocketAddr;

/// Extrae la IP del cliente desde el `ConnectInfo<SocketAddr>` del request.
/// Si la app está detrás de un proxy (nginx, Cloudflare...), considera leer
/// el header `X-Forwarded-For` o `X-Real-IP` aquí.
pub fn client_ip(addr: &SocketAddr) -> IpAddr {
    addr.ip()
}
