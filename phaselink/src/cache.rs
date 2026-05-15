// ── Redis cache helpers ───────────────────────────────────────────────────────
// Simple GET / SETEX / DEL wrappers with 24-hour TTL and log-on-error semantics.
// Cache misses are silent (returns None); failures log warn! and return None/no-op.

use redis::AsyncCommands;
use tracing::{debug, warn};

const CACHE_TTL_SECS: u64 = 86_400; // 24 hours

pub async fn cache_get(redis: &mut redis::aio::ConnectionManager, key: &str) -> Option<String> {
    match redis.get::<_, Option<String>>(key).await {
        Ok(Some(v)) => {
            debug!("cache hit: {key}");
            Some(v)
        }
        Ok(None) => None,
        Err(e) => {
            warn!("cache GET {key} failed: {e}");
            None
        }
    }
}

pub async fn cache_set(redis: &mut redis::aio::ConnectionManager, key: &str, value: &str) {
    match redis.set_ex::<_, _, ()>(key, value, CACHE_TTL_SECS).await {
        Ok(_) => debug!("cache set: {key} (ttl={CACHE_TTL_SECS}s)"),
        Err(e) => warn!("cache SET {key} failed: {e}"),
    }
}

pub async fn cache_del(redis: &mut redis::aio::ConnectionManager, key: &str) {
    match redis.del::<_, ()>(key).await {
        Ok(_) => debug!("cache invalidated: {key}"),
        Err(e) => warn!("cache DEL {key} failed: {e}"),
    }
}

// Delete locally AND broadcast to other instances so their caches stay coherent.
pub async fn cache_invalidate(redis: &mut redis::aio::ConnectionManager, key: &str) {
    cache_del(redis, key).await;
    use redis::AsyncCommands as _;
    match redis.publish::<_, _, ()>("zeeble:cache:invalidate", key).await {
        Ok(_) => debug!("cache invalidate broadcast: {key}"),
        Err(e) => warn!("cache invalidate publish {key} failed: {e}"),
    }
}
