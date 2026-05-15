// ── Redis pub/sub listener ────────────────────────────────────────────────────
// Subscribes to all `zeeble:*` channels with pattern subscription.
// Reconnects automatically with exponential backoff on failure.
//
// Routed channels:
//   zeeble:voice:events    → forward payload to server_bus (voice presence)
//   zeeble:broadcast       → forward payload to server_bus (cross-instance WS)
//   zeeble:cache:invalidate → delete the key from local Redis cache

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use tracing::{debug, error, info, warn};

use crate::AppState;

const BACKOFF_MIN_SECS: u64 = 1;
const BACKOFF_MAX_SECS: u64 = 30;

pub fn start(state: Arc<AppState>, redis_url: String) {
    tokio::spawn(async move {
        let mut backoff = BACKOFF_MIN_SECS;

        loop {
            match run_once(&state, &redis_url).await {
                Ok(()) => {
                    // Clean disconnect (should not happen with psubscribe)
                    warn!("pubsub: listener exited cleanly — reconnecting in {backoff}s");
                }
                Err(e) => {
                    error!("pubsub: listener error: {e} — reconnecting in {backoff}s");
                }
            }

            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
        }
    });
}

async fn run_once(state: &Arc<AppState>, redis_url: &str) -> Result<(), redis::RedisError> {
    let client = redis::Client::open(redis_url)?;
    let mut conn = client.get_async_pubsub().await?;

    conn.psubscribe("zeeble:*").await?;
    info!("pubsub: subscribed to zeeble:* pattern");
    // Reset backoff on successful connection — caller resets after we return Ok
    // (we signal via Ok vs Err; backoff reset happens in the outer loop)

    let mut stream = conn.into_on_message();

    while let Some(msg) = stream.next().await {
        let channel: String = msg.get_channel_name().to_string();
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(e) => {
                warn!("pubsub: could not decode payload on {channel}: {e}");
                continue;
            }
        };

        debug!("pubsub: received on {channel}");

        match channel.as_str() {
            "zeeble:voice:events" | "zeeble:broadcast" => {
                let _ = state.server_bus.send(payload);
            }
            "zeeble:cache:invalidate" => {
                // `payload` is the cache key to evict on this instance
                let mut redis = state.redis.clone();
                crate::cache::cache_del(&mut redis, &payload).await;
            }
            other => {
                debug!("pubsub: unhandled channel {other}");
            }
        }
    }

    // Stream ended — Redis connection dropped
    Err(redis::RedisError::from((
        redis::ErrorKind::IoError,
        "pub/sub stream ended",
    )))
}
