use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, require_auth};
use crate::config::{BOT_MSG_MAX_PER_WINDOW, BOT_MSG_WINDOW_SECS};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Generate a random lowercase hex string of the given byte length (output is 2× chars).
fn gen_hex(bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..bytes)
        .map(|_| format!("{:02x}", rng.r#gen::<u8>()))
        .collect()
}

/// Check that the caller is the server owner; returns Err(response) if not.
async fn require_owner(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let identity = require_auth(state, headers).await?;
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "only the server owner can manage bots" })),
        ));
    }
    Ok(identity)
}

// ── Bot auth helper ───────────────────────────────────────────────────────────

/// Validate an `Authorization: Bot <token>` header.
/// Returns `(bot_id, bot_name)` or a 401 error response.
pub async fn require_bot_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bot "));

    let Some(token) = token else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing Bot token — use Authorization: Bot <token>" })),
        ));
    };

    let result = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT id, name FROM bots WHERE token = ?1",
            rusqlite::params![token],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .ok()
    };

    match result {
        Some((id, name)) => Ok((id, name)),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid bot token" })),
        )),
    }
}

// ── Bot management ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateBotPayload {
    name: String,
}

/// POST /bots — create a new bot (owner only).
/// Returns the bot's token — shown once, store it securely.
pub async fn create_bot(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateBotPayload>,
) -> impl IntoResponse {
    let identity = match require_owner(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "bot name is required" })),
        )
            .into_response();
    }

    let id = gen_hex(16);
    let token = gen_hex(32);

    let result = {
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO bots (id, name, token, created_by) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, name, token, identity],
        )
    };

    match result {
        Ok(_) => {
            tracing::info!("bot created: {name} (id={id}) by {identity}");
            Json(json!({
                "id": id,
                "name": name,
                // Token is only shown once — the caller must store it
                "token": token,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to create bot: {e}") })),
        )
            .into_response(),
    }
}

/// GET /bots — list all bots (owner only). Tokens are not returned.
pub async fn list_bots(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_owner(&state, &headers).await {
        return e.into_response();
    }

    let bots: Vec<Value> = {
        let db = state.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT id, name, created_by, created_at FROM bots ORDER BY created_at ASC",
            )
            .unwrap();
        stmt.query_map([], |row| {
            Ok(json!({
                "id":         row.get::<_, String>(0)?,
                "name":       row.get::<_, String>(1)?,
                "created_by": row.get::<_, String>(2)?,
                "created_at": row.get::<_, i64>(3)?,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };

    Json(json!({ "bots": bots })).into_response()
}

/// DELETE /bots/:id — delete a bot (owner only).
pub async fn delete_bot(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(bot_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_owner(&state, &headers).await {
        return e.into_response();
    }

    let deleted = {
        let db = state.db.lock().unwrap();
        db.execute("DELETE FROM bots WHERE id = ?1", rusqlite::params![bot_id])
            .unwrap_or(0)
    };

    if deleted == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "bot not found" })),
        )
            .into_response();
    }

    tracing::info!("bot deleted: {bot_id}");
    Json(json!({ "ok": true })).into_response()
}

// ── Bot actions ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BotMessagePayload {
    content: String,
}

/// POST /bot/channels/:channel_id/messages — send a message as a bot.
pub async fn bot_send_message(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Json(payload): Json<BotMessagePayload>,
) -> impl IntoResponse {
    let (bot_id, bot_name) = match require_bot_auth(&state, &headers).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    // ── Rate limit check ──────────────────────────────────────────────
    {
        let mut limits = state.bot_rate_limits.lock().unwrap();
        let now = Instant::now();
        let entry = limits.entry(bot_id.clone()).or_insert((0, now));
        if entry.1.elapsed().as_secs() >= BOT_MSG_WINDOW_SECS {
            *entry = (0, now);
        }
        entry.0 += 1;
        if entry.0 > BOT_MSG_MAX_PER_WINDOW {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": format!("bot message rate limit exceeded ({BOT_MSG_MAX_PER_WINDOW}/{BOT_MSG_WINDOW_SECS}s)"), "retry_after": BOT_MSG_WINDOW_SECS })),
            )
                .into_response();
        }
    }

    let content = payload.content.trim().to_string();
    if content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "content is required" })),
        )
            .into_response();
    }

    let max_len = state.settings.read().await.max_message_length as usize;
    if content.len() > max_len {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("message too long (max {max_len} chars)") })),
        )
            .into_response();
    }

    let exists = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT 1 FROM channels WHERE id = ?1",
            rusqlite::params![channel_id],
            |_| Ok(true),
        )
        .unwrap_or(false)
    };
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "channel not found" })),
        )
            .into_response();
    }

    let beam_identity = format!("bot:{bot_name}");
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let msg_id = {
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO messages (channel_id, beam_identity, content, created_at, bot_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![channel_id, beam_identity, content, created_at, bot_id],
        )
        .expect("insert bot message");
        db.last_insert_rowid()
    };

    // Broadcast to channel bus so WebSocket clients see the message in real time
    let broadcast = serde_json::to_string(&json!({
        "type":          "message",
        "id":            msg_id,
        "channel_id":    channel_id,
        "beam_identity": beam_identity,
        "content":       content,
        "created_at":    created_at,
        "attachments":   [],
    }))
    .unwrap();
    let _ = state.bus_for(&channel_id).send(broadcast);

    tracing::info!("bot:{bot_name} sent message {msg_id} in #{channel_id}");
    Json(json!({ "id": msg_id, "ok": true })).into_response()
}

/// GET /bot/channels/:channel_id/messages — read recent messages (bot token auth).
pub async fn bot_get_messages(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_bot_auth(&state, &headers).await {
        return e.into_response();
    }

    let messages: Vec<Value> = {
        let db = state.db.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT id, beam_identity, content, created_at, edited_at
                 FROM messages WHERE channel_id = ?1
                 ORDER BY created_at DESC LIMIT 50",
            )
            .unwrap();
        stmt.query_map(rusqlite::params![channel_id], |row| {
            Ok(json!({
                "id":            row.get::<_, i64>(0)?,
                "beam_identity": row.get::<_, String>(1)?,
                "content":       row.get::<_, String>(2)?,
                "created_at":    row.get::<_, i64>(3)?,
                "edited_at":     row.get::<_, Option<i64>>(4)?,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };

    Json(json!({ "messages": messages })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_hex_produces_expected_length() {
        // gen_hex produces 2 hex chars per byte
        assert_eq!(gen_hex(16).len(), 32);
        assert_eq!(gen_hex(32).len(), 64);
        assert_eq!(gen_hex(1).len(), 2);
    }

    #[test]
    fn gen_hex_is_lowercase() {
        for _ in 0..20 {
            let s = gen_hex(16);
            assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn gen_hex_uniqueness() {
        let a = gen_hex(16);
        let b = gen_hex(16);
        assert_ne!(a, b); // vanishingly unlikely to collide
    }

    #[test]
    fn bot_rate_constants() {
        assert_eq!(BOT_MSG_MAX_PER_WINDOW, 60);
        assert_eq!(BOT_MSG_WINDOW_SECS, 60);
    }

    #[test]
    fn bot_identity_prefix_format() {
        // Validate the convention used in bot_send_message
        let bot_name = "testbot";
        let identity = format!("bot:{}", bot_name);
        assert_eq!(identity, "bot:testbot");
        assert!(identity.starts_with("bot:"));
    }
}
