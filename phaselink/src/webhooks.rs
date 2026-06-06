use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{AppState, require_auth};

type HmacSha256 = Hmac<Sha256>;

fn gen_hex(bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..bytes)
        .map(|_| format!("{:02x}", rng.r#gen::<u8>()))
        .collect()
}

async fn require_owner(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let identity = require_auth(state, headers).await?;
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "only the server owner can manage webhooks" })),
        ));
    }
    Ok(identity)
}

// ── Management endpoints ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateWebhookPayload {
    name: String,
    url: String,
    /// Comma-separated event names. Supported: message, message_edited, message_deleted, member_join
    #[serde(default = "default_events")]
    events: String,
    /// If set, only fire for this channel.
    channel_id: Option<String>,
}

fn default_events() -> String {
    "message".to_string()
}

/// POST /v1/webhooks — create a webhook (owner only).
/// Returns the signing secret once — store it securely.
pub async fn create_webhook(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateWebhookPayload>,
) -> impl IntoResponse {
    let identity = match require_owner(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let name = payload.name.trim().to_string();
    let url = payload.url.trim().to_string();

    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "name is required" }))).into_response();
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "url must start with http:// or https://" }))).into_response();
    }

    // Validate event names
    let valid_events = ["message", "message_edited", "message_deleted", "member_join"];
    let events = payload.events.trim().to_string();
    for ev in events.split(',') {
        let ev = ev.trim();
        if !valid_events.contains(&ev) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("unknown event '{ev}' — valid: {}", valid_events.join(", ")) })),
            ).into_response();
        }
    }

    let id = gen_hex(16);
    let secret = gen_hex(32);

    let result = {
        let db = state.db.get().expect("db pool");
        db.execute(
            "INSERT INTO webhooks (id, name, url, secret, channel_id, events, created_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![id, name, url, secret, payload.channel_id, events, identity],
        )
    };

    match result {
        Ok(_) => {
            tracing::info!("webhook created: {name} (id={id}) by {identity}");
            Json(json!({
                "id": id,
                "name": name,
                "url": url,
                "events": events,
                "channel_id": payload.channel_id,
                "secret": secret,
            })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to create webhook: {e}") })),
        ).into_response(),
    }
}

/// GET /v1/webhooks — list webhooks (owner only). Secrets are not returned.
pub async fn list_webhooks(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_owner(&state, &headers).await {
        return e.into_response();
    }

    let webhooks: Vec<Value> = {
        let db = state.db.get().expect("db pool");
        let mut stmt = match db.prepare(
            "SELECT id, name, url, channel_id, events, created_by, created_at FROM webhooks ORDER BY created_at ASC"
        ) {
            Ok(s) => s,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": format!("{e}") }))).into_response(),
        };
        stmt.query_map([], |row| {
            Ok(json!({
                "id":         row.get::<_, String>(0)?,
                "name":       row.get::<_, String>(1)?,
                "url":        row.get::<_, String>(2)?,
                "channel_id": row.get::<_, Option<String>>(3)?,
                "events":     row.get::<_, String>(4)?,
                "created_by": row.get::<_, String>(5)?,
                "created_at": row.get::<_, i64>(6)?,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };

    Json(json!({ "webhooks": webhooks })).into_response()
}

/// DELETE /v1/webhooks/:id — delete a webhook (owner only).
pub async fn delete_webhook(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(webhook_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_owner(&state, &headers).await {
        return e.into_response();
    }

    let deleted = {
        let db = state.db.get().expect("db pool");
        db.execute("DELETE FROM webhooks WHERE id = ?1", rusqlite::params![webhook_id])
            .unwrap_or(0)
    };

    if deleted == 0 {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "webhook not found" }))).into_response();
    }

    tracing::info!("webhook deleted: {webhook_id}");
    Json(json!({ "ok": true })).into_response()
}

// ── Event dispatch ────────────────────────────────────────────────────────────

/// Fire an event to all matching webhooks. Non-async — spawns background tasks for all delivery.
/// `channel_id` — if Some, also matches webhooks scoped to that channel.
pub fn fire_event(state: Arc<AppState>, event: &'static str, channel_id: Option<String>, payload: Value) {
    tokio::spawn(async move {
        struct Hook {
            url: String,
            secret: String,
        }

        let hooks: Vec<Hook> = {
            let db = match state.db.get() {
                Ok(db) => db,
                Err(_) => return,
            };
            let mut stmt = match db.prepare(
                "SELECT url, secret FROM webhooks WHERE (channel_id IS NULL OR channel_id = ?1) AND (',' || events || ',') LIKE ('%,' || ?2 || ',%')"
            ) {
                Ok(s) => s,
                Err(_) => return,
            };
            let ch = channel_id.as_deref().unwrap_or("");
            stmt.query_map(rusqlite::params![ch, event], |row| {
                Ok(Hook { url: row.get(0)?, secret: row.get(1)? })
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
        };

        if hooks.is_empty() {
            return;
        }

        let body = serde_json::to_string(&json!({
            "event": event,
            "data": payload,
        }))
        .unwrap_or_default();

        let client = reqwest::Client::new();

        for hook in hooks {
            let sig = {
                let mut mac = HmacSha256::new_from_slice(hook.secret.as_bytes())
                    .expect("HMAC accepts any key size");
                mac.update(body.as_bytes());
                let result = mac.finalize();
                format!("sha256={}", hex::encode(result.into_bytes()))
            };

            let client = client.clone();
            let body_clone = body.clone();
            let url = hook.url.clone();
            tokio::spawn(async move {
                let res = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Zeeble-Signature", &sig)
                    .header("X-Zeeble-Event", event)
                    .body(body_clone)
                    .timeout(std::time::Duration::from_secs(10))
                    .send()
                    .await;
                match res {
                    Ok(r) if r.status().is_success() => {
                        tracing::debug!("webhook delivered to {url}: {}", r.status());
                    }
                    Ok(r) => {
                        tracing::warn!("webhook {url} returned non-2xx: {}", r.status());
                    }
                    Err(e) => {
                        tracing::warn!("webhook {url} delivery failed: {e}");
                    }
                }
            });
        }
    });
}
