// ── Live Link — voice endpoints ───────────────────────────────────────────────
// Proxies to the livekit-api service to issue LiveKit room tokens and list rooms.
// All endpoints require a valid Zeeble JWT.

use axum::{
    Json,
    extract::{Extension, Path, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use super::{AppState, require_auth};

// ── GET /voice/token?channel_id=<id> ─────────────────────────────────────────

#[derive(Deserialize)]
pub struct VoiceTokenQuery {
    channel_id: String,
}

/// Return a LiveKit participant token for the given channel's voice room.
/// The room name equals the channel ID, so each text channel doubles as a
/// voice room — no extra configuration needed.
pub async fn get_voice_token(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<VoiceTokenQuery>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    if query.channel_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "channel_id is required" })),
        )
            .into_response();
    }

    let url = format!("{}/token", state.livekit_api_url);
    let body = json!({
        "room":     query.channel_id,
        "identity": identity,
        "name":     identity,
        "permissions": {
            "can_publish":   true,
            "can_subscribe": true,
        },
        "ttl": 3600,
    });

    forward_livekit_with_url(&url, &body, &state.livekit_bridge_secret).await
}

// ── GET /voice/rooms ──────────────────────────────────────────────────────────

/// List active LiveKit rooms (and their participants).
pub async fn get_voice_rooms(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers).await {
        return e.into_response();
    }

    let url = format!("{}/rooms", state.livekit_api_url);
    let client = reqwest::Client::new();

    match client.get(&url).header("X-Bridge-Secret", &state.livekit_bridge_secret).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(data) => Json(data).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to parse LiveKit response: {e}") })),
            )
                .into_response(),
        },
        Ok(resp) => {
            let status = resp.status();
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("LiveKit API returned {status}") })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Could not reach LiveKit API: {e}") })),
        )
            .into_response(),
    }
}

// ── GET /voice/participants/:channel_id ───────────────────────────────────────

/// List participants in a LiveKit room (channel).
pub async fn get_voice_participants(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers).await {
        return e.into_response();
    }

    if channel_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "channel_id is required" })),
        )
            .into_response();
    }

    let url = format!("{}/rooms/{}/participants", state.livekit_api_url, channel_id);
    let client = reqwest::Client::new();

    match client.get(&url).header("X-Bridge-Secret", &state.livekit_bridge_secret).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(data) => Json(data).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to parse LiveKit response: {e}") })),
            )
                .into_response(),
        },
        Ok(resp) if resp.status() == StatusCode::NOT_FOUND => {
            Json(json!({ "participants": [] })).into_response()
        }
        Ok(resp) => {
            let status = resp.status();
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("LiveKit API returned {status}") })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Could not reach LiveKit API: {e}") })),
        )
            .into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// POST `url` with `body` and return the response unchanged.
/// The LiveKit API response includes the `livekit_url` field which clients
/// will connect to directly (no reverse proxy involvement).
async fn forward_livekit_with_url(url: &str, body: &Value, bridge_secret: &str) -> axum::response::Response {
    let client = reqwest::Client::new();
    match client.post(url).header("X-Bridge-Secret", bridge_secret).json(body).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
            Ok(data) => {
                Json(data).into_response()
            }
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Failed to parse LiveKit response: {e}") })),
            )
                .into_response(),
        },
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": format!("LiveKit API error {status}: {text}") })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("Could not reach LiveKit API: {e}") })),
        )
            .into_response(),
    }
}
