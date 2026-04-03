use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use governor::{
    clock::DefaultClock,
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};
use livekit_api::services::room::RoomClient;
use serde::Deserialize;
use serde_json::{json, Value};
use std::num::NonZeroU32;
use std::sync::Arc;

use crate::{
    config::AppState,
    error::{AppError, AppResult},
    rooms,
    token::{self, ParticipantPermissions},
};

// ─── Rate Limiting ────────────────────────────────────────────────────────────

pub type TokenRateLimiter = Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>;

/// Create a rate limiter for the /token endpoint (10 req/min per identity)
pub fn create_token_rate_limiter() -> TokenRateLimiter {
    let quota = Quota::per_minute(NonZeroU32::new(10).unwrap());
    Arc::new(RateLimiter::keyed(quota))
}

fn check_rate_limit(limiter: &TokenRateLimiter, identity: &str) -> Result<(), AppError> {
    match limiter.check_key(&identity.to_string()) {
        Ok(_) => Ok(()),
        Err(_) => Err(AppError::RateLimited),
    }
}

// ─── Health ──────────────────────────────────────────────────────────────────

pub fn health_routes() -> Router<AppState> {
    Router::new().route("/health", get(health_handler))
}

async fn health_handler() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "livekit-management-server",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

// ─── Token Routes ─────────────────────────────────────────────────────────────

pub fn token_routes(rate_limiter: TokenRateLimiter) -> Router<AppState> {
    Router::new()
        .route("/token", post({
            let limiter = rate_limiter.clone();
            move |state: State<AppState>, json: Json<CreateTokenRequest>| {
                let limiter = limiter.clone();
                async move { create_token_handler(state, json, limiter).await }
            }
        }))
}

#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    room: String,
    identity: String,
    name: Option<String>,
    #[serde(default)]
    permissions: ParticipantPermissions,
    #[serde(default = "default_ttl")]
    ttl: u64,
}

fn default_ttl() -> u64 { 3600 }

async fn create_token_handler(
    State(state): State<AppState>,
    Json(req): Json<CreateTokenRequest>,
    rate_limiter: TokenRateLimiter,
) -> AppResult<Json<Value>> {
    // Rate limit check by identity (10 requests per minute)
    check_rate_limit(&rate_limiter, &req.identity)?;

    if req.room.is_empty() {
        return Err(AppError::BadRequest("room name cannot be empty".into()));
    }
    if req.identity.is_empty() {
        return Err(AppError::BadRequest("identity cannot be empty".into()));
    }

    let token_resp = token::generate_token(
        &state.config.livekit_api_key,
        &state.config.livekit_api_secret,
        &req.room,
        &req.identity,
        req.name.as_deref(),
        &req.permissions,
        req.ttl,
    )?;

    Ok(Json(json!({
        "token": token_resp.token,
        "room": token_resp.room,
        "identity": token_resp.identity,
        "expires_at": token_resp.expires_at,
        "livekit_url": state.config.livekit_public_url.replace("http://", "ws://").replace("https://", "wss://"),
    })))
}

// ─── Room Routes ──────────────────────────────────────────────────────────────

pub fn room_routes() -> Router<AppState> {
    Router::new()
        .route("/rooms", get(list_rooms_handler))
        .route("/rooms", post(create_room_handler))
        .route("/rooms/:name", delete(delete_room_handler))
        .route("/rooms/:name/participants", get(list_participants_handler))
}

async fn list_rooms_handler(State(state): State<AppState>) -> AppResult<Json<Value>> {
    let client = make_room_client(&state)?;
    let rooms = rooms::list_rooms(&client).await?;
    Ok(Json(json!({ "rooms": rooms })))
}

async fn create_room_handler(
    State(state): State<AppState>,
    Json(req): Json<rooms::CreateRoomRequest>,
) -> AppResult<Json<Value>> {
    if req.name.is_empty() {
        return Err(AppError::BadRequest("room name cannot be empty".into()));
    }
    let client = make_room_client(&state)?;
    let room = rooms::create_room(&client, req).await?;
    Ok(Json(serde_json::to_value(room).unwrap()))
}

async fn delete_room_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> AppResult<Json<Value>> {
    let client = make_room_client(&state)?;
    rooms::delete_room(&client, &name).await?;
    Ok(Json(json!({ "deleted": name })))
}

async fn list_participants_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> AppResult<Json<Value>> {
    let client = make_room_client(&state)?;
    let participants = rooms::list_participants(&client, &name).await?;
    Ok(Json(json!({ "participants": participants })))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// RoomClient::new() takes only the host; it reads LIVEKIT_API_KEY and
// LIVEKIT_API_SECRET from the environment automatically.
fn make_room_client(state: &AppState) -> AppResult<RoomClient> {
    RoomClient::new(&state.config.livekit_host)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("RoomClient init failed: {}", e)))
}
