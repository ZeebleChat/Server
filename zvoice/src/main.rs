use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use redis::AsyncCommands;
use serde_json::json;
use tokio::sync::broadcast;
use tower_http::cors::{AllowHeaders, AllowMethods, CorsLayer};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use tracing::{error, info, warn};

mod auth;
mod ws;

pub use auth::JwksStore;

// ── State ─────────────────────────────────────────────────────────────────────

pub type ChannelBus = Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>;

pub struct AppState {
    pub voice_buses: ChannelBus,
    pub stream_buses: ChannelBus,
    pub stream_broadcasters: Arc<Mutex<HashMap<String, String>>>,
    pub voice_members: Arc<Mutex<HashMap<String, HashSet<String>>>>,
    pub jwks: Arc<Mutex<JwksStore>>,
    pub auth_server_url: String,
    pub server_bus: broadcast::Sender<String>,
    pub redis: redis::aio::ConnectionManager,
}

impl AppState {
    pub fn voice_bus_for(&self, channel_id: &str) -> broadcast::Sender<String> {
        let mut map = self.voice_buses.lock().unwrap();
        map.entry(channel_id.to_string())
            .or_insert_with(|| broadcast::channel::<String>(4096).0)
            .clone()
    }

    pub fn stream_bus_for(&self, channel_id: &str) -> broadcast::Sender<String> {
        let mut map = self.stream_buses.lock().unwrap();
        map.entry(channel_id.to_string())
            .or_insert_with(|| broadcast::channel::<String>(4096).0)
            .clone()
    }

    pub fn claim_stream(&self, channel_id: &str, identity: &str) -> bool {
        let mut map = self.stream_broadcasters.lock().unwrap();
        if map.contains_key(channel_id) {
            return false;
        }
        map.insert(channel_id.to_string(), identity.to_string());
        true
    }

    pub fn release_stream(&self, channel_id: &str, identity: &str) {
        let mut map = self.stream_broadcasters.lock().unwrap();
        if map.get(channel_id).map(|s| s.as_str()) == Some(identity) {
            map.remove(channel_id);
        }
    }

    pub fn stream_broadcaster(&self, channel_id: &str) -> Option<String> {
        self.stream_broadcasters.lock().unwrap().get(channel_id).cloned()
    }

    pub fn voice_join(&self, channel_id: &str, identity: &str) {
        let mut rooms = self.voice_members.lock().unwrap();
        rooms
            .entry(channel_id.to_string())
            .or_default()
            .insert(identity.to_string());
    }

    pub fn voice_leave(&self, channel_id: &str, identity: &str) {
        let mut rooms = self.voice_members.lock().unwrap();
        if let Some(members) = rooms.get_mut(channel_id) {
            members.remove(identity);
            if members.is_empty() {
                rooms.remove(channel_id);
            }
        }
    }

    pub fn voice_leave_all(&self, identity: &str) -> Vec<String> {
        let mut rooms = self.voice_members.lock().unwrap();
        let mut left = Vec::new();
        for (channel_id, members) in rooms.iter_mut() {
            if members.remove(identity) {
                left.push(channel_id.clone());
            }
        }
        rooms.retain(|_, members| !members.is_empty());
        left
    }

    pub fn voice_participants(&self, channel_id: &str) -> Vec<String> {
        let rooms = self.voice_members.lock().unwrap();
        rooms
            .get(channel_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }
}

// ── REST handlers ─────────────────────────────────────────────────────────────

async fn get_voice_rooms(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = auth::require_auth(&state, &headers).await {
        return e.into_response();
    }
    let mut redis = state.redis.clone();
    let room_ids: Vec<String> = match redis.smembers("voice:rooms").await {
        Ok(ids) => ids,
        Err(e) => {
            error!("GET /v1/voice/rooms: redis SMEMBERS voice:rooms failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "voice state unavailable" })),
            )
                .into_response();
        }
    };
    let mut rooms = Vec::new();
    for channel_id in room_ids {
        let participants: Vec<String> = match redis
            .smembers(format!("voice:room:{channel_id}"))
            .await
        {
            Ok(p) => p,
            Err(e) => {
                warn!("GET /v1/voice/rooms: redis SMEMBERS voice:room:{channel_id} failed: {e}");
                state.voice_participants(&channel_id)
            }
        };
        if !participants.is_empty() {
            rooms.push(json!({
                "channel_id": channel_id,
                "participant_count": participants.len(),
                "participants": participants,
            }));
        }
    }
    Json(json!({ "rooms": rooms })).into_response()
}

async fn get_voice_participants(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = auth::require_auth(&state, &headers).await {
        return e.into_response();
    }
    let mut redis = state.redis.clone();
    let participants: Vec<String> = match redis
        .smembers(format!("voice:room:{channel_id}"))
        .await
    {
        Ok(p) => p,
        Err(e) => {
            warn!("GET /v1/voice/participants/{channel_id}: redis failed: {e}");
            state.voice_participants(&channel_id)
        }
    };
    Json(json!({ "channel_id": channel_id, "participants": participants })).into_response()
}

async fn list_streams(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = auth::require_auth(&state, &headers).await {
        return e.into_response();
    }
    let mut redis = state.redis.clone();
    let channel_ids: Vec<String> = match redis.smembers("stream:live").await {
        Ok(ids) => ids,
        Err(e) => {
            error!("GET /v1/streams: redis SMEMBERS stream:live failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "stream state unavailable" })),
            )
                .into_response();
        }
    };
    let mut streams = Vec::new();
    for channel_id in channel_ids {
        let broadcaster: Option<String> = match redis.get(format!("stream:{channel_id}")).await {
            Ok(b) => b,
            Err(e) => {
                warn!("GET /v1/streams: redis GET stream:{channel_id} failed: {e}");
                None
            }
        };
        if let Some(broadcaster) = broadcaster {
            streams.push(json!({ "channel_id": channel_id, "broadcaster": broadcaster }));
        }
    }
    Json(json!({ "streams": streams })).into_response()
}

async fn get_stream(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = auth::require_auth(&state, &headers).await {
        return e.into_response();
    }
    let mut redis = state.redis.clone();
    let broadcaster: Option<String> = match redis.get(format!("stream:{channel_id}")).await {
        Ok(b) => b,
        Err(e) => {
            warn!("GET /v1/stream/{channel_id}: redis GET failed: {e}");
            None
        }
    };
    match broadcaster {
        Some(b) => Json(json!({ "live": true, "channel_id": channel_id, "broadcaster": b }))
            .into_response(),
        None => Json(json!({ "live": false, "channel_id": channel_id })).into_response(),
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "zvoice=info,tower_http=debug".into()),
            )
            .init();

        let _ = dotenvy::dotenv();

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(4001);

        let auth_server_url = std::env::var("AUTH_SERVER_URL")
            .unwrap_or_else(|_| "http://localhost:3001".into());

        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".into());

        let allowed_origins: Vec<String> = std::env::var("ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // ── Redis ─────────────────────────────────────────────────────────────
        let redis_client = redis::Client::open(redis_url.as_str())
            .unwrap_or_else(|e| panic!("Invalid REDIS_URL '{redis_url}': {e}"));
        let redis_conn = redis::aio::ConnectionManager::new(redis_client)
            .await
            .unwrap_or_else(|e| panic!("Failed to connect to Redis at '{redis_url}': {e}"));
        info!("Redis connected: {redis_url}");

        let (server_bus, _) = broadcast::channel::<String>(256);

        let state = Arc::new(AppState {
            voice_buses: Arc::new(Mutex::new(HashMap::new())),
            stream_buses: Arc::new(Mutex::new(HashMap::new())),
            stream_broadcasters: Arc::new(Mutex::new(HashMap::new())),
            voice_members: Arc::new(Mutex::new(HashMap::new())),
            jwks: Arc::new(Mutex::new(JwksStore { keys: HashMap::new() })),
            auth_server_url: auth_server_url.clone(),
            server_bus,
            redis: redis_conn,
        });

        // ── Fetch JWKS ────────────────────────────────────────────────────────
        let auth_url_for_jwks = auth_server_url.clone();
        match tokio::task::spawn_blocking(move || auth::fetch_jwks(&auth_url_for_jwks))
            .await
            .unwrap()
        {
            Ok(jwks_store) => {
                *state.jwks.lock().unwrap() = jwks_store;
                info!("JWKS fetched from {auth_server_url}");
            }
            Err(e) => {
                eprintln!("FATAL: Failed to fetch JWKS from auth server: {e}");
                std::process::exit(1);
            }
        }

        // ── CORS ──────────────────────────────────────────────────────────────
        let cors_origin = if allowed_origins.is_empty() {
            tower_http::cors::AllowOrigin::mirror_request()
        } else {
            tower_http::cors::AllowOrigin::list(
                allowed_origins
                    .iter()
                    .filter_map(|o| axum::http::HeaderValue::from_str(o).ok())
                    .collect::<Vec<_>>(),
            )
        };
        let cors_layer = CorsLayer::new()
            .allow_origin(cors_origin)
            .allow_methods(AllowMethods::any())
            .allow_headers(AllowHeaders::list([
                AUTHORIZATION,
                CONTENT_TYPE,
                axum::http::header::ACCEPT,
            ]));

        let app = Router::<()>::new()
            .route(
                "/health",
                get(|| async {
                    Json(json!({ "status": "ok", "service": "zvoice", "version": "0.1.0" }))
                }),
            )
            .route("/v1/ws", get(ws::ws_handler))
            .route("/v1/voice/rooms", get(get_voice_rooms))
            .route("/v1/voice/participants/:channel_id", get(get_voice_participants))
            .route("/v1/streams", get(list_streams))
            .route("/v1/stream/:channel_id", get(get_stream))
            .layer(axum::extract::Extension(state))
            .layer(cors_layer);

        let addr = format!("0.0.0.0:{port}");
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to bind {addr}: {e}"));

        println!("zvoice listening on {addr}");
        info!("zvoice listening on {addr}");

        let server = axum::serve(listener, app.into_make_service());
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received — shutting down");
            }
            result = server => {
                if let Err(e) = result {
                    error!("server error: {e}");
                }
            }
        }
    });
}
