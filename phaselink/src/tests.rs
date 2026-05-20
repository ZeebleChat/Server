#![cfg(test)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

use axum_test::TestServer;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::{AppState, DbPool, create_router, setup_db};
use crate::rate_limit::RateLimitStore;

// ── Test helpers ──────────────────────────────────────────────────────────────

fn test_pool() -> DbPool {
    let manager = r2d2_sqlite::SqliteConnectionManager::memory();
    let pool = r2d2::Pool::builder()
        .max_size(4)
        .build(manager)
        .expect("in-memory pool");
    {
        let conn = pool.get().expect("init conn");
        setup_db(&conn);
    }
    pool
}

async fn test_server() -> TestServer {
    let pool = test_pool();
    let (server_bus, _) = broadcast::channel(64);

    // Minimal real Redis is unavailable in CI; use a fake URL that will be
    // initialised but never queried in unit tests.
    let redis_client = redis::Client::open("redis://127.0.0.1/")
        .expect("redis client");
    let redis_conn = redis::aio::ConnectionManager::new(redis_client)
        .await
        .expect("redis conn");

    let state = Arc::new(AppState {
        db: pool,
        buses: Arc::new(Mutex::new(HashMap::new())),
        jwks: Arc::new(Mutex::new(crate::JwksStore { keys: HashMap::new() })),
        auth_server_url: "http://localhost:9999".to_string(),
        online_users: Mutex::new(HashMap::new()),
        settings: Arc::new(tokio::sync::RwLock::new(crate::config::Settings {
            owner_beam_identity: "test_owner».0".to_string(),
            ..Default::default()
        })),
        server_bus,
        redis: redis_conn,
        locked: Arc::new(AtomicBool::new(false)),
        unlock_attempts: Mutex::new(HashMap::new()),
        bot_rate_limits: Mutex::new(HashMap::new()),
        attachments_dir: None,
        trusted_proxies: vec![],
        require_tls: false,
        rate_limits: Arc::new(RateLimitStore::new()),
        voice_members: Arc::new(Mutex::new(HashMap::new())),
    });

    TestServer::new(create_router(state)).expect("test server")
}

// ── Health ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let server = test_server().await;
    let resp = server.get("/health").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
}

// ── Channels ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_channels_requires_auth() {
    let server = test_server().await;
    let resp = server.get("/v1/channels").await;
    resp.assert_status_unauthorized();
}

// ── Members ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_members_requires_auth() {
    let server = test_server().await;
    let resp = server.get("/v1/members").await;
    resp.assert_status_unauthorized();
}

// ── Invites ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_invite_nonexistent_returns_not_found() {
    let server = test_server().await;
    let resp = server.get("/v1/invites/zbl-doesntexist").await;
    // No auth required to look up an invite page, but it must 404
    resp.assert_status_not_found();
}

#[tokio::test]
async fn join_page_for_nonexistent_invite() {
    let server = test_server().await;
    let resp = server.get("/join/zbl-doesntexist").await;
    resp.assert_status_not_found();
}

// ── Messages ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_messages_requires_auth() {
    let server = test_server().await;
    let resp = server.get("/v1/channels/general/messages").await;
    resp.assert_status_unauthorized();
}

// ── Bots ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_bots_requires_auth() {
    let server = test_server().await;
    let resp = server.get("/v1/bots").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn bot_send_message_without_token_is_unauthorized() {
    let server = test_server().await;
    let resp = server
        .post("/v1/bot/channels/general/messages")
        .json(&json!({ "content": "hello" }))
        .await;
    resp.assert_status_unauthorized();
}
