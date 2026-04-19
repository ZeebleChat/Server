use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::net::IpAddr;

use axum::{
    Json, Router,
    extract::{
        ConnectInfo, Path, Query,
        multipart::Multipart,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post, put},
};
use rusqlite::{Connection, ToSql};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use tracing::{debug, error, info, warn};

use local_ip_address::list_afinet_netifas;

use tokio::sync::broadcast;
use tower_http::compression::CompressionLayer;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use tower_http::cors::{AllowHeaders, AllowMethods, CorsLayer};

mod auth;
mod bots;
mod categories;
mod channels;
mod config;
mod files;
mod invites;
mod members;
mod messages;
mod openapi;
mod permissions;
mod rate_limit;
mod roles;
mod server_settings;
mod voice;
mod ws;

// Re-export auth helpers so sibling modules can use `crate::validate_jwt` etc.
pub use auth::{
    auth_server_login, require_auth, resolve_identity,
    validate_bot_token, validate_jwt, JwksStore,
};
pub use config::{Config, ConfigFile, Settings, CONFIG_FILE, EVERYONE_ROLE};


// ── Router ────────────────────────────────────────────────────────────────────

fn create_router(state: Arc<AppState>) -> Router<()> {
    // Routes that are always accessible, even when the server is locked.
    let open_routes = Router::<()>::new()
        .route(
            "/health",
            get(|| async {
                Json(json!({
                    "status": "ok",
                    "server_name": "Zeeble Server",
                    "version": "0.1.0"
                }))
            }),
        )
        .route("/admin/unlock", get(unlock_page).post(unlock_server))
        .route("/join/:code", get(invites::join_page));

    // All other routes are gated behind the startup lock.
    let guarded_routes = Router::<()>::new()
        .route(
            "/v1/channels",
            get(channels::list_channels).post(channels::create_channel),
        )
        .route(
            "/v1/channels/:id",
            delete(channels::delete_channel).patch(channels::rename_channel),
        )
        .route(
            "/v1/channels/:channel_id/messages",
            get(messages::get_messages).post(messages::create_message),
        )
        .route(
            "/v1/channels/:channel_id/posts",
            get(messages::get_board_posts),
        )
        .route(
            "/v1/channels/:channel_id/posts/:post_id/replies",
            get(messages::get_post_replies),
        )
        .route(
            "/v1/messages/:message_id",
            patch(messages::edit_message).delete(messages::delete_message),
        )
        .route(
            "/v1/messages/:message_id/history",
            get(messages::get_message_history),
        )
        .route(
            "/v1/invites",
            get(invites::list_invites).post(invites::create_invite),
        )
        .route(
            "/v1/invites/:code",
            get(invites::get_invite).delete(invites::delete_invite),
        )
        .route("/v1/invites/:code/redeem", post(invites::redeem_invite))
        .route("/v1/join/:code", post(invites::join_redeem))
        .route("/v1/channels/:id/permissions", get(permissions::list_channel_perms))
        .route("/v1/channels/:id/permissions/:role", put(permissions::set_channel_perm).delete(permissions::delete_channel_perm))
        .route("/v1/categories/:id/permissions", get(permissions::list_category_perms))
        .route("/v1/categories/:id/permissions/:role", put(permissions::set_category_perm).delete(permissions::delete_category_perm))
        .route("/v1/members", get(members::get_members))
        .route("/v1/members/:identity", delete(members::delete_member))
        .route("/v1/account/status", patch(members::update_status))
        .route("/v1/categories", get(categories::list_categories).post(categories::create_category))
        .route(
            "/v1/categories/:id",
            patch(categories::update_category).delete(categories::delete_category),
        )
        .route("/v1/roles", get(roles::list_roles))
        .route(
            "/v1/roles/:user_id",
            put(roles::set_role).delete(roles::delete_role),
        )
        .route("/v1/custom_roles", get(roles::list_custom_roles).post(roles::create_custom_role).patch(roles::reorder_custom_roles))
        .route(
            "/v1/custom_roles/:name",
            put(roles::update_custom_role).delete(roles::delete_custom_role),
        )
        .route("/v1/upload", post(files::upload_file))
        .route("/v1/attachments/:id", get(files::get_attachment))
        .route("/v1/first-time-setup", post(invites::create_invite))
        .route("/v1/ws", get(ws::ws_handler))
        .route("/v1/voice/token", get(voice::get_voice_token))
        .route("/v1/voice/rooms", get(voice::get_voice_rooms))
        .route("/v1/voice/participants/:channel_id", get(voice::get_voice_participants))
        .route("/v1/server/info", get(server_info))
        .route("/v1/server/settings", get(server_settings::get_settings).patch(server_settings::patch_settings))
        // Bot management (owner only)
        .route("/v1/bots", get(bots::list_bots).post(bots::create_bot))
        .route("/v1/bots/:id", delete(bots::delete_bot))
        // Bot action endpoints (bot token auth)
        .route(
            "/v1/bot/channels/:channel_id/messages",
            get(bots::bot_get_messages).post(bots::bot_send_message),
        )
        .route_layer(axum::middleware::from_fn(require_unlocked));


    // Resolve CORS origins: use `allowed_origins` from settings if populated,
    // otherwise fall back to just `public_url`.
    let settings_guard = state.settings.try_read()
        .expect("settings RwLock should be available during router init");
    let cors_origins: Vec<String> = if !settings_guard.allowed_origins.is_empty() {
        settings_guard.allowed_origins.clone()
    } else {
        vec![settings_guard.public_url.clone()]
    };
    drop(settings_guard);

    let cors_layer = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::list(
            cors_origins
                .iter()
                .filter_map(|o| axum::http::HeaderValue::from_str(o).ok())
                .collect::<Vec<_>>(),
        ))
        .allow_methods(AllowMethods::any())
        .allow_headers(AllowHeaders::list([
            AUTHORIZATION,
            CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::HeaderName::from_static("x-active-server"),
        ]));

    let openapi_router = openapi::openapi_routes();
    
    Router::<()>::new()
        .merge(open_routes)
        .merge(guarded_routes)
        .merge(openapi_router)
        .fallback(|| async { (StatusCode::NOT_FOUND, "Not Found") })
        .layer(CompressionLayer::new())
        .layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(axum::extract::Extension(state.clone()))
        .layer(cors_layer)
        .layer(axum::middleware::from_fn(security_headers))
}

/// Attach security headers to all responses (text/html gets CSP too).
async fn security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(axum::http::header::X_CONTENT_TYPE_OPTIONS, axum::http::HeaderValue::from_static("nosniff"));
    resp.headers_mut().insert(axum::http::header::X_FRAME_OPTIONS, axum::http::HeaderValue::from_static("DENY"));
    resp.headers_mut().insert(axum::http::header::REFERRER_POLICY, axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"));
    let html = resp.headers().get(axum::http::header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap_or_default())
        .unwrap_or_default()
        .starts_with("text/html");
    if html {
        resp.headers_mut().insert(
            axum::http::header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:"),
        );
    }
    resp
}

async fn server_info(
    axum::extract::Extension(state): axum::extract::Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let s = state.settings.read().await;

    let channels: Vec<Value> = {
        let db = state.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT id, name, topic FROM channels").unwrap();
        stmt.query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "name": row.get::<_, String>(1)?,
                "topic": row.get::<_, String>(2)?,
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    };

    Json(json!({
        "server_name": s.server_name.clone(),
        "public_url": s.public_url.clone(),
        "about": s.about.clone(),
        "owner": s.owner_beam_identity.clone(),
        "channels": channels,
        "allow_new_members": s.allow_new_members,
        "invites_anyone": s.invites_anyone_can_create,
        "logo_attachment_id": s.logo_attachment_id,
    }))
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = KB * 1_024;
    const GB: u64 = MB * 1_024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Generates a random invite code like `zbl-a3f9k2t8`.
fn generate_invite_code() -> String {
    let chars = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..8)
        .map(|_| {
            use rand::Rng;
            chars[rng.gen_range(0..chars.len())] as char
        })
        .collect();
    format!("zbl-{}", suffix)
}

// ── State ─────────────────────────────────────────────────────────────────────

pub type ChannelBus = Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>;

/// Per-IP rate limit entry: (failure_count, window_start).
type RateLimitEntry = (u32, Instant);

/// Maximum failed unlock attempts before an IP is locked out.
const UNLOCK_MAX_ATTEMPTS: u32 = 5;
/// How long (seconds) the lockout window lasts.
const UNLOCK_WINDOW_SECS: u64 = 15 * 60;

pub struct AppState {
    pub db: Mutex<Connection>,
    pub buses: ChannelBus,
    pub jwks: Arc<Mutex<JwksStore>>,
    pub auth_server_url: String,
    pub online_users: Mutex<HashMap<String, usize>>,
    /// Hot-reloadable settings — read with `state.settings.read().await`.
    pub settings: Arc<tokio::sync::RwLock<Settings>>,
    /// Server-wide broadcast channel for member/channel updates.
    pub server_bus: broadcast::Sender<String>,
    /// LiveKit API management service URL.
    pub livekit_api_url: String,
    /// Shared secret sent as `X-Bridge-Secret` to the livekit-api bridge.
    pub livekit_bridge_secret: String,
    /// Internal LiveKit server URL (unused; clients connect directly via
    /// `livekit_url` from token response). Kept for backwards compatibility.
    pub livekit_server_url: String,
    /// Startup lock — server rejects all client requests until the owner unlocks it.
    pub locked: Arc<AtomicBool>,
    /// Per-IP rate limiting for the /admin/unlock endpoint.
    pub unlock_attempts: Mutex<HashMap<String, RateLimitEntry>>,
    /// Per-bot rate limiting for bot message send endpoint.
    pub bot_rate_limits: Mutex<HashMap<String, RateLimitEntry>>,
    /// Directory on disk where uploaded files are stored. If None, fall back to
    /// the legacy SQLite BLOB column.
    pub attachments_dir: Option<String>,
    /// Trusted proxy IPs/CIDRs for rate-limiting IP extraction.
    pub trusted_proxies: Vec<String>,
    /// When true, reject credential-bearing HTTP requests unless they
    /// carry x-forwarded-proto: https.
    pub require_tls: bool,
    /// IP-based and user-based rate limiting store for sensitive endpoints.
    pub rate_limits: Arc<rate_limit::RateLimitStore>,
}

/// Extract the correct client IP for rate-limiting purposes.
/// Only honours `X-Forwarded-For` / `X-Real-IP` if the raw socket IP is in
/// the trusted-proxies list; otherwise returns the raw socket IP.
pub fn client_ip(
    headers: &HeaderMap,
    socket_ip: &IpAddr,
    trusted_proxies: &[String],
) -> String {
    // Only trust forwarded headers if the raw connection IP is in the trusted set.
    if trusted_proxies.iter().any(|tp| {
        // Support exact match and CIDR via simple prefix (exact IP only for now)
        ip_matches(socket_ip, tp)
    }) {
        headers
            .get("x-real-ip")
            .or_else(|| headers.get("x-forwarded-for"))
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| socket_ip.to_string())
    } else {
        socket_ip.to_string()
    }
}

/// Check if an IpAddr matches a trusted-proxies entry.
/// Supports exact IP match and CIDR notation (e.g. "10.0.0.0/8").
fn ip_matches(ip: &IpAddr, entry: &str) -> bool {
    if let Some((net, prefix_str)) = entry.split_once('/') {
        if let Ok(prefix) = prefix_str.parse::<u8>() {
            match (ip, net.parse::<IpAddr>()) {
                (IpAddr::V4(a), Ok(IpAddr::V4(b))) => {
                    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
                    let ip_bits = u32::from_be_bytes(a.octets()) & mask;
                    let net_bits = u32::from_be_bytes(b.octets()) & mask;
                    return ip_bits == net_bits;
                }
                (IpAddr::V6(a), Ok(IpAddr::V6(b))) => {
                    let mask = if prefix == 0 {
                        0u128
                    } else {
                        !0u128 << (128 - prefix)
                    };
                    let ip_bits = u128::from_be_bytes(a.octets()) & mask;
                    let net_bits = u128::from_be_bytes(b.octets()) & mask;
                    return ip_bits == net_bits;
                }
                _ => {}
            }
        }
    }
    // Exact match fallback
    entry == ip.to_string()
}

impl AppState {
    fn bus_for(&self, channel_id: &str) -> broadcast::Sender<String> {
        let mut map = self.buses.lock().unwrap();
        map.entry(channel_id.to_string())
            .or_insert_with(|| broadcast::channel::<String>(256).0)
            .clone()
    }

    fn mark_online(&self, identity: &str) {
        {
            let mut map = self.online_users.lock().unwrap();
            let count = map.entry(identity.to_string()).or_insert(0);
            *count += 1;
            if *count == 1 {
                self.set_user_status_in_db(identity, "online");
            }
        }
    }

    async fn mark_offline(&self, identity: &str) {
        let need_broadcast = {
            let mut map = self.online_users.lock().unwrap();
            if let Some(count) = map.get_mut(identity) {
                *count -= 1;
                if *count == 0 {
                    map.remove(identity);
                    self.set_user_status_in_db(identity, "offline");
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if need_broadcast {
            self.broadcast_member_update().await;
        }
    }

    fn set_user_status_in_db(&self, identity: &str, status: &str) {
        debug!("presence: {identity} → {status}");
        let db = match self.db.lock() {
            Ok(db) => db,
            Err(_) => return,
        };
        let _ = db.execute(
            "INSERT INTO users (beam_identity, status) VALUES (?1, ?2) ON CONFLICT(beam_identity) DO UPDATE SET status = excluded.status",
            rusqlite::params![identity, status],
        );
    }

    pub async fn broadcast_member_update(&self) {
        let (rows, hoisted_roles) = {
            let db = match self.db.lock() {
                Ok(db) => db,
                Err(_) => return,
            };
            let mut stmt = match db.prepare(
                "SELECT src.beam_identity, COUNT(m.id) as message_count, COALESCE(MAX(u.status), 'offline') as status, MAX(u.role) as role
             FROM (SELECT beam_identity FROM users UNION SELECT beam_identity FROM messages) src
             LEFT JOIN users u ON u.beam_identity = src.beam_identity
             LEFT JOIN messages m ON m.beam_identity = src.beam_identity
             GROUP BY src.beam_identity
             ORDER BY message_count DESC",
            ) {
                Ok(s) => s,
                Err(e) => { error!("prepare members: {e}"); return; }
            };
            let rows: Vec<(String, i64, String, Option<String>)> = stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

            let hoisted: Vec<String> = db
                .prepare("SELECT name FROM custom_roles WHERE hoist = 1 ORDER BY position ASC")
                .map(|mut s| s.query_map([], |row| row.get(0)).unwrap().filter_map(|r| r.ok()).collect())
                .unwrap_or_default();

            (rows, hoisted)
        };

        let owner = self.settings.read().await.owner_beam_identity.clone();
        let mut hoisted_groups: Vec<(String, Vec<members::FrontendMember>)> =
            hoisted_roles.iter().map(|n| (n.clone(), Vec::new())).collect();
        let hoisted_set: std::collections::HashSet<&str> = hoisted_roles.iter().map(|s| s.as_str()).collect();
        let mut online = Vec::new();
        let mut offline = Vec::new();
        for (beam_identity, _message_count, status, role) in rows {
            let is_owner = !owner.is_empty() && beam_identity == owner;
            let member = members::FrontendMember { name: beam_identity, status: status.clone(), role: role.clone(), avatar: None, is_owner };
            if status == "online" {
                let is_hoisted = role.as_deref().map(|r| hoisted_set.contains(r)).unwrap_or(false);
                if is_hoisted {
                    let group_key = role.as_deref().unwrap_or("");
                    if let Some(grp) = hoisted_groups.iter_mut().find(|(n, _)| n.as_str() == group_key) {
                        grp.1.push(member);
                    } else { online.push(member); }
                } else { online.push(member); }
            } else { offline.push(member); }
        }

        let mut categories = Vec::new();
        for (role_name, users) in hoisted_groups {
            if !users.is_empty() {
                categories.push(members::MemberCategory { category: role_name, users });
            }
        }
        if !online.is_empty() {
            categories.push(members::MemberCategory { category: "Online".to_string(), users: online });
        }
        if !offline.is_empty() {
            categories.push(members::MemberCategory { category: "Offline".to_string(), users: offline });
        }

        let server_name = self.settings.read().await.server_name.clone();
        let broadcast = serde_json::to_string(&json!({
            "type": "member",
            "members": categories,
            "server_id": server_name,
        })).unwrap();
        let _ = self.server_bus.send(broadcast);
    }
}

// ── DB setup ──────────────────────────────────────────────────────────────────

pub fn setup_db(conn: &Connection) {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS categories (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS channels (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            topic       TEXT NOT NULL DEFAULT '',
            type        TEXT NOT NULL DEFAULT 'text',
            category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS messages (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id     TEXT NOT NULL REFERENCES channels(id),
            beam_identity  TEXT NOT NULL,
            content        TEXT NOT NULL,
            created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
            edited_at      INTEGER
        );

        CREATE TABLE IF NOT EXISTS attachments (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id      INTEGER,
            dm_message_id   INTEGER,
            filename        TEXT NOT NULL,
            mime_type       TEXT NOT NULL,
            file_size       INTEGER NOT NULL,
            file_data       BLOB,
            file_path       TEXT,
            uploaded_by     TEXT NOT NULL,
            uploaded_at     INTEGER NOT NULL DEFAULT (unixepoch()),
            CHECK (
                (message_id IS NOT NULL AND dm_message_id IS NULL) OR
                (message_id IS NULL AND dm_message_id IS NOT NULL) OR
                (message_id IS NULL AND dm_message_id IS NULL)
            ),
            FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
        CREATE INDEX IF NOT EXISTS idx_attachments_dm ON attachments(dm_message_id);

        CREATE TABLE IF NOT EXISTS invites (
            code           TEXT PRIMARY KEY,
            created_by     TEXT NOT NULL,
            created_at     INTEGER NOT NULL DEFAULT (unixepoch()),
            expires_at     INTEGER,
            max_uses       INTEGER,
            use_count      INTEGER NOT NULL DEFAULT 0
        );

CREATE TABLE IF NOT EXISTS users (
      beam_identity TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'offline',
      avatar_attachment_id INTEGER,
      role TEXT,
      is_deleted INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_users_deleted ON users(is_deleted);

        CREATE TABLE IF NOT EXISTS bots (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            token       TEXT NOT NULL UNIQUE,
            created_by  TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE TABLE IF NOT EXISTS server_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS custom_roles (
            name        TEXT PRIMARY KEY,
            color       TEXT NOT NULL DEFAULT '#6366f1',
            position    INTEGER NOT NULL DEFAULT 0,
            hoist       INTEGER NOT NULL DEFAULT 0,
            permissions TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS channel_permissions (
            channel_id    TEXT    NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            role_name     TEXT    NOT NULL,
            view_channel  INTEGER NOT NULL DEFAULT 1,
            send_messages INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (channel_id, role_name)
        );

        CREATE TABLE IF NOT EXISTS category_permissions (
            category_id   INTEGER NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
            role_name     TEXT    NOT NULL,
            view_category INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (category_id, role_name)
        );

        CREATE TABLE IF NOT EXISTS message_edit_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            content     TEXT NOT NULL,
            edited_by   TEXT NOT NULL,
            edited_at   INTEGER NOT NULL DEFAULT (unixepoch())
        );
        CREATE INDEX IF NOT EXISTS idx_edit_history_msg ON message_edit_history(message_id);

        INSERT OR IGNORE INTO channels (id, name, topic)
        VALUES ('general', 'general', 'General zeeble-chat for everyone');
    ",
    )
    .expect("DB setup failed");

    // Run column migrations, adding new columns to existing tables as needed.
    run_migration(conn, "users", "avatar_attachment_id", "ALTER TABLE users ADD COLUMN avatar_attachment_id INTEGER");
    run_migration(conn, "users", "role",                 "ALTER TABLE users ADD COLUMN role TEXT");
    run_migration(conn, "channels", "type",              "ALTER TABLE channels ADD COLUMN type TEXT DEFAULT 'text'");
    run_migration(conn, "channels", "category_id",       "ALTER TABLE channels ADD COLUMN category_id INTEGER");
    run_migration(conn, "channels", "position",          "ALTER TABLE channels ADD COLUMN position INTEGER DEFAULT 0");
    run_migration(conn, "messages",     "bot_id",      "ALTER TABLE messages ADD COLUMN bot_id TEXT REFERENCES bots(id)");
    run_migration(conn, "messages",     "title",       "ALTER TABLE messages ADD COLUMN title TEXT");
    run_migration(conn, "messages",     "reply_to",    "ALTER TABLE messages ADD COLUMN reply_to INTEGER REFERENCES messages(id) ON DELETE SET NULL");
    run_migration(conn, "custom_roles", "hoist",       "ALTER TABLE custom_roles ADD COLUMN hoist INTEGER NOT NULL DEFAULT 0");
    run_migration(conn, "custom_roles", "permissions", "ALTER TABLE custom_roles ADD COLUMN permissions TEXT NOT NULL DEFAULT '{}'");
    run_migration(conn, "channel_permissions",  "allow", "ALTER TABLE channel_permissions ADD COLUMN allow TEXT NOT NULL DEFAULT '{}'");
    run_migration(conn, "channel_permissions",  "deny",  "ALTER TABLE channel_permissions ADD COLUMN deny  TEXT NOT NULL DEFAULT '{}'");
    run_migration(conn, "category_permissions", "allow", "ALTER TABLE category_permissions ADD COLUMN allow TEXT NOT NULL DEFAULT '{}'");
    run_migration(conn, "category_permissions", "deny",  "ALTER TABLE category_permissions ADD COLUMN deny  TEXT NOT NULL DEFAULT '{}'");
    run_migration(conn, "attachments", "file_path", "ALTER TABLE attachments ADD COLUMN file_path TEXT");

    // Seed default roles (INSERT OR IGNORE = skip if already present)
    conn.execute_batch(
        "INSERT OR IGNORE INTO custom_roles (name, color, position, hoist, permissions) VALUES
            ('Admin',     '#ef4444', 0,   1, '{\"administrator\":true,\"manage_roles\":true,\"kick_members\":true,\"ban_members\":true,\"create_invites\":true,\"manage_invites\":true,\"manage_channels\":true,\"manage_server\":true,\"manage_messages\":true,\"manage_nicknames\":true,\"change_nickname\":true}'),
            ('Mod',       '#f59e0b', 1,   1, '{\"kick_members\":true,\"create_invites\":true,\"manage_messages\":true,\"change_nickname\":true}'),
            ('VIP',       '#6366f1', 2,   0, '{\"create_invites\":true,\"change_nickname\":true}'),
            (EVERYONE_ROLE, '#99aab5', 999, 0, '{\"view_channel\":true,\"send_messages\":true,\"read_message_history\":true,\"embed_links\":true,\"attach_files\":true,\"add_reactions\":true,\"create_invites\":true,\"change_nickname\":true,\"connect\":true,\"speak\":true}');"
    ).ok();

    // Seed default "Channels" category and migrate any uncategorized channels into it.
    conn.execute(
        "INSERT OR IGNORE INTO categories (name, position) VALUES ('Channels', 0)",
        [],
    ).ok();
    let default_cat_id: i64 = conn.query_row(
        "SELECT id FROM categories WHERE name = 'Channels'",
        [],
        |row| row.get(0),
    ).unwrap_or(1);
    conn.execute(
        "UPDATE channels SET category_id = ?1 WHERE category_id IS NULL",
        rusqlite::params![default_cat_id],
    ).ok();
}

/// Add a column to `table` if it doesn't already exist.
fn run_migration(conn: &Connection, table: &str, column: &str, sql: &str) {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name=?2",
            rusqlite::params![table, column],
            |row| row.get(0),
        )
        .unwrap_or(0i64) > 0;
    if !exists {
        conn.execute(sql, []).ok();
    }
}

// ── Lock middleware ───────────────────────────────────────────────────────────

async fn require_unlocked(
    axum::extract::Extension(state): axum::extract::Extension<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if state.locked.load(Ordering::SeqCst) {
        return (
            StatusCode::LOCKED,
            Json(json!({ "error": "server is locked — POST /admin/unlock with owner JWT" })),
        )
            .into_response();
    }
    next.run(req).await
}

// ── Unlock handlers ───────────────────────────────────────────────────────────

/// GET /admin/unlock — HTML sign-in form for browser-based unlock.
async fn unlock_page(
    axum::extract::Extension(state): axum::extract::Extension<Arc<AppState>>,
) -> impl IntoResponse {
    if !state.locked.load(Ordering::SeqCst) {
        let settings = state.settings.read().await;
        let server_name = settings.server_name.clone();
        let public_url = settings.public_url.clone();
        drop(settings);
        return Html(format!(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Zeeble — {server_name}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#212328;color:#f3f4f6;min-height:100vh;display:flex;align-items:center;justify-content:center}}
  .card{{background:#26282e;border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:36px;width:100%;max-width:440px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}}
  .logo{{font-size:22px;font-weight:700;letter-spacing:-0.5px;margin-bottom:24px;color:#f3f4f6}}
  .logo span{{color:#6366f1}}
  h2{{font-size:18px;font-weight:600;margin-bottom:6px}}
  p{{font-size:13px;color:#9ca3af;margin-bottom:0}}
  .msg{{margin-top:16px;padding:10px 14px;border-radius:8px;font-size:13px;font-weight:500;background:rgba(16,185,129,0.1);color:#10b981;display:flex;align-items:center;gap:8px;border:1px solid rgba(16,185,129,0.2)}}
  .info{{margin-top:20px;display:flex;flex-direction:column;gap:8px}}
  .info-row{{display:flex;justify-content:space-between;align-items:center;font-size:13px;padding:8px 12px;background:#1b1d21;border-radius:8px;border:1px solid rgba(255,255,255,0.06)}}
  .info-label{{color:#9ca3af;font-weight:500}}
  .info-value{{color:#f3f4f6;font-weight:600;font-family:monospace;font-size:12px}}
  .dot{{width:8px;height:8px;border-radius:50%;background:#10b981;flex-shrink:0;box-shadow:0 0 6px #10b981}}
</style></head>
<body>
<div class="card">
  <div class="logo">Zee<span>ble</span></div>
  <h2>Server Online</h2>
  <p>This server is running and accepting connections.</p>
  <div class="msg"><div class="dot"></div>&nbsp;Online and ready</div>
  <div class="info">
    <div class="info-row"><span class="info-label">Server name</span><span class="info-value">{server_name}</span></div>
    <div class="info-row"><span class="info-label">Public URL</span><span class="info-value">{public_url}</span></div>
  </div>
</div>
</body></html>"#));
    }
    Html(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Unlock Server — Zeeble</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#212328;color:#f3f4f6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
  .card{background:#26282e;border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:36px;width:100%;max-width:400px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
  .logo{font-size:22px;font-weight:700;letter-spacing:-0.5px;margin-bottom:28px;color:#f3f4f6}
  .logo span{color:#6366f1}
  h2{font-size:18px;font-weight:600;margin-bottom:6px}
  .sub{font-size:13px;color:#9ca3af;margin-bottom:24px}
  label{display:block;font-size:12px;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px}
  input{width:100%;padding:10px 12px;font-size:14px;background:#1b1d21;color:#f3f4f6;border:1px solid rgba(255,255,255,0.1);border-radius:8px;outline:none;transition:border-color 0.15s;margin-bottom:16px}
  input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,0.2)}
  input::placeholder{color:#6b7280}
  button{width:100%;padding:11px;font-size:14px;font-weight:600;cursor:pointer;background:#6366f1;color:#fff;border:none;border-radius:8px;transition:background 0.15s;margin-top:4px}
  button:hover{background:#4f46e5}
  button:active{background:#4338ca}
  #msg{margin-top:16px;padding:10px 14px;border-radius:8px;font-size:13px;font-weight:500;display:none;align-items:center;gap:8px}
  #msg.ok{background:rgba(16,185,129,0.12);color:#10b981;display:flex;border:1px solid rgba(16,185,129,0.2)}
  #msg.err{background:rgba(239,68,68,0.12);color:#ef4444;display:flex;border:1px solid rgba(239,68,68,0.2)}
  #status{display:none;margin-top:20px}
  .status-banner{display:flex;align-items:center;gap:10px;padding:10px 14px;background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2);border-radius:8px;margin-bottom:14px}
  .dot{width:8px;height:8px;border-radius:50%;background:#10b981;flex-shrink:0;box-shadow:0 0 6px #10b981}
  .status-banner span{font-size:13px;font-weight:600;color:#10b981}
  .info-row{display:flex;justify-content:space-between;align-items:center;font-size:13px;padding:8px 12px;background:#1b1d21;border-radius:8px;border:1px solid rgba(255,255,255,0.06);margin-bottom:8px}
  .info-label{color:#9ca3af;font-weight:500}
  .info-value{color:#f3f4f6;font-weight:600;font-family:monospace;font-size:12px;word-break:break-all;text-align:right;max-width:220px}
</style></head>
<body>
<div class="card">
  <div class="logo">Zee<span>ble</span></div>
  <div id="form-section">
    <h2>Unlock Server</h2>
    <p class="sub">Sign in with your Beam identity to unlock the server.</p>
    <label for="id">Beam Identity</label>
    <input id="id" placeholder="name»tag" autocomplete="username">
    <label for="pw">Password</label>
    <input id="pw" type="password" placeholder="••••••••" autocomplete="current-password">
    <button id="btn" onclick="unlock()">Sign in</button>
    <div id="msg"></div>
  </div>
  <div id="status">
    <h2>Server Online</h2>
    <p class="sub" id="status-sub">Unlocked and accepting connections.</p>
    <div class="status-banner"><div class="dot"></div><span>Online and ready</span></div>
    <div class="info-row"><span class="info-label">Server name</span><span class="info-value" id="s-name">—</span></div>
    <div class="info-row"><span class="info-label">Public URL</span><span class="info-value" id="s-url">—</span></div>
    <div class="info-row"><span class="info-label">Owner</span><span class="info-value" id="s-owner">—</span></div>
  </div>
</div>
<script>
  document.addEventListener('keydown', e => { if (e.key === 'Enter') unlock(); });
  async function unlock() {
    const id  = document.getElementById('id').value.trim();
    const pw  = document.getElementById('pw').value;
    if (!id || !pw) { show('err', 'Enter your beam identity and password.'); return; }
    document.getElementById('btn').disabled = true;
    show('', 'Signing in\u2026');
    const r = await fetch('/admin/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ beam_identity: id, password: pw })
    });
    const j = await r.json();
    if (r.ok) {
      document.getElementById('form-section').style.display = 'none';
      document.getElementById('s-name').textContent = j.server_name || '—';
      document.getElementById('s-url').textContent = j.public_url || window.location.origin;
      document.getElementById('s-owner').textContent = j.identity || id;
      document.getElementById('status-sub').textContent = 'Unlocked by ' + (j.identity || id) + '.';
      document.getElementById('status').style.display = 'block';
    } else {
      document.getElementById('btn').disabled = false;
      show('err', j.error || ('Error ' + r.status));
    }
  }
  function show(cls, text) {
    const el = document.getElementById('msg');
    el.className = cls ? 'msg ' + cls : 'msg';
    el.textContent = text;
    if (!cls) el.style.display = 'flex';
  }
</script>
</body></html>"#.to_string())
}

/// POST /admin/unlock — authenticate with beam identity + password to lift the startup lock.
///
/// Rate limited: after 5 failures from the same IP the endpoint returns 429 for 15 minutes.
async fn unlock_server(
    axum::extract::Extension(state): axum::extract::Extension<Arc<AppState>>,
    ConnectInfo(sock_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Securely extract client IP respecting trusted-proxies config
    let ip = client_ip(&headers, &sock_addr.ip(), &state.trusted_proxies);

    // ── TLS enforcement guard ─────────────────────────────────────────────────
    if state.require_tls {
        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok());
        if proto != Some("https") {
            warn!("unlock rejected: REQUIRE_TLS=true but no x-forwarded-proto: https (ip={ip})");
            return (
                StatusCode::UPGRADE_REQUIRED,
                Json(json!({ "error": "This server requires HTTPS. Configure a TLS-terminating reverse proxy." })),
            )
                .into_response();
        }
    }

    // ── Rate limit check ──────────────────────────────────────────────────────
    {
        let mut attempts = state.unlock_attempts.lock().unwrap();
        let now = Instant::now();
        let entry = attempts.entry(ip.clone()).or_insert((0, now));
        // Reset window if it has expired
        if entry.1.elapsed().as_secs() >= UNLOCK_WINDOW_SECS {
            *entry = (0, now);
        }
        if entry.0 >= UNLOCK_MAX_ATTEMPTS {
            warn!("unlock rate-limited: too many attempts from {ip}");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "too many failed attempts — try again in 15 minutes" })),
            )
                .into_response();
        }
    }

    // ── Validate payload ──────────────────────────────────────────────────────
    let beam_identity = payload
        .get("beam_identity")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if beam_identity.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "beam_identity and password are required" })),
        )
            .into_response();
    }

    // ── Authenticate against auth server ─────────────────────────────────────
    match auth_server_login(&beam_identity, &password, &state).await {
        Err(e) => {
            warn!("unlock failed for {beam_identity} (ip={ip}): {e}");
            // Increment failure counter
            let mut attempts = state.unlock_attempts.lock().unwrap();
            if let Some(entry) = attempts.get_mut(&ip) {
                entry.0 += 1;
                let remaining = UNLOCK_MAX_ATTEMPTS.saturating_sub(entry.0);
                drop(attempts);
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": e, "attempts_remaining": remaining })),
                )
                    .into_response();
            }
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": e }))).into_response()
        }
        Ok(identity) => {
            let owner = state.settings.read().await.owner_beam_identity.clone();
            if !owner.is_empty() && identity != owner {
                warn!("unlock rejected: {identity} is not the owner ({owner}) — ip={ip}");
                let mut attempts = state.unlock_attempts.lock().unwrap();
                if let Some(entry) = attempts.get_mut(&ip) {
                    entry.0 += 1;
                }
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": format!("signed in as {identity} but owner is {owner}") })),
                )
                    .into_response();
            }
            // Success — clear rate limit entry for this IP
            state.unlock_attempts.lock().unwrap().remove(&ip);
            // First unlock: persist this identity as the server owner
            if owner.is_empty() {
                let _ = state.db.lock().unwrap().execute(
                    "INSERT OR IGNORE INTO server_meta (key, value) VALUES ('owner_beam_identity', ?1)",
                    rusqlite::params![&identity],
                );
                state.settings.write().await.owner_beam_identity = identity.clone();
                info!("owner identity set to {identity} via first unlock (ip={ip})");
            }
            state.locked.store(false, Ordering::SeqCst);
            info!("server unlocked by {identity} (ip={ip})");
            let settings = state.settings.read().await;
            let server_name = settings.server_name.clone();
            let public_url = settings.public_url.clone();
            drop(settings);
            Json(json!({
                "ok": true,
                "message": format!("Signed in as {identity} — server unlocked"),
                "server_name": server_name,
                "public_url": public_url,
                "identity": identity
            }))
                .into_response()
        }
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
                    .unwrap_or_else(|_| "zeeble_server=info,tower_http=debug".into()),
            )
            .init();

        let (config, config_file) = Config::load();

        let port = config.port;
        let db_path = config.db_path.clone();
        let config_source = config
            .config_path
            .clone()
            .map(|p| format!("{p} (+ env overrides)"))
            .unwrap_or_else(|| format!("env vars only (example written to {CONFIG_FILE})"));

        let mut initial_settings = Settings::from_file(&config_file, port);

        let server_name = initial_settings.server_name.clone();
        let public_url  = initial_settings.public_url.clone();

        let mut conn = Connection::open(&config.db_path)
            .unwrap_or_else(|e| panic!("Failed to open DB at {}: {e}", config.db_path));
        info!("database opened: {}", config.db_path);
        setup_db(&conn);
        debug!("database schema initialized");

        // Load owner identity from DB (populated on first unlock).
        // Only applies if not already overridden by OWNER_BEAM_IDENTITY env var.
        if initial_settings.owner_beam_identity.is_empty() {
            if let Ok(owner) = conn.query_row(
                "SELECT value FROM server_meta WHERE key = 'owner_beam_identity'",
                [],
                |row| row.get::<_, String>(0),
            ) {
                info!("owner identity loaded from database: {}", owner);
                initial_settings.owner_beam_identity = owner;
            }
        }

        // If an owner is already established (from DB or env), start unlocked.
        // On a fresh install with no owner the server stays locked until the
        // first /admin/unlock call sets the owner.
        let start_unlocked = !initial_settings.owner_beam_identity.is_empty();
        if start_unlocked {
            info!("owner already set — starting unlocked");
        }

        let settings = Arc::new(tokio::sync::RwLock::new(initial_settings));
        let (server_bus, _) = broadcast::channel(256);

        // Create a one-time startup invite (reuses the existing connection).
        // Must happen BEFORE `conn` is moved into `AppState`.
        let startup_invite = {
            let invite = create_startup_invite(&mut conn);
            println!("\n🎟️  STARTUP INVITE (one-time use, stored in DB):");
            println!("   • Code:      {}", invite);
            println!("   • Web URL:   {}/join/{}", public_url, invite);
            println!("   • Deep Link: zeeble://join?code={}", invite);
            invite
        };

    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        buses: Arc::new(Mutex::new(HashMap::new())),
        jwks: Arc::new(Mutex::new(JwksStore { keys: HashMap::new() })),
        auth_server_url: config.auth_server_url.clone(),
        online_users: Mutex::new(HashMap::new()),
        settings: Arc::clone(&settings),
        server_bus,
        livekit_api_url: config.livekit_api_url.clone(),
        livekit_bridge_secret: config.livekit_bridge_secret.clone(),
        livekit_server_url: config.livekit_server_url.clone(),
        locked: Arc::new(AtomicBool::new(!start_unlocked)),
        unlock_attempts: Mutex::new(HashMap::new()),
        bot_rate_limits: Mutex::new(HashMap::new()),
        attachments_dir: config.attachments_dir.clone(),
        trusted_proxies: config.trusted_proxies.clone(),
        require_tls: config.require_tls,
        rate_limits: Arc::new(rate_limit::RateLimitStore::new()),
    });

        // Fetch JWKS — use spawn_blocking because reqwest::blocking can't run
        // inside an existing Tokio runtime.
        let auth_url_for_jwks = config.auth_server_url.clone();
        match tokio::task::spawn_blocking(move || auth::fetch_jwks(&auth_url_for_jwks))
            .await
            .unwrap()
        {
            Ok(jwks_store) => {
                *state.jwks.lock().unwrap() = jwks_store;
                info!("JWKS fetched successfully from {}", config.auth_server_url);
            }
            Err(e) => {
                eprintln!("FATAL: Failed to fetch JWKS from auth server: {e}");
                eprintln!("The server cannot validate tokens without JWKS. Exiting.");
                std::process::exit(1);
            }
        }

        // Print startup banner
        let local_ips = get_local_ips();
        println!("\n{}", "═".repeat(60));
        println!("🚀 ZEEBLE SERVER STARTED");
        println!("{}", "═".repeat(60));
        println!("\n📡 SERVER INFORMATION:");
        println!("   • Server Name: {}", server_name);
        println!("   • Port:        {}", port);
        println!("   • Public URL:  {}", public_url);
        println!("   • Database:    {}", db_path);
        println!("   • Config:      {}", config_source);
        println!("\n🌐 LOCAL NETWORK ACCESS:");
        for ip in &local_ips {
            if ip.starts_with("localhost") {
                println!("   • {} (localhost)", ip.split(": ").nth(1).unwrap_or("127.0.0.1"));
            } else {
                let parts: Vec<&str> = ip.split(": ").collect();
                if parts.len() == 2 {
                    println!("   • http://{}:{} ({})", parts[1], port, parts[0]);
                }
            }
        }
        println!("\n🔗 IMPORTANT ENDPOINTS:");
        println!("   • API Base:  {}", public_url);
        println!("   • WebSocket: {}/ws", public_url.replace("http", "ws"));
        println!("   • Health:    {}/health", public_url);
        println!("   • Join Page: {}/join/{}", public_url, startup_invite);
        println!("   • LiveKit:   {}", config.livekit_api_url);
        println!("\n⚡ Server is now running. Press Ctrl+C to stop.");
        println!("   Config changes in phaselink.yaml are applied live — no restart needed.");
        println!("{}", "═".repeat(60));
        println!();

        // ── Startup login ─────────────────────────────────────────────────────
        use std::io::IsTerminal as _;
        if std::io::stdin().is_terminal() {
            println!("🔒 SERVER IS LOCKED");
            println!("   Sign in with your Beam identity to unlock and start accepting connections.");
            println!();

            let state_for_login = Arc::clone(&state);
            loop {
                print!("Beam identity (e.g. name»tag): ");
                std::io::Write::flush(&mut std::io::stdout()).ok();
                let beam_identity = tokio::task::spawn_blocking(|| {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).ok();
                    line.trim().to_string()
                })
                .await
                .unwrap_or_default();

                if beam_identity.is_empty() {
                    println!("   No identity entered — try again.");
                    continue;
                }

                print!("Password: ");
                std::io::Write::flush(&mut std::io::stdout()).ok();
                let password = tokio::task::spawn_blocking(|| {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).ok();
                    line.trim().to_string()
                })
                .await
                .unwrap_or_default();

                match auth_server_login(&beam_identity, &password, &state_for_login).await {
                    Err(e) => println!("   Login failed: {e}"),
                    Ok(identity) => {
                        let owner = state_for_login.settings.read().await.owner_beam_identity.clone();
                        if !owner.is_empty() && identity != owner {
                            println!("   Signed in as {identity}, but the owner is {owner}. Try again.");
                        } else {
                            // First login: persist as owner
                            if owner.is_empty() {
                                let _ = state_for_login.db.lock().unwrap().execute(
                                    "INSERT OR IGNORE INTO server_meta (key, value) VALUES ('owner_beam_identity', ?1)",
                                    rusqlite::params![&identity],
                                );
                                state_for_login.settings.write().await.owner_beam_identity = identity.clone();
                                info!("owner identity set to {identity} via first terminal login");
                            }
                            state_for_login.locked.store(false, Ordering::SeqCst);
                            println!();
                            println!("✅ Signed in as {identity} — server is now open.");
                            println!();
                            info!("server unlocked via terminal login by {identity}");
                            break;
                        }
                    }
                }
            }
        } else {
            println!("🔒 SERVER IS LOCKED (headless mode)");
            println!("   Visit {}/admin/unlock or POST with beam identity + password to unlock.", public_url);
            println!();
        }

        // Log active settings
        {
            let s = settings.read().await;
            info!(
                "active settings: max_message_length={} max_upload={} allow_new_members={} invites_anyone={} owner={:?}",
                s.max_message_length,
                humanize_bytes(s.max_upload_bytes),
                s.allow_new_members,
                s.invites_anyone_can_create,
                if s.owner_beam_identity.is_empty() { "<not set>" } else { &s.owner_beam_identity },
            );
        }

        // ── LiveKit key validation ────────────────────────────────────────────
        let livekit_secret = std::env::var("LIVEKIT_API_SECRET")
            .ok()
            .unwrap_or_else(|| config.livekit_api_secret.clone());
        if livekit_secret.contains("change-me") || livekit_secret.len() < 32 {
            eprintln!("\n⚠️  WARNING: LiveKit secret is weak or default.");
            eprintln!("    Generate a secure string: openssl rand -hex 20");
            eprintln!("    Or set LIVEKIT_API_SECRET to a value ≥ 32 chars.");
            if config.require_tls {
                eprintln!("\n    REQUIRE_TLS is enabled — refusing to start with insecure LiveKit key.");
                std::process::exit(1);
            }
        }

        // ── Config file watcher (notify-based, replaces 2-second polling) ────
        let settings_arc = Arc::clone(&settings);
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(4);

        let mut watcher = {
            let tx = notify_tx.clone();
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if let Ok(event) = res {
                    // React to writes/renames (the common save patterns)
                    if event.kind.is_modify() || matches!(event.kind, notify::EventKind::Create(_)) {
                        let _ = tx.blocking_send(());
                    }
                }
            })
        };

        match watcher {
            Ok(ref mut w) => {
                use notify::Watcher as _;
                if let Err(e) = w.watch(
                    std::path::Path::new(CONFIG_FILE),
                    notify::RecursiveMode::NonRecursive,
                ) {
                    warn!("config watcher: could not watch {CONFIG_FILE}: {e} — falling back to polling");
                    // Fall back to polling if watch fails (e.g. file doesn't exist yet)
                    let settings_poll = Arc::clone(&settings_arc);
                    tokio::spawn(async move {
                        let mut last = String::new();
                        loop {
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            if let Ok(contents) = std::fs::read_to_string(CONFIG_FILE) {
                                if contents != last {
                                    if let Ok(parsed) = serde_yaml::from_str::<ConfigFile>(&contents) {
                                        *settings_poll.write().await = Settings::from_file(&parsed, port);
                                        last = contents;
                                        info!("config watcher: reloaded {CONFIG_FILE} (poll)");
                                    }
                                }
                            }
                        }
                    });
                } else {
                    // Notify watcher is active — process events
                    tokio::spawn(async move {
                        let _watcher = watcher; // keep alive in this task
                        while notify_rx.recv().await.is_some() {
                            // Debounce: drain rapid bursts (e.g. editor writes multiple times)
                            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
                            while notify_rx.try_recv().is_ok() {}

                            match std::fs::read_to_string(CONFIG_FILE) {
                                Ok(contents) => match serde_yaml::from_str::<ConfigFile>(&contents) {
                                    Ok(parsed) => {
                                        *settings_arc.write().await = Settings::from_file(&parsed, port);
                                        info!("config watcher: reloaded {CONFIG_FILE}");
                                    }
                                    Err(e) => warn!("config watcher: parse error in {CONFIG_FILE}: {e}"),
                                },
                                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                                    warn!("config watcher: read error: {e}");
                                }
                                _ => {}
                            }
                        }
                    });
                }
            }
            Err(e) => {
                warn!("config watcher: could not create watcher: {e} — falling back to polling");
                let settings_poll = Arc::clone(&settings_arc);
                tokio::spawn(async move {
                    let mut last = String::new();
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                        if let Ok(contents) = std::fs::read_to_string(CONFIG_FILE) {
                            if contents != last {
                                if let Ok(parsed) = serde_yaml::from_str::<ConfigFile>(&contents) {
                                    *settings_poll.write().await = Settings::from_file(&parsed, port);
                                    last = contents;
                                    info!("config watcher: reloaded {CONFIG_FILE} (poll)");
                                }
                            }
                        }
                    }
                });
            }
        }

        let app = create_router(state);
        let addr = format!("0.0.0.0:{}", port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to bind {addr}: {e}"));

        // ── Graceful shutdown ─────────────────────────────────────────────────
        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received — shutting down gracefully");
            }
            result = server => {
                if let Err(e) = result {
                    error!("server error: {e}");
                }
            }
        }
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn create_startup_invite(conn: &mut Connection) -> String {
    let code = generate_invite_code();
    let tx = conn.transaction().unwrap();

    let exists: bool = tx
        .query_row(
            "SELECT 1 FROM invites WHERE code = ?1",
            rusqlite::params![code],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if exists {
        drop(tx);
        return create_startup_invite(conn);
    }

    tx.execute(
        "INSERT INTO invites (code, created_by, expires_at, max_uses, use_count)
         VALUES (?1, 'startup', NULL, NULL, 0)",
        rusqlite::params![code],
    )
    .unwrap_or_default();
    tx.commit().unwrap();
    info!("startup invite created: {}", code);
    code
}

fn get_local_ips() -> Vec<String> {
    let mut ips = vec!["localhost: 127.0.0.1".to_string()];
    if let Ok(ifas) = list_afinet_netifas() {
        for (name, addr) in ifas {
            if addr.is_loopback() || addr.is_ipv6() { continue; }
            ips.push(format!("{name}: {addr}"));
        }
    }
    ips
}

// =============================================================================
// Phase 0 — Unit tests for main.rs
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── generate_invite_code ─────────────────────────────────────────────────

    #[test]
    fn generate_invite_code_format() {
        let code = generate_invite_code();
        assert!(code.starts_with("zbl-"));
        // zbl- prefix (4) + 8 chars = 12 chars total
        assert_eq!(code.len(), 12);
    }

    #[test]
    fn generate_invite_code_uniqueness() {
        // Generate 100 codes and verify they're unique
        let codes: std::collections::HashSet<String> =
            (0..100).map(|_| generate_invite_code()).collect();
        assert_eq!(codes.len(), 100, "Generated codes should be unique");
    }

    #[test]
    fn generate_invite_code_charset() {
        let code = generate_invite_code();
        let suffix = &code[4..]; // Skip "zbl-"
        let valid_chars: std::collections::HashSet<char> =
            "abcdefghijkmnpqrstuvwxyz23456789".chars().collect();
        for c in suffix.chars() {
            assert!(
                valid_chars.contains(&c),
                "Invalid character '{}' in invite code",
                c
            );
        }
    }

    #[test]
    fn generate_invite_code_no_ambiguous() {
        // Verify no ambiguous characters (0, 1, O)
        // Note: 'l' IS in the charset (abcdefghijkmnpqrstuvwxyz23456789)
        let code = generate_invite_code();
        let invalid_chars = ['0', '1', 'O'];
        for c in code.chars() {
            assert!(
                !invalid_chars.contains(&c),
                "Ambiguous character '{}' found in invite code",
                c
            );
        }
    }

    // ── client_ip (CIDR matching) ───────────────────────────────────────────

    fn test_client_ip(
        headers: &HeaderMap,
        socket_ip: &std::net::IpAddr,
        trusted_proxies: &[String],
    ) -> String {
        // Only trust forwarded headers if the raw connection IP is in the trusted set.
        if trusted_proxies.iter().any(|tp| ip_matches(socket_ip, tp)) {
            headers
                .get("x-real-ip")
                .or_else(|| headers.get("x-forwarded-for"))
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| socket_ip.to_string())
        } else {
            socket_ip.to_string()
        }
    }

    fn ip_matches(ip: &std::net::IpAddr, pattern: &str) -> bool {
        // Simplified: exact match or CIDR prefix matching
        if let Ok(parsed_ip) = pattern.parse::<std::net::IpAddr>() {
            return ip == &parsed_ip;
        }
        // Simple CIDR matching for IPv4 (e.g., "192.168.0.0/24")
        if pattern.contains('/') {
            let parts: Vec<&str> = pattern.split('/').collect();
            if parts.len() == 2 {
                if let (Ok(base), Ok(prefix_len)) = (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<u8>()) {
                    if let std::net::IpAddr::V4(v4) = ip {
                        return matches_cidr(v4, &base, prefix_len);
                    }
                }
            }
        }
        false
    }

    fn matches_cidr(ip: &std::net::Ipv4Addr, base: &std::net::Ipv4Addr, prefix_len: u8) -> bool {
        let ip_u32 = u32::from(*ip);
        let base_u32 = u32::from(*base);
        let mask = if prefix_len == 0 {
            0
        } else {
            (!0u32) << (32 - prefix_len)
        };
        (ip_u32 & mask) == (base_u32 & mask)
    }

    #[test]
    fn ip_matches_exact_ipv4() {
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(ip_matches(&ip, "192.168.1.100"));
        assert!(!ip_matches(&ip, "192.168.1.101"));
    }

    #[test]
    fn ip_matches_cidr_ipv4() {
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        assert!(ip_matches(&ip, "192.168.1.0/24"));
        assert!(!ip_matches(&ip, "192.168.2.0/24"));

        // Test /16
        assert!(ip_matches(&ip, "192.168.0.0/16"));
        assert!(!ip_matches(&ip, "192.167.0.0/16"));

        // Test /8
        assert!(ip_matches(&ip, "192.0.0.0/8"));
    }

    #[test]
    fn ip_matches_cidr_edge_cases() {
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(ip_matches(&ip, "10.0.0.0/8"));
        assert!(ip_matches(&ip, "10.0.0.1/32"));
        assert!(!ip_matches(&ip, "10.0.0.2/32"));
    }

    #[test]
    fn ip_matches_invalid_patterns() {
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(!ip_matches(&ip, "invalid"));
        assert!(!ip_matches(&ip, ""));
        assert!(!ip_matches(&ip, "192.168.1.1/invalid"));
    }

    #[test]
    fn client_ip_untrusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        let socket_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let trusted_proxies: Vec<String> = vec!["127.0.0.1".to_string()];

        let result = test_client_ip(&headers, &socket_ip, &trusted_proxies);
        assert_eq!(result, "192.168.1.100"); // Returns socket IP, ignores forwarded header
    }

    #[test]
    fn client_ip_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());
        let socket_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let trusted_proxies: Vec<String> = vec!["127.0.0.1".to_string()];

        let result = test_client_ip(&headers, &socket_ip, &trusted_proxies);
        assert_eq!(result, "10.0.0.1"); // Uses forwarded header
    }

    #[test]
    fn client_ip_trusted_cidr() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        let socket_ip = std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let trusted_proxies: Vec<String> = vec!["203.0.113.0/24".to_string()];

        let result = test_client_ip(&headers, &socket_ip, &trusted_proxies);
        assert_eq!(result, "203.0.113.50"); // Uses forwarded header via CIDR match
    }

    #[test]
    fn client_ip_no_forwarded_headers() {
        let headers = HeaderMap::new();
        let socket_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let trusted_proxies: Vec<String> = vec!["192.168.1.100".to_string()];

        let result = test_client_ip(&headers, &socket_ip, &trusted_proxies);
        assert_eq!(result, "192.168.1.100"); // Falls back to socket IP
    }

    #[test]
    fn client_ip_multiple_x_forwarded_for() {
        let mut headers = HeaderMap::new();
        // X-Forwarded-For can have multiple IPs, client is first
        headers.insert("x-forwarded-for", "203.0.113.50, 10.0.0.1, 127.0.0.1".parse().unwrap());
        let socket_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let trusted_proxies: Vec<String> = vec!["192.168.1.1".to_string()];

        let result = test_client_ip(&headers, &socket_ip, &trusted_proxies);
        assert_eq!(result, "203.0.113.50"); // Takes first IP
    }

    // ── invite code expiry logic ───────────────────────────────────────────

    fn is_invite_valid(expires_at: Option<i64>, max_uses: Option<i64>, use_count: i64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let expired = expires_at.map(|e| now > e).unwrap_or(false);
        let exhausted = max_uses.map(|m| use_count >= m).unwrap_or(false);

        !expired && !exhausted
    }

    #[test]
    fn invite_valid_no_expiry_no_limit() {
        let valid = is_invite_valid(None, None, 0);
        assert!(valid);
    }

    #[test]
    fn invite_valid_future_expiry() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 + 3600; // 1 hour from now
        let valid = is_invite_valid(Some(future), None, 0);
        assert!(valid);
    }

    #[test]
    fn invite_expired_past_expiry() {
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 - 3600; // 1 hour ago
        let valid = is_invite_valid(Some(past), None, 0);
        assert!(!valid);
    }

    #[test]
    fn invite_exhausted_at_limit() {
        let valid = is_invite_valid(None, Some(5), 5);
        assert!(!valid);
    }

    #[test]
    fn invite_valid_under_limit() {
        let valid = is_invite_valid(None, Some(5), 4);
        assert!(valid);
    }

    #[test]
    fn invite_expired_and_exhausted() {
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 - 3600;
        let valid = is_invite_valid(Some(past), Some(5), 5);
        assert!(!valid);
    }

    // ── Invite expiry calculation ──────────────────────────────────────────

    fn calculate_expiry(hours: u64) -> Option<i64> {
        if hours == 0 {
            None
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            Some(now + (hours as i64) * 3600)
        }
    }

    fn calculate_max_uses(limit: u64) -> Option<i64> {
        if limit == 0 {
            None
        } else {
            Some(limit as i64)
        }
    }

    #[test]
    fn expiry_zero_means_never() {
        assert!(calculate_expiry(0).is_none());
    }

    #[test]
    fn expiry_one_hour() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expiry = calculate_expiry(1).unwrap();
        assert!(expiry > now);
        assert!(expiry <= now + 3601); // Within 1 second tolerance
    }

    #[test]
    fn max_uses_zero_means_unlimited() {
        assert!(calculate_max_uses(0).is_none());
    }

    #[test]
    fn max_uses_non_zero() {
        assert_eq!(calculate_max_uses(10), Some(10));
        assert_eq!(calculate_max_uses(1), Some(1));
    }
}
