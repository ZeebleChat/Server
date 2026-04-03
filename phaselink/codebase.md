# Cargo.toml

```toml
[package]
name = "zeeble-server"
version = "0.1.0"
edition = "2024"
description = "Zeeble chat server — host this to run your own Zeeble node"

[dependencies]
axum          = { version = "0.7", features = ["ws", "multipart", "macros"] }
tokio         = { version = "1",   features = ["full"] }
rusqlite      = { version = "0.31", features = ["bundled"] }
tower-http    = { version = "0.5", features = ["cors", "compression-gzip"] }
serde         = { version = "1",   features = ["derive"] }
serde_json    = "1"
hmac          = { version = "0.12", features = ["std"] }
sha2          = "0.10"
base64        = "0.22"
tracing       = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy       = "0.15"
local-ip-address = "0.5"
toml = "0.8"
reqwest = { version = "0.12", features = ["json"] }
multer = "3"
tokio-util = { version = "0.7", features = ["io"] }
rand = "0.8"

[dev-dependencies]
axum-test = "18.7.0"
jsonwebtoken = "8"
rand = "0.8"


```

# Dockerfile

```
# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1.93-slim AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY src ./src

RUN cargo build --release

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create data directory for SQLite DB
RUN mkdir -p /app/data

WORKDIR /app

COPY --from=builder /app/target/release/zeeble-server /usr/local/bin/zeeble-server

EXPOSE 4000

CMD ["zeeble-server"]

```

# src\channels.rs

```rs
use std::sync::Arc;
use axum::extract::Extension;
// ── REST — channels ───────────────────────────────────────────────────────────

use super::*;

#[derive(Serialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub topic: String,
}

#[derive(Deserialize)]
pub struct CreateChannel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub topic: String,
}

#[derive(Deserialize)]
pub struct RenameChannel {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
}

pub async fn list_channels(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&headers, &state.jwt_secret) {
        return e.into_response();
    }
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };
    let mut stmt = match db.prepare("SELECT id, name, topic FROM channels ORDER BY name ASC") {
        Ok(s) => s,
        Err(e) => {
            error!("prepare: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response();
        }
    };
    let channels: Vec<Channel> = match stmt.query_map([], |row| {
        Ok(Channel {
            id: row.get(0)?,
            name: row.get(1)?,
            topic: row.get(2)?,
        })
    }) {
        Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
        Err(e) => {
            error!("query channels: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response();
        }
    };
    debug!("list_channels: returning {} channels", channels.len());
    Json(channels).into_response()
}

pub async fn create_channel(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<CreateChannel>,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    // Only server owner can create channels
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only server owner can create channels" })),
        )
            .into_response();
    }
    let id = body.id.trim().to_lowercase();
    if id.is_empty()
        || id.len() > 32
        || !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Channel ID must be 1–32 alphanumeric/dash/underscore chars" })),
        )
            .into_response();
    }
    let insert_result = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response(),
        };
        db.execute(
            "INSERT INTO channels (id, name, topic) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, body.name.trim(), body.topic.trim()],
        )
    };
    match insert_result {
        Ok(_) => {
            info!("channel created: #{id} by {identity}");
            // Broadcast channel creation
            let server_id = state.settings.read().await.server_name.clone();
            let broadcast = serde_json::to_string(&json!({
                "type": "channel_created",
                "channel": {
                    "id": id,
                    "name": body.name.trim(),
                    "topic": body.topic.trim(),
                },
                "server_id": server_id,
            })).unwrap();
            let _ = state.server_bus.send(broadcast);
            Json(json!({ "id": id, "name": body.name.trim(), "topic": body.topic.trim() })).into_response()
        }
        Err(e) if e.to_string().contains("UNIQUE") => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "Channel ID already exists" })),
        )
            .into_response(),
        Err(e) => {
            error!("insert channel: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

pub async fn delete_channel(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    // Only server owner can delete channels
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only server owner can delete channels" })),
        )
            .into_response();
    }
    if channel_id == "general" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cannot delete the general channel" })),
        )
            .into_response();
    }
    let delete_result = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response(),
        };
        db.execute(
            "DELETE FROM messages WHERE channel_id = ?1",
            rusqlite::params![channel_id],
        )
            .ok();
        db.execute(
            "DELETE FROM channels WHERE id = ?1",
            rusqlite::params![channel_id],
        )
    };
    match delete_result {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Channel not found" })),
        )
            .into_response(),
        Ok(_) => {
            info!("channel deleted: #{channel_id} by {identity}");
            // Broadcast channel deletion
            let server_id = state.settings.read().await.server_name.clone();
            let broadcast = serde_json::to_string(&json!({
                "type": "channel_deleted",
                "channel_id": channel_id,
                "server_id": server_id,
            })).unwrap();
            let _ = state.server_bus.send(broadcast);
            (StatusCode::OK, Json(json!({ "deleted": true }))).into_response()
        }
        Err(e) => {
            error!("delete channel: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

pub async fn rename_channel(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RenameChannel>,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only server owner can rename channels" }))).into_response();
    }
    if channel_id == "general" {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Cannot rename the general channel" }))).into_response();
    }
    if let Some(name) = &body.name {
        if name.trim().is_empty() {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Channel name cannot be empty" }))).into_response();
        }
    }
    if body.name.is_none() && body.topic.is_none() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "No name or topic provided" }))).into_response();
    }

    let update_result = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
        };

        let mut set_clauses = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(name) = &body.name {
            set_clauses.push(format!("name = ?{}", idx));
            params.push(Box::new(name.trim().to_string()));
            idx += 1;
        }
        if let Some(topic) = &body.topic {
            set_clauses.push(format!("topic = ?{}", idx));
            params.push(Box::new(topic.trim().to_string()));
            idx += 1;
        }

        let sql = format!("UPDATE channels SET {} WHERE id = ?{}", set_clauses.join(", "), idx);
        params.push(Box::new(channel_id.clone()));
        let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let result = db.execute(&sql, param_refs.as_slice());
        drop(db);

        // *** FIX: was missing `let update_result =` and had a stray `;` ***
        match result {
            Ok(0) => Err("Channel not found"),
            Ok(_) => {
                let db = state.db.lock().unwrap();
                let mut stmt = db.prepare("SELECT id, name, topic FROM channels WHERE id = ?1").unwrap();
                let mut rows = stmt.query(rusqlite::params![channel_id]).unwrap();
                match rows.next() {
                    Ok(Some(row)) => {
                        let id: String = row.get(0).unwrap();
                        let name: String = row.get(1).unwrap();
                        let topic: String = row.get(2).unwrap();
                        Ok((id, name, topic))
                    }
                    _ => Err("Channel not found"),
                }
            }
            Err(e) => {
                error!("update channel: {e}");
                Err("DB error")
            }
        }
    }; // <-- update_result is now properly assigned

    // *** FIX: this match is now outside the block, and only appears once ***
    match update_result {
        Ok((id, name, topic)) => {
            info!("channel renamed: #{id} by {identity} → name={name:?} topic={topic:?}");
            let server_id = state.settings.read().await.server_name.clone();
            let broadcast = serde_json::to_string(&json!({
                "type": "channel_renamed",
                "channel": {
                    "id": id.clone(),
                    "name": name.clone(),
                    "topic": topic.clone(),
                },
                "server_id": server_id,
            })).unwrap();
            let _ = state.server_bus.send(broadcast);
            (StatusCode::OK, Json(json!({ "id": id, "name": name, "topic": topic }))).into_response()
        }
        Err(e) => match e {
            "Channel not found" => (StatusCode::NOT_FOUND, Json(json!({ "error": e }))).into_response(),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
        }
    }
}

```

# src\files.rs

```rs
use std::sync::Arc;
use axum::extract::Extension;
use super::*;

#[derive(Serialize)]
pub struct AttachmentUploadResponse {
    pub attachment_id: i64,
    pub filename: String,
    pub mime_type: String,
    pub file_size: i64,
}

#[derive(Serialize)]
pub struct UploadResult {
    pub ok: bool,
    pub attachments: Vec<AttachmentUploadResponse>,
}

const ALLOWED_MIME_TYPES: &[&str] = &[
    // Images
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    // Videos
    "video/mp4",
    "video/webm",
    // Audio
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    // Documents
    "application/pdf",
    "text/plain",
    "text/markdown",
    // Archives
    "application/zip",
    "application/x-zip-compressed",
];

fn sanitize_filename(filename: &str) -> String {
    // Remove path traversal attempts
    let sanitized = filename.replace("..", "").replace(['/', '\\'], "_");
    // Limit length to 255, preserving extension
    if sanitized.len() > 255 {
        if let Some(ext_pos) = sanitized.rfind('.') {
            let ext = &sanitized[ext_pos..];
            let max_name_len = 255 - ext.len();
            if max_name_len > 0 {
                format!("{}{}", &sanitized[..max_name_len], ext)
            } else {
                // Extension itself is longer than 255, just truncate
                sanitized[..255].to_string()
            }
        } else {
            sanitized[..255].to_string()
        }
    } else {
        sanitized
    }
}

/// POST /upload — upload one or more files and get attachment IDs
pub async fn upload_file(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let max_upload_bytes = state.settings.read().await.max_upload_bytes as i64;
    let mut attachments_data = Vec::new();
    let mut total_size = 0;

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let filename: String = match field.file_name() {
            Some(name) => sanitize_filename(name).to_string(),
            None => continue,
        };

        let mime_type: String = match field.content_type() {
            Some(mime) => mime.to_string(),
            None => continue,
        };

        if !ALLOWED_MIME_TYPES.contains(&mime_type.as_str()) {
            continue; // skip disallowed types
        }

        let mut bytes = Vec::new();
        while let Ok(Some(chunk)) = field.chunk().await {
            let chunk_len = chunk.len() as i64;
            total_size += chunk_len;
            if total_size > max_upload_bytes {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(json!({
                        "error": format!("File too large. Maximum size is {}.", humanize_bytes(max_upload_bytes as u64))
                    })),
                )
                    .into_response();
            }
            bytes.extend_from_slice(&chunk);
        }

        attachments_data.push((filename, mime_type, bytes));
    }

    if attachments_data.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No valid files uploaded" })),
        )
            .into_response();
    }

    if total_size > max_upload_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": format!("Total file size exceeds {} limit.", humanize_bytes(max_upload_bytes as u64)) })),
        )
            .into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    let mut response_attachments = Vec::new();

    for (filename, mime_type, data) in attachments_data {
        let file_size = data.len() as i64;

        match db.execute(
            "INSERT INTO attachments (filename, mime_type, file_size, file_data, uploaded_by) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![filename, mime_type, file_size, data, &identity],
        ) {
            Ok(_) => {
                let attachment_id = db.last_insert_rowid();
                response_attachments.push(AttachmentUploadResponse {
                    attachment_id,
                    filename: filename.clone(),
                    mime_type: mime_type.clone(),
                    file_size,
                });
            }
            Err(e) => {
                error!("insert attachment: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Failed to store file" })),
                ).into_response();
            }
        }
    }

    let count = response_attachments.len();
    let total_kb = total_size / 1024;
    info!("{identity} uploaded {count} file(s) ({total_kb} KB total)");
    Json(UploadResult {
        ok: true,
        attachments: response_attachments,
    })
        .into_response()
}

/// GET /attachments/:id — retrieve a file by attachment ID
pub async fn get_attachment(
    Extension(state): Extension<Arc<AppState>>,
    Path(attachment_id): Path<i64>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let auth_result = if let Ok(id) = require_auth(&headers, &state.jwt_secret) {
        Some(id)
    } else if let Some(token) = params.get("token") {
        validate_jwt(token, &state.jwt_secret)
    } else {
        None
    };

    let _identity = match auth_result {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or expired token" })),
            )
                .into_response();
        }
    };

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    // Fetch attachment using prepare to handle errors explicitly
    let (filename, mime_type, file_size, data) = match db
        .prepare("SELECT filename, mime_type, file_size, file_data FROM attachments WHERE id = ?1")
    {
        Ok(mut stmt) => {
            match stmt.query_row(rusqlite::params![attachment_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            }) {
                Ok(att) => att,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "Attachment not found" })),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("query attachment: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Database error" })),
                    )
                        .into_response();
                }
            }
        }
        Err(e) => {
            error!("prepare statement: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
                .into_response();
        }
    };

    debug!("attachment {attachment_id} served: {filename} ({file_size} bytes)");
    (
        [
            (axum::http::header::CONTENT_TYPE, mime_type),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{}\"", filename),
            ),
            (axum::http::header::CONTENT_LENGTH, file_size.to_string()),
        ],
        data,
    )
        .into_response()
}

```

# src\invites.rs

```rs
use std::sync::Arc;
use axum::extract::Extension;
use super::*;

#[derive(Deserialize)]
pub struct CreateInvite {
    /// Hours until expiry. 0 or absent = never expires.
    #[serde(default)]
    pub expires_in_hours: Option<u64>,
    /// Max redemptions. 0 or absent = unlimited.
    #[serde(default)]
    pub max_uses: Option<u64>,
}

#[derive(Serialize)]
pub struct InviteInfo {
    pub code: String,
    pub server_name: String,
    pub ws_url: String,
    pub api_url: String,
    pub uses_left: Option<i64>,  // None = unlimited
    pub expires_at: Option<i64>, // None = never
    pub created_by: String,
}

/// POST /invites  — create an invite link (any authenticated user)
pub async fn create_invite(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<CreateInvite>,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Check if non-owners are allowed to create invites
    {
        let s = state.settings.read().await;
        if !s.invites_anyone_can_create && !s.owner_beam_identity.is_empty() && identity != s.owner_beam_identity {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Only the server owner can create invites" })),
            )
                .into_response();
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Use request body if provided, otherwise fall back to configured defaults
    let settings_snapshot = state.settings.read().await;
    let default_expiry = settings_snapshot.default_invite_expiry_hours;
    let default_max_uses = settings_snapshot.default_invite_max_uses;
    drop(settings_snapshot);

    let expiry_hours = body.expires_in_hours.unwrap_or(default_expiry);
    let use_limit    = body.max_uses.unwrap_or(default_max_uses);

    let expires_at: Option<i64> = if expiry_hours > 0 {
        Some(now + (expiry_hours as i64) * 3600)
    } else {
        None
    };

    let max_uses: Option<i64> = if use_limit > 0 { Some(use_limit as i64) } else { None };

    // Generate a unique code (retry on collision — vanishingly rare)
    let code = loop {
        let candidate = generate_invite_code();
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let exists: bool = db
            .query_row(
                "SELECT 1 FROM invites WHERE code = ?1",
                rusqlite::params![candidate],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !exists {
            break candidate;
        }
    };

    {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = db.execute(
            "INSERT INTO invites (code, created_by, expires_at, max_uses)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![code, identity, expires_at, max_uses],
        ) {
            error!("insert invite: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to create invite" })),
            )
                .into_response();
        }
    }

    let public_url = state.settings.read().await.public_url.clone();
    let web_url = format!("{}/join/{}", public_url, code);
    let deep_url = format!("zeeble://join/{}", code);

    info!(
        "{identity} created invite {code} (expires={expires_at:?}, max_uses={max_uses:?})"
    );

    Json(json!({
        "code":      code,
        "web_url":   web_url,
        "deep_url":  deep_url,
        "expires_at": expires_at,
        "max_uses":  max_uses,
    }))
        .into_response()
}

/// GET /invites/:code  — peek at an invite (no side-effects, used by the join page)
pub async fn get_invite(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let row = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        db.query_row(
            "SELECT code, created_by, expires_at, max_uses, use_count
             FROM invites WHERE code = ?1",
            rusqlite::params![code],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
    }; // db lock dropped here, before any .await

    let (code, created_by, expires_at, max_uses, use_count) = match row {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Invite not found" })),
            )
                .into_response();
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if let Some(exp) = expires_at
        && now > exp
    {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "This invite has expired" })),
        )
            .into_response();
    }
    if let Some(max) = max_uses
        && use_count >= max
    {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "This invite has reached its maximum uses" })),
        )
            .into_response();
    }

    let (server_name, public_url) = {
        let s = state.settings.read().await;
        (s.server_name.clone(), s.public_url.clone())
    };
    let base = public_url.trim_end_matches('/');
    let ws_url = base
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
        + "/ws";

    debug!("invite peeked: {code}");
    Json(InviteInfo {
        code,
        server_name,
        ws_url,
        api_url: public_url,
        uses_left: max_uses.map(|m| m - use_count),
        expires_at,
        created_by,
    })
        .into_response()
}

/// POST /invites/:code/redeem  — consume one use (call once the client has connected)
pub async fn redeem_invite(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Check allow_new_members gate
    if !state.settings.read().await.allow_new_members {
        warn!("invite redeem blocked: allow_new_members=false (attempted by {identity}, code={code})");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "This server is not accepting new members at this time." })),
        )
            .into_response();
    }

    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Atomic update: increment only if invite exists, not expired, and under max_uses
    let rows_affected = db.execute(
        "UPDATE invites SET use_count = use_count + 1 \
         WHERE code = ?1 AND (expires_at IS NULL OR expires_at > ?2) \
         AND (max_uses IS NULL OR use_count < max_uses)",
        rusqlite::params![code, now],
    );

    match rows_affected {
        Ok(1) => {
            info!("{identity} redeemed invite {code}");
            Json(json!({ "ok": true })).into_response()
        }
        Ok(0) => {
            // Check if invite exists to provide appropriate error
            let exists: bool = db
                .query_row(
                    "SELECT 1 FROM invites WHERE code = ?1",
                    rusqlite::params![code],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if !exists {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Invite not found" })),
                )
                    .into_response()
            } else {
                // Retrieve details to determine exact failure reason
                let row = db.query_row(
                    "SELECT expires_at, max_uses, use_count FROM invites WHERE code = ?1",
                    rusqlite::params![code],
                    |row| {
                        Ok((
                            row.get::<_, Option<i64>>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                );

                match row {
                    Ok((expires_at, max_uses, use_count)) => {
                        if let Some(exp) = expires_at
                            && now >= exp
                        {
                            return (StatusCode::GONE, Json(json!({ "error": "Invite expired" })))
                                .into_response();
                        }
                        if let Some(max) = max_uses
                            && use_count >= max
                        {
                            return (
                                StatusCode::GONE,
                                Json(json!({ "error": "Invite at max uses" })),
                            )
                                .into_response();
                        }
                        // Fallback if something else prevented the update
                        (
                            StatusCode::GONE,
                            Json(json!({ "error": "Invite cannot be redeemed" })),
                        )
                            .into_response()
                    }
                    Err(_) => (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "Invite not found" })),
                    )
                        .into_response(),
                }
            }
        }
        Err(e) => {
            error!("redeem invite: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to redeem invite" })),
            )
                .into_response()
        }
        _ => unreachable!(),
    }
}

/// DELETE /invites/:code  — revoke (creator only)
pub async fn delete_invite(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let created_by: Option<String> = db
        .query_row(
            "SELECT created_by FROM invites WHERE code = ?1",
            rusqlite::params![code],
            |row| row.get(0),
        )
        .ok();

    match created_by {
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Invite not found" })),
        )
            .into_response(),
        Some(creator) if creator != identity => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only the invite creator can revoke it" })),
        )
            .into_response(),
        Some(_) => {
            db.execute(
                "DELETE FROM invites WHERE code = ?1",
                rusqlite::params![code],
            )
                .ok();
            info!("{identity} revoked invite {code}");
            (StatusCode::OK, Json(json!({ "deleted": true }))).into_response()
        }
    }
}

/// GET /join/:code  — browser-friendly landing page
pub async fn join_page(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let api_url = state.settings.read().await.public_url.clone();
    let api_url_base = api_url.trim_end_matches('/');
    let api_url = &api_url_base;
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Join — Zeeble</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
    :root {{
      --bg:      #0d0f14;
      --surface: #161922;
      --border:  #1e2535;
      --accent:  #e94560;
      --blue:    #4e9fff;
      --text:    #e2e8f0;
      --muted:   #64748b;
    }}
    *, *::before, *::after {{ margin:0; padding:0; box-sizing:border-box; }}
    body {{
      font-family: 'Space Grotesk', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }}
    body::before {{
      content: '';
      position: fixed; inset: 0;
      background-image:
        linear-gradient(var(--border) 1px, transparent 1px),
        linear-gradient(90deg, var(--border) 1px, transparent 1px);
      background-size: 40px 40px;
      opacity: 0.35;
      pointer-events: none;
    }}
    .card {{
      position: relative;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 40px;
      max-width: 420px;
      width: 100%;
      box-shadow: 0 0 80px rgba(233,69,96,0.07), 0 24px 48px rgba(0,0,0,0.45);
      animation: rise 0.4s cubic-bezier(.16,1,.3,1) both;
    }}
    @keyframes rise {{ from {{ opacity:0; transform:translateY(16px); }} }}
    .card::before {{
      content: '';
      position: absolute;
      top: -1px; left: 20%; right: 20%;
      height: 2px;
      background: linear-gradient(90deg, transparent, var(--accent), transparent);
      border-radius: 99px;
    }}
    .logo {{
      font-size: 1rem; font-weight: 700;
      color: var(--accent); letter-spacing: 5px;
      text-transform: uppercase; margin-bottom: 28px;
    }}
    .badge {{
      display: inline-flex; align-items: center; gap: 6px;
      background: rgba(233,69,96,0.1);
      border: 1px solid rgba(233,69,96,0.25);
      color: var(--accent);
      font-size: 0.72rem; font-family: 'JetBrains Mono', monospace;
      padding: 4px 10px; border-radius: 99px;
      margin-bottom: 20px; letter-spacing: 0.04em;
    }}
    .server-name {{
      font-size: 1.65rem; font-weight: 700;
      margin-bottom: 6px; line-height: 1.2;
    }}
    .creator {{
      font-size: 0.85rem; color: var(--muted);
      margin-bottom: 20px;
    }}
    .creator span {{ font-family: 'JetBrains Mono', monospace; color: var(--blue); font-size: 0.8rem; }}
    .meta-row {{ display: flex; gap: 10px; margin-bottom: 28px; flex-wrap: wrap; }}
    .meta-pill {{
      display: flex; align-items: center; gap: 5px;
      font-size: 0.77rem; color: var(--muted);
      background: rgba(255,255,255,0.04);
      border: 1px solid var(--border);
      padding: 5px 10px; border-radius: 6px;
    }}
    .divider {{ height: 1px; background: var(--border); margin: 0 0 24px; }}
    .btn-group {{ display: flex; flex-direction: column; gap: 10px; }}
    .btn {{
      display: flex; align-items: center; justify-content: center; gap: 8px;
      padding: 13px 20px; border-radius: 10px;
      font-family: 'Space Grotesk', sans-serif;
      font-size: 0.92rem; font-weight: 600;
      text-decoration: none; cursor: pointer;
      border: none; transition: all 0.15s;
    }}
    .btn-primary {{ background: var(--accent); color: #fff; }}
    .btn-primary:hover {{ background: #c73652; transform: translateY(-1px); box-shadow: 0 6px 24px rgba(233,69,96,0.35); }}
    .btn-secondary {{
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
    }}
    .btn-secondary:hover {{ background: rgba(255,255,255,0.05); }}
    .code-line {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem; color: var(--muted);
      text-align: center; margin-top: 14px;
    }}
    .error-wrap {{ text-align: center; padding: 16px 0; }}
    .error-icon {{ font-size: 2rem; margin-bottom: 10px; }}
    .error-title {{ font-size: 1rem; font-weight: 700; color: var(--accent); margin-bottom: 6px; }}
    .error-msg {{ font-size: 0.85rem; color: var(--muted); }}
    .loading {{ text-align:center; color:var(--muted); font-size:0.9rem; padding:16px 0; }}
    .dot::after {{
      content:''; animation: dots 1.2s steps(4,end) infinite;
    }}
    @keyframes dots {{
      0%,20% {{ content:''; }} 40% {{ content:'.'; }}
      60% {{ content:'..'; }} 80%,100% {{ content:'...'; }}
    }}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">⚡ ZEEBLE</div>
  <div id="root"><div class="loading">Fetching invite<span class="dot"></span></div></div>
</div>
<script>
const CODE    = {code_json};
const API_URL = {api_url_json};

async function load() {{
  try {{
    const r = await fetch(`${{API_URL}}/invites/${{CODE}}`);
    const d = await r.json();
    if (!r.ok) {{ renderError(d.error || 'Invalid invite'); return; }}
    render(d);
  }} catch {{ renderError('Could not reach the server.'); }}
}}

function fmt_expiry(ts) {{
  if (!ts) return 'Never expires';
  return 'Expires ' + new Date(ts * 1000).toLocaleDateString(undefined,
    {{month:'short', day:'numeric', year:'numeric'}});
}}

function fmt_uses(n) {{
  if (n === null || n === undefined) return 'Unlimited uses';
  return n === 1 ? '1 use remaining' : `${{n}} uses remaining`;
}}

function render(inv) {{
  document.getElementById('root').innerHTML = `
    <div class="badge">&#9993; You've been invited</div>
    <div class="server-name">${{inv.server_name}}</div>
    <div class="creator">Invited by <span>${{inv.created_by}}</span></div>
    <div class="meta-row">
      <div class="meta-pill">&#x23F1; ${{fmt_expiry(inv.expires_at)}}</div>
      <div class="meta-pill">&#x1F465; ${{fmt_uses(inv.uses_left)}}</div>
    </div>
    <div class="divider"></div>
    <div class="btn-group">
      <a class="btn btn-primary" href="zeeble://join/${{CODE}}">&#9889; Open in Zeeble</a>
      <button class="btn btn-secondary" onclick="copyLink(this)">&#x2398; Copy invite link</button>
    </div>
    <div class="code-line">code: ${{CODE}}</div>
  `;
}}

function renderError(msg) {{
  document.getElementById('root').innerHTML = `
    <div class="error-wrap">
      <div class="error-icon">&#x2715;</div>
      <div class="error-title">Invite invalid</div>
      <div class="error-msg">${{msg}}</div>
    </div>`;
}}

function copyLink(btn) {{
  navigator.clipboard.writeText(window.location.href).then(() => {{
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => btn.textContent = orig, 2000);
  }});
}}

load();
</script>
</body>
</html>"#,
        code_json = serde_json::to_string(&code).unwrap(),
        api_url_json = serde_json::to_string(api_url).unwrap(),
    );

    Html(html).into_response()
}
```

# src\main.rs

```rs
use axum::{
    Json, Router,
    extract::{
        Path, Query,
        multipart::Multipart,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post},
};
use rusqlite::{Connection, ToSql};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use local_ip_address::list_afinet_netifas;
use toml;
use reqwest;

use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tower_http::compression::CompressionLayer;
use tracing::{debug, error, info, warn};

mod channels;
mod messages;
mod invites;
mod members;
mod files;
mod ws;

// Router builder function
fn create_router(state: Arc<AppState>) -> Router<()>
{
    let app = Router::<()>::new()
        .route("/channels", get(channels::list_channels).post(channels::create_channel))
        .route("/channels/:id", delete(channels::delete_channel).patch(channels::rename_channel))
        .route("/channels/:channel_id/messages", get(messages::get_messages).post(messages::create_message))
        .route("/messages/:message_id", patch(messages::edit_message).delete(messages::delete_message))
        .route("/invites", post(invites::create_invite))
        .route("/invites/:code", get(invites::get_invite).delete(invites::delete_invite))
        .route("/invites/:code/redeem", post(invites::redeem_invite))
        .route("/members", get(members::get_members))
        .route("/account/status", patch(members::update_status))
        .route("/upload", post(files::upload_file))
        .route("/attachments/:id", get(files::get_attachment))
        .route("/first-time-setup", post(invites::create_invite))
        .route("/ws", get(ws::ws_handler))
        .route("/join/:code", get(invites::join_page))
        .route("/health", get(|| async { 
            Json(json!({ 
                "status": "ok", 
                "server_name": "Zeeble Server", 
                "version": "0.1.0" 
            }))
        }))
        .route("/server/info", get(server_info))
        .fallback(|| async { (StatusCode::NOT_FOUND, "Not Found") })
        .layer(CompressionLayer::new())
        .layer(axum::extract::DefaultBodyLimit::max(50 * 1024 * 1024))
        .layer(axum::extract::Extension(state.clone()))
        .layer(CorsLayer::permissive());

    app
}

async fn server_info(
    axum::extract::Extension(state): axum::extract::Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let s = state.settings.read().await;
    
    // Get basic channel list for discovery (public)
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
    }))
}

// ── Config ────────────────────────────────────────────────────────────────────

const CONFIG_FILE: &str = "zeeble.toml";

/// Parse human-readable byte sizes like "8MB", "500KB", "2GB", "1024".
/// Case-insensitive. Returns None if the string can't be parsed.
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_part, unit) = match s.find(|c: char| c.is_alphabetic()) {
        Some(i) => (&s[..i], s[i..].trim().to_uppercase()),
        None => (s, String::new()),
    };
    let num: f64 = num_part.trim().parse().ok()?;
    let multiplier: u64 = match unit.as_str() {
        "" | "B"  => 1,
        "KB"      => 1_024,
        "MB"      => 1_024 * 1_024,
        "GB"      => 1_024 * 1_024 * 1_024,
        "TB"      => 1_024 * 1_024 * 1_024 * 1_024,
        _         => return None,
    };
    Some((num * multiplier as f64) as u64)
}

/// Raw deserialized shape of `zeeble.toml`.
/// All fields optional — resolution happens in `Config::load` / `Settings::from_file`.
#[derive(Deserialize, Default, Clone, Serialize)]
struct ConfigFile {
    // ── Startup-only ──────────────────────────────
    port:                       Option<u16>,
    jwt_secret:                 Option<String>,
    db_path:                    Option<String>,
    auth_server_url:            Option<String>,
    register_token:             Option<String>, // token for auto-registering this server with the auth server

    // ── Hot-reloadable ────────────────────────────
    server_name:                Option<String>,
    public_url:                 Option<String>,
    owner_beam_identity:        Option<String>,
    about:                      Option<String>,
    max_message_length:         Option<u64>,
    max_upload_size:            Option<String>,
    invites_anyone_can_create:  Option<bool>,
    default_invite_expiry_hours:Option<u64>,
    default_invite_max_uses:    Option<u64>,
    allow_new_members:          Option<bool>,
}

// ── Startup-only config (never changes after boot) ────────────────────────────

struct Config {
    port:            u16,
    jwt_secret:      String,
    db_path:         String,
    auth_server_url: String,
    register_token:  Option<String>,
    /// Path to the config file that was loaded (or None if not found).
    config_path:     Option<String>,
}

// ── Hot-reloadable settings ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Settings {
    pub server_name:                 String,
    pub public_url:                  String,
    pub owner_beam_identity:         String,
    pub about:                       Option<String>,
    pub max_message_length:          u64,
    pub max_upload_bytes:            u64,
    pub invites_anyone_can_create:   bool,
    pub default_invite_expiry_hours: u64,
    pub default_invite_max_uses:     u64,
    pub allow_new_members:           bool,
}

impl Settings {
    fn from_file(file: &ConfigFile, port: u16) -> Self {
        let public_url_default = format!("http://localhost:{port}");

        let owner_beam_identity = std::env::var("OWNER_BEAM_IDENTITY")
            .ok()
            .or_else(|| file.owner_beam_identity.clone())
            .unwrap_or_default();

        if owner_beam_identity.is_empty() {
            warn!("owner_beam_identity is not set — owner-only actions will be unrestricted");
        }

        let max_upload_bytes = std::env::var("MAX_UPLOAD_SIZE")
            .ok()
            .or_else(|| file.max_upload_size.clone())
            .and_then(|s| parse_size(&s))
            .unwrap_or(8 * 1024 * 1024); // 8 MB default

        Self {
            server_name: std::env::var("SERVER_NAME")
                .ok()
                .or_else(|| file.server_name.clone())
                .unwrap_or_else(|| "Zeeble Server".into()),

            public_url: std::env::var("PUBLIC_URL")
                .ok()
                .or_else(|| file.public_url.clone())
                .unwrap_or(public_url_default),

            owner_beam_identity,
            about: file.about.clone(),
            max_message_length: file.max_message_length.unwrap_or(4000),
            max_upload_bytes,
            invites_anyone_can_create: file.invites_anyone_can_create.unwrap_or(true),
            default_invite_expiry_hours: file.default_invite_expiry_hours.unwrap_or(0),
            default_invite_max_uses: file.default_invite_max_uses.unwrap_or(0),
            allow_new_members: file.allow_new_members.unwrap_or(true),
        }
    }
}

// ── Config template written on first run ─────────────────────────────────────

const CONFIG_EXAMPLE: &str = r#"# ─────────────────────────────────────────────────────────────────────────────
#  ZEEBLE SERVER  —  zeeble.toml
#
#  Most settings marked "live" are applied immediately when you save this file.
#  Settings marked "restart required" only take effect after a server restart.
#  Environment variables always override values in this file.
# ─────────────────────────────────────────────────────────────────────────────

# ── Network ──────────────────────────────────────────────────────────────────
# [restart required]
port = 4000

# Publicly reachable base URL — used in invite links and the join page.
# Defaults to http://localhost:<port> if not set.
# [live]
# public_url = "https://chat.example.com"

# ── Security ─────────────────────────────────────────────────────────────────
# REQUIRED. Secret used to sign and verify JWT tokens.
# If left empty or unspecified, a random secret will be generated on first startup.
# Change this to a long random string before going live.
# [restart required]
# jwt_secret = ""

# ── Storage ───────────────────────────────────────────────────────────────────
# [restart required]
db_path = "zeeble.db"

# Maximum size for a single file upload.
# Supports human-readable units: KB, MB, GB  (e.g. "25MB", "1GB")
# [live]
max_upload_size = "8MB"

# ── Chat ──────────────────────────────────────────────────────────────────────
# Maximum number of characters in a single message.
# [live]
max_message_length = 4000

# ── Invites ───────────────────────────────────────────────────────────────────
# Allow any authenticated user to create invite links.
# Set to false to restrict invite creation to the server owner only.
# [live]
invites_anyone_can_create = true

# Default expiry for new invites, in hours. 0 = never expires.
# [live]
default_invite_expiry_hours = 0

# Default max redemptions for new invites. 0 = unlimited.
# [live]
default_invite_max_uses = 0

# Set to false to stop new members from joining via invite links.
# [live]
allow_new_members = true

# ── Identity ──────────────────────────────────────────────────────────────────
# Display name shown on invite pages and in /server/info.
# [live]
server_name = "Zeeble Server"

# Beam identity of the server owner.
# Required for owner-only actions (creating/deleting channels, etc.)
# [live]
# owner_beam_identity = "admin#abc12"

# A short description of this server, shown in /server/info.
# [live]
# about = "A chill place to hang out."
"#;

impl Config {
    /// Load startup config with the following priority (highest → lowest):
    ///   1. Environment variables
    ///   2. `zeeble.toml` (if present)
    ///   3. Built-in defaults
    fn load() -> (Self, ConfigFile) {
        // Load .env file if present (lowest priority — real env vars win)
        let _ = dotenvy::dotenv();

        // Try to read and parse zeeble.toml
        let (mut file, config_path) = match std::fs::read_to_string(CONFIG_FILE) {
            Ok(contents) => {
                let parsed: ConfigFile = toml::from_str(&contents)
                    .unwrap_or_else(|e| panic!("Invalid {CONFIG_FILE}: {e}"));
                (parsed, Some(CONFIG_FILE.to_string()))
            }
            Err(_) => {
                // File absent — write an example so the user knows what's available
                if let Err(e) = std::fs::write(CONFIG_FILE, CONFIG_EXAMPLE) {
                    eprintln!("Warning: could not write example {CONFIG_FILE}: {e}");
                }
                (ConfigFile::default(), None)
            }
        };

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .or(file.port)
            .unwrap_or(4000);

        // Resolve JWT secret: env > file. If empty/missing/placeholder, generate random and persist.
        let mut jwt_secret_opt = if let Ok(secret) = std::env::var("JWT_SECRET") {
            Some(secret)
        } else if let Some(ref secret) = file.jwt_secret {
            if !secret.is_empty() && secret != "change-me-to-a-long-random-secret" {
                Some(secret.clone())
            } else {
                None
            }
        } else {
            None
        };

        if jwt_secret_opt.is_none() {
            // Generate a new random secret
            let generated = Self::generate_jwt_secret();
            eprintln!("Generated a new JWT_SECRET because none was configured or the placeholder is still used. This will be written to {CONFIG_FILE}. For production, set a strong secret via JWT_SECRET env var or in {CONFIG_FILE}.");
            file.jwt_secret = Some(generated.clone());
            // Write back the updated config file
            if let Ok(toml) = toml::to_string_pretty(&file) {
                let _ = std::fs::write(CONFIG_FILE, toml);
            }
            jwt_secret_opt = Some(generated);
        }
        let jwt_secret = jwt_secret_opt.unwrap();

        let db_path = std::env::var("DB_PATH")
            .ok()
            .or_else(|| file.db_path.clone())
            .unwrap_or_else(|| "zeeble.db".into());

        let auth_server_url = std::env::var("AUTH_SERVER_URL")
            .ok()
            .or_else(|| file.auth_server_url.clone())
            .unwrap_or_else(|| "http://localhost:3001".into());

        let register_token = std::env::var("AUTH_REGISTER_TOKEN")
            .ok()
            .or_else(|| file.register_token.clone());

        (
            Self { port, jwt_secret, db_path, auth_server_url, register_token, config_path },
            file,
        )
    }

    /// Generate a cryptographically random 256-bit (32-byte) base64 secret.
    fn generate_jwt_secret() -> String {
        use rand::RngCore;
        use base64::{Engine, engine::general_purpose::STANDARD};
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        STANDARD.encode(&bytes)
    }
}

// ── JWT ───────────────────────────────────────────────────────────────────────

fn validate_jwt(token: &str, secret: &str) -> Option<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(signing_input.as_bytes());
    let sig_bytes = base64_url_decode(parts[2])?;
    mac.verify_slice(&sig_bytes).ok()?;

    let payload_bytes = base64_url_decode(parts[1])?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;

    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64()) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        if now > exp {
            return None;
        }
    }

    payload
        .get("beam_identity")
        .or_else(|| payload.get("sub"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let padded = match input.len() % 4 {
        2 => format!("{}==", input),
        3 => format!("{}=", input),
        _ => input.to_string(),
    };
    STANDARD
        .decode(padded.replace('-', "+").replace('_', "/"))
        .ok()
}

// ── Utilities ────────────────────────────────────────────────────────────────

/// Format a byte count as a human-readable string like "8 MB", "512 KB".
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

// ── Invite code generation ────────────────────────────────────────────────────

/// Generates a random invite code like `zbl-a3f9k2t8`.
/// Uses a simple LCG seeded from nanosecond time — no extra deps.
fn generate_invite_code() -> String {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let mut x = seed ^ 0x9e3779b97f4a7c15;
    let chars: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut code = String::from("zbl-");
    for _ in 0..8 {
        x = x
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = ((x >> 33) as usize) % chars.len();
        code.push(chars[idx] as char);
    }
    code
}

// ── State ─────────────────────────────────────────────────────────────────────

pub type ChannelBus = Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>;

pub struct AppState {
    pub db: Mutex<Connection>,
    pub buses: ChannelBus,
    pub jwt_secret: String,
    pub auth_server_url: String,
    pub online_users: Mutex<HashMap<String, usize>>,
    /// Hot-reloadable settings — read with `state.settings.read().await`
    pub settings: Arc<tokio::sync::RwLock<Settings>>,
    /// Server-wide broadcast channel for member/channel updates
    pub server_bus: broadcast::Sender<String>,
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

    /// Broadcast member list update to all connected clients
    async fn broadcast_member_update(&self) {
        let rows: Vec<(String, i64, String)> = {
            let db = match self.db.lock() {
                Ok(db) => db,
                Err(_) => return,
            };
            let mut stmt = match db.prepare(
                "SELECT m.beam_identity, COUNT(*) as message_count, COALESCE(MAX(u.status), 'offline') as status\n             FROM messages m\n             LEFT JOIN users u ON m.beam_identity = u.beam_identity\n             GROUP BY m.beam_identity\n             ORDER BY message_count DESC",
            ) {
                Ok(s) => s,
                Err(e) => {
                    error!("prepare members: {e}");
                    return;
                }
            };
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect()
        };

        let mut online = Vec::new();
        let mut offline = Vec::new();

        for (beam_identity, _message_count, status) in rows {
            let member = members::FrontendMember {
                name: beam_identity,
                status: status.clone(),
                role: None,
                avatar: None,
            };
            if status == "online" {
                online.push(member);
            } else {
                offline.push(member);
            }
        }

        let mut categories = Vec::new();
        if !online.is_empty() {
            categories.push(members::MemberCategory {
                category: "Online".to_string(),
                users: online,
            });
        }
        if !offline.is_empty() {
            categories.push(members::MemberCategory {
                category: "Offline".to_string(),
                users: offline,
            });
        }

        let broadcast = serde_json::to_string(&json!({
            "type": "member",
            "members": categories,
            "server_id": self.settings.read().await.server_name.clone(),
        })).unwrap();
        let _ = self.server_bus.send(broadcast);
    }
}

// ── DB helpers ────────────────────────────────────────────────────────────────

pub fn setup_db(conn: &Connection) {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS channels (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            topic       TEXT NOT NULL DEFAULT '',
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
            file_data       BLOB NOT NULL,
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
            expires_at     INTEGER,     -- NULL = never expires
            max_uses       INTEGER,     -- NULL = unlimited
            use_count      INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS users (
            beam_identity TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'offline'
        );

        INSERT OR IGNORE INTO channels (id, name, topic)
        VALUES ('general', 'general', 'General chat for everyone');
    ",
    )
        .expect("DB setup failed");
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn require_auth(headers: &HeaderMap, secret: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let b = bearer(headers);
    match b.and_then(|t| validate_jwt(t, secret)) {
        Some(id) => Ok(id),
        None => {
            let reason = if b.is_none() { 
                debug!("auth headers missing. keys present: {:?}", headers.keys().collect::<Vec<_>>());
                "missing token" 
            } else { 
                "invalid/expired token" 
            };
            warn!("auth rejected: {reason}");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or expired token" })),
            ))
        }
    }
}

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

    // Build initial hot-reloadable settings from the parsed config file
    let initial_settings = Settings::from_file(&config_file, port);

    // Capture values needed for optional registration with auth server
    let register_token = config.register_token.clone();
    let auth_server_url_for_reg = config.auth_server_url.clone();
    let public_url_for_reg = initial_settings.public_url.clone();
    let owner_beam_for_reg = initial_settings.owner_beam_identity.clone();
    let chat_secret_for_reg = config.jwt_secret.clone();

    // Create a real one-time invite in the DB for first-time setup
    let startup_invite = {
    let mut conn = Connection::open(&config.db_path)
            .unwrap_or_else(|e| panic!("Failed to open DB for startup invite: {e}"));
        setup_db(&conn);
        let invite = create_startup_invite(&mut conn);
        
        // Print startup invite before moving the connection
        println!("\n🎟️  STARTUP INVITE (one-time use, stored in DB):");
        println!("   • Code:        {}", invite);
        println!("   • Web URL:     {}/join/{}", initial_settings.public_url.clone(), invite);
        println!("   • Deep Link:   zeeble://join/{}", invite);
        
        invite
    };

    // Clone display values before moving into state
    let server_name = initial_settings.server_name.clone();
    let public_url  = initial_settings.public_url.clone();

    let conn = Connection::open(&config.db_path)
        .unwrap_or_else(|e| panic!("Failed to open DB at {}: {e}", config.db_path));
    info!("database opened: {}", config.db_path);
    setup_db(&conn);
    debug!("database schema initialized");

    let settings = Arc::new(tokio::sync::RwLock::new(initial_settings));

    let (server_bus, _) = broadcast::channel(256);
    let state = Arc::new(AppState {
        db: Mutex::new(conn),
        buses: Arc::new(Mutex::new(HashMap::new())),
        jwt_secret: config.jwt_secret,
        auth_server_url: config.auth_server_url.clone(),
        online_users: Mutex::new(HashMap::new()),
        settings: Arc::clone(&settings),
        server_bus,
    });

    // Auto-register with auth server if register_token and owner_beam are set
    if let Some(token) = register_token {
        if !owner_beam_for_reg.is_empty() {
            let public_url = public_url_for_reg.clone();
            let auth_url = auth_server_url_for_reg.clone();
            let chat_secret = chat_secret_for_reg.clone();
            let owner = owner_beam_for_reg.clone();
            tokio::spawn(async move {
                match reqwest::Client::new()
                    .post(&format!("{}/servers/register", auth_url))
                    .header("X-Register-Token", token)
                    .json(&json!({
                        "server_url": public_url,
                        "owner_beam_identity": owner,
                        "jwt_secret": chat_secret,
                    }))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        info!("Successfully registered chat server {} with auth", public_url);
                    }
                Ok(resp) => {
                    let status = resp.status();
                    let txt = resp.text().await.unwrap_or_default();
                    warn!("Auth registration failed for {}: {} - {}", public_url, status, txt);
                }
                    Err(e) => {
                        warn!("Auth registration error for {}: {}", public_url, e);
                    }
                }
            });
        }
    }

    // Get local IP addresses
    let local_ips: Vec<String> = get_local_ips();

    // Print beautiful startup banner
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
    for ip in local_ips {
        if ip.starts_with("localhost") {
            println!(
                "   • {} (localhost)",
                ip.split(": ").nth(1).unwrap_or("127.0.0.1")
            );
        } else {
            let parts: Vec<&str> = ip.split(": ").collect();
            if parts.len() == 2 {
                println!("   • http://{}:{} ({})", parts[1], port, parts[0]);
            }
        }
    }

    println!("\n🔗 IMPORTANT ENDPOINTS:");
    println!("   • API Base:    {}", public_url);
    println!("   • WebSocket:   {}/ws", public_url.replace("http", "ws"));
    println!("   • Health:      {}/health", public_url);
    println!("   • Join Page:   {}/join/{}", public_url, startup_invite);

    println!("\n⚡ Server is now running. Press Ctrl+C to stop.");
    println!("   Config changes in zeeble.toml are applied live — no restart needed.");
    println!("{}", "═".repeat(60));
    println!();

    // Log active settings at info level so they appear in log output
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

        // Spawn config file watcher
        let settings_watcher = Arc::clone(&settings);
        tokio::spawn(async move {
            let mut last_content = String::new();
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                match std::fs::read_to_string(CONFIG_FILE) {
                    Ok(contents) => {
                        if contents == last_content {
                            continue;
                        }
                        let parsed: ConfigFile = match toml::from_str(&contents) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("config watcher: failed to parse {CONFIG_FILE}: {e}");
                                continue;
                            }
                        };
                        let new_settings = Settings::from_file(&parsed, port);
                        let mut lock = settings_watcher.write().await;
                        *lock = new_settings;
                        last_content = contents;
                        info!("config watcher: reloaded {CONFIG_FILE}");
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            continue;
                        }
                        warn!("config watcher: failed to read {CONFIG_FILE}: {e}");
                    }
                }
            }
        });

        // Create the app before starting the server
        let app = create_router(state);

        let addr = format!("0.0.0.0:{}", port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to bind {addr}: {e}"));
        axum::serve(listener, app).await.unwrap();
    }); // closes runtime.block_on(async {
} // closes fn main()

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
    ).unwrap_or_default();

    tx.commit().unwrap();
    info!("startup invite created: {}", code);
    code
}

fn get_local_ips() -> Vec<String> {
    let mut ips = Vec::new();
    ips.push("localhost: 127.0.0.1".to_string());

    if let Ok(ifas) = list_afinet_netifas() {
        for (name, addr) in ifas {
            if addr.is_loopback() || addr.is_ipv6() {
                continue;
            }
            ips.push(format!("{name}: {addr}"));
        }
    }

    ips
}
```

# src\members.rs

```rs
use std::sync::Arc;
use axum::extract::Extension;
use super::*;

#[derive(Deserialize)]
pub struct UpdateStatusBody {
    pub status: String,
}

#[derive(Serialize)]
pub struct FrontendMember {
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

#[derive(Serialize)]
pub struct MemberCategory {
    pub category: String,
    pub users: Vec<FrontendMember>,
}

/// GET /members  — list all unique users who have ever posted, sorted by message count
pub async fn get_members(headers: HeaderMap, Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    if let Err(e) = require_auth(&headers, &state.jwt_secret) {
        return e.into_response();
    }
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };
    let mut stmt = match db.prepare(
        "SELECT m.beam_identity, COUNT(*) as message_count, COALESCE(MAX(u.status), 'offline') as status
         FROM messages m
         LEFT JOIN users u ON m.beam_identity = u.beam_identity
         GROUP BY m.beam_identity
         ORDER BY message_count DESC",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("prepare members: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response();
        }
    };
    let rows: Vec<(String, i64, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    let mut online = Vec::new();
    let mut offline = Vec::new();

    for (beam_identity, _message_count, status) in rows {
        let member = FrontendMember {
            name: beam_identity,
            status: status.clone(),
            role: None,
            avatar: None,
        };
        if status == "online" {
            online.push(member);
        } else {
            offline.push(member);
        }
    }

    debug!("get_members: {} online, {} offline", online.len(), offline.len());
    let mut categories = Vec::new();
    if !online.is_empty() {
        categories.push(MemberCategory {
            category: "Online".to_string(),
            users: online,
        });
    }
    if !offline.is_empty() {
        categories.push(MemberCategory {
            category: "Offline".to_string(),
            users: offline,
        });
    }

    Json(categories).into_response()
}

pub async fn update_status(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<UpdateStatusBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    if !["online", "idle", "dnd", "offline"].contains(&body.status.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid status value" })),
        )
            .into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    match db.execute(
        "INSERT INTO users (beam_identity, status) VALUES (?1, ?2) ON CONFLICT(beam_identity) DO UPDATE SET status = excluded.status",
        rusqlite::params![identity, body.status],
    ) {
        Ok(_) => {
            info!("{identity} set status → {}", body.status);
            Json(json!({ "status": body.status })).into_response()
        }
        Err(e) => {
            error!("update status: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

```

# src\messages.rs

```rs
use std::sync::Arc;
use axum::extract::Extension;
use super::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub id: i64,
    pub channel_id: String,
    pub beam_identity: String,
    pub content: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Attachment {
    pub id: i64,
    pub filename: String,
    pub mime_type: String,
    pub file_size: i64,
}

#[derive(Serialize)]
pub struct WsBroadcast {
    pub kind: &'static str,
    pub channel_id: String,
    pub id: i64,
    pub beam_identity: String,
    pub content: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attachments: Vec<Attachment>,
}

#[derive(Deserialize)]
pub struct MessagesQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub before: Option<i64>,
}

fn default_limit() -> i64 {
    50
}

#[derive(Deserialize)]
pub struct CreateMessageBody {
    pub content: String,
}

#[derive(Deserialize)]
pub struct EditMessageBody {
    pub content: String,
}

pub async fn get_messages(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
    Query(q): Query<MessagesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&headers, &state.jwt_secret) {
        return e.into_response();
    }
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };
    let exists: bool = db
        .query_row(
            "SELECT 1 FROM channels WHERE id = ?1",
            rusqlite::params![channel_id],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Channel not found" })),
        )
            .into_response();
    }
    let limit = q.limit.clamp(1, 200);
    let rows: Vec<ChatMessage> = if let Some(before) = q.before {
        let mut stmt = db
            .prepare(
                "SELECT m.id, m.channel_id, m.beam_identity, m.content, m.created_at, m.edited_at, a.id, a.filename, a.mime_type, a.file_size\n             FROM messages m\n             LEFT JOIN attachments a ON m.id = a.message_id\n             WHERE m.channel_id = ?1 AND m.created_at < ?2\n             ORDER BY m.created_at DESC LIMIT ?3",
            )
            .unwrap();
        let mut rows = Vec::new();
        let mut current_message_id = None;
        let mut current_attachments = Vec::new();
        let mut current_message: Option<ChatMessage> = None;
        
        stmt.query_map(rusqlite::params![channel_id, before, limit], |row| {
            let msg_id: i64 = row.get(0)?;
            let channel_id: String = row.get(1)?;
            let beam_identity: String = row.get(2)?;
            let content: String = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            let edited_at: Option<i64> = row.get(5)?;
            let att_id: Option<i64> = row.get(6)?;
            let att_filename: Option<String> = row.get(7)?;
            let att_mime_type: Option<String> = row.get(8)?;
            let att_file_size: Option<i64> = row.get(9)?;

            if let Some(prev_id) = current_message_id {
                if prev_id != msg_id {
                    if let Some(msg) = current_message.take() {
                        rows.push(ChatMessage {
                            id: msg.id,
                            channel_id: msg.channel_id,
                            beam_identity: msg.beam_identity,
                            content: msg.content,
                            created_at: msg.created_at,
                            edited_at: msg.edited_at,
                            attachments: current_attachments.clone(),
                        });
                    }
                    current_attachments.clear();
                }
            }

            current_message_id = Some(msg_id);
            current_message = Some(ChatMessage {
                id: msg_id,
                channel_id,
                beam_identity,
                content,
                created_at,
                edited_at,
                attachments: Vec::new(),
            });

            if let (Some(att_id), Some(att_filename), Some(att_mime_type), Some(att_file_size)) = (att_id, att_filename, att_mime_type, att_file_size) {
                current_attachments.push(Attachment {
                    id: att_id,
                    filename: att_filename,
                    mime_type: att_mime_type,
                    file_size: att_file_size,
                });
            }

            Ok(())
        }).unwrap().for_each(|_| {});

        if let Some(msg) = current_message.take() {
            rows.push(ChatMessage {
                id: msg.id,
                channel_id: msg.channel_id,
                beam_identity: msg.beam_identity,
                content: msg.content,
                created_at: msg.created_at,
                edited_at: msg.edited_at,
                attachments: current_attachments.clone(),
            });
        }
        rows
    } else {
        let mut stmt = db
            .prepare(
                "SELECT m.id, m.channel_id, m.beam_identity, m.content, m.created_at, m.edited_at, a.id, a.filename, a.mime_type, a.file_size\n             FROM messages m\n             LEFT JOIN attachments a ON m.id = a.message_id\n             WHERE m.channel_id = ?1\n             ORDER BY m.created_at DESC LIMIT ?2",
            )
            .unwrap();
        let mut rows = Vec::new();
        let mut current_message_id = None;
        let mut current_attachments = Vec::new();
        let mut current_message: Option<ChatMessage> = None;
        
        stmt.query_map(rusqlite::params![channel_id, limit], |row| {
            let msg_id: i64 = row.get(0)?;
            let channel_id: String = row.get(1)?;
            let beam_identity: String = row.get(2)?;
            let content: String = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            let edited_at: Option<i64> = row.get(5)?;
            let att_id: Option<i64> = row.get(6)?;
            let att_filename: Option<String> = row.get(7)?;
            let att_mime_type: Option<String> = row.get(8)?;
            let att_file_size: Option<i64> = row.get(9)?;

            if let Some(prev_id) = current_message_id {
                if prev_id != msg_id {
                    if let Some(msg) = current_message.take() {
                        rows.push(ChatMessage {
                            id: msg.id,
                            channel_id: msg.channel_id,
                            beam_identity: msg.beam_identity,
                            content: msg.content,
                            created_at: msg.created_at,
                            edited_at: msg.edited_at,
                            attachments: current_attachments.clone(),
                        });
                    }
                    current_attachments.clear();
                }
            }

            current_message_id = Some(msg_id);
            current_message = Some(ChatMessage {
                id: msg_id,
                channel_id,
                beam_identity,
                content,
                created_at,
                edited_at,
                attachments: Vec::new(),
            });

            if let (Some(att_id), Some(att_filename), Some(att_mime_type), Some(att_file_size)) = (att_id, att_filename, att_mime_type, att_file_size) {
                current_attachments.push(Attachment {
                    id: att_id,
                    filename: att_filename,
                    mime_type: att_mime_type,
                    file_size: att_file_size,
                });
            }

            Ok(())
        }).unwrap().for_each(|_| {});

        if let Some(msg) = current_message.take() {
            rows.push(ChatMessage {
                id: msg.id,
                channel_id: msg.channel_id,
                beam_identity: msg.beam_identity,
                content: msg.content,
                created_at: msg.created_at,
                edited_at: msg.edited_at,
                attachments: current_attachments.clone(),
            });
        }
        rows
    };
    let mut rows = rows;
    rows.reverse();
    debug!("get_messages: #{channel_id} returned {} messages", rows.len());
    Json(rows).into_response()
}

pub async fn create_message(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreateMessageBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let content = body.content.trim().to_string();
    let max_len = state.settings.read().await.max_message_length as usize;
    if content.is_empty() || content.len() > max_len {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Content must be 1–{max_len} characters") })),
        )
            .into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    let channel_exists: bool = db
        .query_row(
            "SELECT 1 FROM channels WHERE id = ?1",
            rusqlite::params![channel_id],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !channel_exists {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Channel not found" })),
        )
            .into_response();
    }

    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let insert_result = db.execute(
        "INSERT INTO messages (channel_id, beam_identity, content, created_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![channel_id, identity, content, created_at],
    );

    match insert_result {
        Ok(_) => {
            let message_id = db.last_insert_rowid();
            // Broadcast new message
            let broadcast = serde_json::to_string(&json!({
                "type":       "message",
                "id":         message_id,
                "channel_id": channel_id,
                "beam_identity": identity,
                "content":    content,
                "created_at": created_at,
            }))
            .unwrap();
            let _ = state.bus_for(&channel_id).send(broadcast);
            info!("{identity} sent message {message_id} in #{channel_id}");
            Json(json!({ "id": message_id, "created_at": created_at })).into_response()
        }
        Err(e) => {
            error!("create message: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

pub async fn edit_message(
    Extension(state): Extension<Arc<AppState>>,
    Path(message_id): Path<i64>,
    headers: HeaderMap,
    Json(body): Json<EditMessageBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let content = body.content.trim().to_string();
    let max_len = state.settings.read().await.max_message_length as usize;
    if content.is_empty() || content.len() > max_len {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("Content must be 1–{max_len} characters") })),
        )
            .into_response();
    }

    let edited_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    // Fetch channel_id so we can broadcast the edit
    let channel_id: String = match db.query_row(
        "SELECT channel_id FROM messages WHERE id = ?1 AND beam_identity = ?2",
        rusqlite::params![message_id, identity],
        |row| row.get(0),
    ) {
        Ok(ch) => ch,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Message not found or not yours" })),
            )
                .into_response();
        }
    };

    match db.execute(
        "UPDATE messages SET content = ?1, edited_at = ?2 WHERE id = ?3 AND beam_identity = ?4",
        rusqlite::params![content, edited_at, message_id, identity],
    ) {
        Ok(_) => {
            // Broadcast edit to all channel subscribers
            let broadcast = serde_json::to_string(&json!({
                "type":       "message_edited",
                "id":         message_id,
                "channel_id": channel_id,
                "content":    content,
                "edited_at":  edited_at,
            }))
            .unwrap();
            let _ = state.bus_for(&channel_id).send(broadcast);
            info!("{identity} edited message {message_id} in #{channel_id}");
            Json(json!({ "ok": true, "edited_at": edited_at })).into_response()
        }
        Err(e) => {
            error!("edit message: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

pub async fn delete_message(
    Extension(state): Extension<Arc<AppState>>,
    Path(message_id): Path<i64>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&headers, &state.jwt_secret) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    let channel_id: String = match db.query_row(
        "SELECT channel_id FROM messages WHERE id = ?1 AND beam_identity = ?2",
        rusqlite::params![message_id, identity],
        |row| row.get(0),
    ) {
        Ok(ch) => ch,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Message not found or not yours" })),
            )
                .into_response();
        }
    };

    match db.execute(
        "DELETE FROM messages WHERE id = ?1 AND beam_identity = ?2",
        rusqlite::params![message_id, identity],
    ) {
        Ok(_) => {
            let broadcast = serde_json::to_string(&json!({
                "type":       "message_deleted",
                "id":         message_id,
                "channel_id": channel_id,
            }))
            .unwrap();
            let _ = state.bus_for(&channel_id).send(broadcast);
            info!("{identity} deleted message {message_id} in #{channel_id}");
            (StatusCode::OK, Json(json!({ "deleted": true }))).into_response()
        }
        Err(e) => {
            error!("delete message: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response()
        }
    }
}

```

# src\ws.rs

```rs
use std::sync::Arc;
use axum::extract::Extension;
use crate::messages::{Attachment, WsBroadcast};
use super::*;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsIncoming {
    Auth {
        token: String,
    },
    Activate {
        server_id: String,
        token: String,
    },
    Join {
        token: String,
        channel_id: String,
    },
    Message {
        token: String,
        channel_id: String,
        content: String,
        #[serde(default)]
        attachment_ids: Vec<i64>,
    },
    Leave {
        channel_id: String,
    },
    EditMessage {
        token: String,
        message_id: i64,
        content: String,
    },
    DeleteMessage {
        token: String,
        message_id: i64,
    },
    Read,
    Ping,
}

async fn send_err(socket: &mut WebSocket, msg: &str) {
    let _ = socket
        .send(Message::Text(
            json!({ "type": "error", "message": msg }).to_string(),
        ))
        .await;
}

pub async fn ws_handler(ws: WebSocketUpgrade, Extension(state): Extension<Arc<AppState>>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

pub async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    debug!("ws: new connection established");
    let mut rx: Option<broadcast::Receiver<String>> = None;
    let mut server_rx: Option<broadcast::Receiver<String>> = None;
    let mut current_channel: Option<String> = None;
    let mut identity: Option<String> = None;

    loop {
        tokio::select! {
            Some(Ok(msg)) = socket.recv() => {
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Close(_) => break,
                    _ => continue,
                };

                let ws_incoming = match serde_json::from_str::<WsIncoming>(&text) {
                    Ok(ws_in) => ws_in,
                    Err(_) => {
                        warn!("malformed WS frame from {:?}", identity);
                        send_err(&mut socket, "Malformed message format").await;
                        break;
                    }
                };

                match ws_incoming {
                    WsIncoming::Ping => {
                        debug!("ws: ping from {}", identity.as_deref().unwrap_or("unauthenticated"));
                        let _ = socket.send(Message::Text(json!({ "type": "pong" }).to_string())).await;
                    }
                    WsIncoming::Auth { token } => {
                        match validate_jwt(&token, &state.jwt_secret) {
                            None => {
                                warn!("ws: auth failed (invalid/expired token)");
                                send_err(&mut socket, "Invalid or expired token").await;
                                break;
                            }
                            Some(id) => {
                                let was_unauth = identity.is_none();
                                identity = Some(id.clone());
                                if was_unauth {
                                    state.mark_online(&id);
                                    info!("ws: {id} authenticated and marked online");
                                } else {
                                    debug!("ws: {id} re-authenticated");
                                }
                            }
                        }
                    }
                    WsIncoming::Activate { server_id, token } => {
                        match validate_jwt(&token, &state.jwt_secret) {
                            None => {
                                send_err(&mut socket, "Invalid or expired token").await;
                                break;
                            }
                            Some(_id) => {
                                // Subscribe to server-wide broadcasts
                                server_rx = Some(state.server_bus.subscribe());
                                
                                let _ = socket
                                    .send(Message::Text(
                                        json!({ "type": "activated", "server_id": server_id }).to_string()
                                    ))
                                    .await;
                                // In standalone mode, activation is a no-op beyond acknowledging.
                            }
                        }
                    }

                    WsIncoming::Join { token, channel_id } => {
                        match validate_jwt(&token, &state.jwt_secret) {
                            None => { send_err(&mut socket, "Invalid or expired token").await; break; }
                            Some(id) => {
                                let was_unauth = identity.is_none();
                                identity = Some(id.clone());
                                if was_unauth {
                                    state.mark_online(&id);
                                }
                                let exists = {
                                    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
                                    db.query_row("SELECT 1 FROM channels WHERE id = ?1",
                                        rusqlite::params![channel_id], |_| Ok(true))
                                        .unwrap_or(false)
                                };
                                if !exists { send_err(&mut socket, "Channel not found").await; continue; }
                                current_channel = Some(channel_id.clone());
                                rx = Some(state.bus_for(&channel_id).subscribe());
                                info!("{} joined #{}", identity.as_deref().unwrap_or("?"), channel_id);
                            }
                        }
                    }

                    WsIncoming::Message { token, channel_id, content, attachment_ids } => {
                        let id = match validate_jwt(&token, &state.jwt_secret) {
                            Some(id) => id,
                            None => { send_err(&mut socket, "Token expired").await; break; }
                        };
                        identity = Some(id.clone());

                        let content = content.trim().to_string();
                        if content.is_empty() && attachment_ids.is_empty() { continue; }
                        let max_len = state.settings.read().await.max_message_length as usize;
                        if content.len() > max_len {
                            send_err(&mut socket, &format!("Message too long (max {max_len} chars)")).await;
                            continue;
                        }

                        let created_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;

                        // Insert message and link attachments in a transaction
                        let (msg_id, attachments) = {
                            let mut db = state.db.lock().unwrap_or_else(|e| e.into_inner());
                            let tx = db.transaction().unwrap();

                            // Insert the message
                            tx.execute(
                                "INSERT INTO messages (channel_id, beam_identity, content, created_at) VALUES (?1, ?2, ?3, ?4)",
                                rusqlite::params![channel_id, &id, content, created_at],
                            ).expect("Failed to insert message");

                            let msg_id = tx.last_insert_rowid();

                            // Link attachments if any provided
                            if !attachment_ids.is_empty() {
                                // Build placeholders for IN clause
                                let placeholders = attachment_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                                let sql = format!(
                                    "UPDATE attachments SET message_id = ?1 WHERE id IN ({}) AND message_id IS NULL",
                                    placeholders
                                );
                                let mut params: Vec<&dyn ToSql> = Vec::new();
                                params.push(&msg_id as &dyn ToSql);
                                for aid in &attachment_ids {
                                    params.push(aid as &dyn ToSql);
                                }
                                let rows_affected = tx.execute(&sql, params.as_slice()).unwrap_or(0);
                                if rows_affected != attachment_ids.len() {
                                    // Some attachments invalid, continue without attachments
                                    warn!("Failed to link attachments: expected {} rows, got {}, continuing without attachments", attachment_ids.len(), rows_affected);
                                    for aid in &attachment_ids {
                                        tx.execute("UPDATE attachments SET message_id = NULL WHERE id = ?1 AND message_id = ?2", rusqlite::params![aid, msg_id]).unwrap_or_default();
                                    }
                                }
                            }

                            tx.commit().ok();

                            // Fetch attachment metadata for broadcast (after commit)
                            let mut att_vec = Vec::new();
                            if !attachment_ids.is_empty() {
                                let placeholders = attachment_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                                let mut stmt = db.prepare(&format!("SELECT id, filename, mime_type, file_size FROM attachments WHERE id IN ({})", placeholders)).unwrap();
                                let rows = stmt
                                    .query_map(rusqlite::params_from_iter(attachment_ids.iter()), |row| {
                                        Ok(Attachment {
                                            id: row.get(0)?,
                                            filename: row.get(1)?,
                                            mime_type: row.get(2)?,
                                            file_size: row.get(3)?,
                                        })
                                    })
                                    .unwrap()
                                    .filter_map(|r| r.ok())
                                    .collect::<Vec<_>>();
                                att_vec = rows;
                            }

                            (msg_id, att_vec)
                        };

                        let att_count = attachments.len();
                        let broadcast = serde_json::to_string(&WsBroadcast {
                            kind: "message",
                            id: msg_id,
                            channel_id: channel_id.clone(),
                            beam_identity: id.clone(),
                            content: content.clone(),
                            created_at,
                            attachments,
                        }).unwrap();
                        info!(
                            "ws: message {msg_id} sent by {id} in #{channel_id} ({} chars{})"
                            , content.len()
                            , if att_count > 0 { format!(", {att_count} attachment(s)") } else { String::new() }
                        );
                        let _ = state.bus_for(&channel_id).send(broadcast);
                    }

                    WsIncoming::Leave { channel_id } => {
                        if current_channel.as_deref() == Some(&channel_id) {
                            rx = None; current_channel = None;
                            debug!("ws: {} left #{channel_id}", identity.as_deref().unwrap_or("?"));
                        }
                    }

                    // Edit a message — only the original sender may edit
                    WsIncoming::EditMessage { token, message_id, content } => {
                        let id = match validate_jwt(&token, &state.jwt_secret) {
                            Some(id) => id,
                            None => { send_err(&mut socket, "Token expired").await; break; }
                        };

                        let content = content.trim().to_string();
                        let max_len = state.settings.read().await.max_message_length as usize;
                        if content.is_empty() || content.len() > max_len {
                            send_err(&mut socket, "Invalid content").await;
                            continue;
                        }

                        let edited_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;

                        let (updated, channel_id) = {
                            let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
                            // Fetch the channel_id so we can broadcast the edit
                            let ch: Option<String> = db.query_row(
                                "SELECT channel_id FROM messages WHERE id = ?1 AND beam_identity = ?2",
                                rusqlite::params![message_id, id],
                                |row| row.get(0),
                            ).ok();
                            if let Some(ref ch) = ch {
                                let ok = db.execute(
                                    "UPDATE messages SET content = ?1, edited_at = ?2 WHERE id = ?3 AND beam_identity = ?4",
                                    rusqlite::params![content, edited_at, message_id, id],
                                ).is_ok();
                                (ok, ch.clone())
                            } else {
                                (false, String::new())
                            }
                        };

                        if !updated || channel_id.is_empty() {
                            warn!("ws: edit failed — message {message_id} not found or wrong owner");
                            send_err(&mut socket, "Message not found or not yours").await;
                            continue;
                        }

                        info!("ws: message {message_id} edited in #{channel_id}");
                        let broadcast = serde_json::to_string(&json!({
                            "type":         "message_edited",
                            "id":           message_id,
                            "channel_id":   channel_id.clone(),
                            "content":      content,
                            "edited_at":    edited_at,
                        })).unwrap();
                        let _ = state.bus_for(&channel_id).send(broadcast);
                    }

                    // Delete a message — only the original sender may delete
                    WsIncoming::DeleteMessage { token, message_id } => {
                        let id = match validate_jwt(&token, &state.jwt_secret) {
                            Some(id) => id,
                            None => { send_err(&mut socket, "Token expired").await; break; }
                        };

                        let channel_id: Option<String> = {
                            let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
                            let ch: Option<String> = db.query_row(
                                "SELECT channel_id FROM messages WHERE id = ?1 AND beam_identity = ?2",
                                rusqlite::params![message_id, id],
                                |row| row.get(0),
                            ).ok();
                            if ch.is_some() {
                                db.execute(
                                    "DELETE FROM messages WHERE id = ?1 AND beam_identity = ?2",
                                    rusqlite::params![message_id, id],
                                ).ok();
                            }
                            ch
                        };

                        match channel_id {
                            None => {
                                warn!("ws: delete failed — message {message_id} not found or wrong owner");
                                send_err(&mut socket, "Message not found or not yours").await;
                            }
                            Some(ch) => {
                                info!("ws: message {message_id} deleted from #{ch}");
                                let broadcast = serde_json::to_string(&json!({
                                    "type":       "message_deleted",
                                    "id":         message_id,
                                    "channel_id": ch.clone(),
                                })).unwrap();
                                let _ = state.bus_for(&ch).send(broadcast);
                            }
                        }
                    }

                    // Read receipt
                    WsIncoming::Read { .. } => {
                        debug!("read receipt received");
                        return;
                    }
                }
            }

            Some(broadcast) = async {
                match rx.as_mut() {
                    Some(r) => match r.recv().await {
                        Ok(m) => Some(m),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("client lagged, dropped {n} messages"); None
                        }
                        Err(_) => None,
                    },
                    None => std::future::pending::<Option<String>>().await,
                }
            } => {
                if socket.send(Message::Text(broadcast)).await.is_err() { break; }
            }
            Some(broadcast) = async {
                match server_rx.as_mut() {
                    Some(r) => match r.recv().await {
                        Ok(m) => Some(m),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("client lagged, dropped {n} server messages"); None
                        }
                        Err(_) => None,
                    },
                    None => std::future::pending::<Option<String>>().await,
                }
            } => {
                if socket.send(Message::Text(broadcast)).await.is_err() { break; }
            }

            else => break,
        }
    }

    if let Some(ref id) = identity {
        state.mark_offline(id).await;
    }
    info!(
        "{} disconnected",
        identity.as_deref().unwrap_or("unauthenticated")
    );
}

```

# zeeble.toml

```toml
port = 4000
jwt_secret = "ZS+m7Fv+v5RBgCEI0hFw6cgr2ORZ3TpDPPyqvMUi93I="
db_path = "zeeble.db"
server_name = "Zeeble Server"
owner_beam_identity = "test»wjbkk"
about = "A chill place to hang out."
max_message_length = 4000
max_upload_size = "8MB"
invites_anyone_can_create = true
default_invite_expiry_hours = 0
default_invite_max_uses = 0
allow_new_members = true

```

