use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use serde::Deserialize;
use serde_json::json;

use std::sync::Arc;
use tokio::fs;
use tracing::error;

use crate::config::parse_size;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct PatchSettingsRequest {
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    public_url: Option<String>,
    #[serde(default)]
    owner_beam_identity: Option<String>,
    #[serde(default)]
    about: Option<String>,
    #[serde(default)]
    max_message_length: Option<u64>,
    #[serde(default)]
    max_upload_size: Option<String>,
    #[serde(default)]
    invites_anyone_can_create: Option<bool>,
    #[serde(default)]
    default_invite_expiry_hours: Option<u64>,
    #[serde(default)]
    default_invite_max_uses: Option<u64>,
    #[serde(default)]
    allow_new_members: Option<bool>,
    #[serde(default)]
    logo_attachment_id: Option<i64>,
}

pub async fn get_settings(
    headers: HeaderMap,
    Extension(state): Extension<Arc<crate::AppState>>,
) -> impl IntoResponse {
    let requester_identity = match crate::require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let settings = state.settings.read().await;
    if requester_identity != settings.owner_beam_identity {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only the server owner can view settings" })),
        )
            .into_response();
    }

    // Format max_upload_bytes back to a human-readable string
    let max_upload_size = {
        let b = settings.max_upload_bytes;
        if b % (1024 * 1024 * 1024) == 0 { format!("{}GB", b / (1024 * 1024 * 1024)) }
        else if b % (1024 * 1024) == 0    { format!("{}MB", b / (1024 * 1024)) }
        else if b % 1024 == 0             { format!("{}KB", b / 1024) }
        else                              { format!("{}B", b) }
    };

    Json(json!({
        "server_name":                  settings.server_name,
        "public_url":                   settings.public_url,
        "owner_beam_identity":          settings.owner_beam_identity,
        "about":                        settings.about,
        "max_message_length":           settings.max_message_length,
        "max_upload_size":              max_upload_size,
        "invites_anyone_can_create":    settings.invites_anyone_can_create,
        "default_invite_expiry_hours":  settings.default_invite_expiry_hours,
        "default_invite_max_uses":      settings.default_invite_max_uses,
        "allow_new_members":            settings.allow_new_members,
        "logo_attachment_id":           settings.logo_attachment_id,
    }))
    .into_response()
}

pub async fn patch_settings(
    headers: HeaderMap,
    Extension(state): Extension<Arc<crate::AppState>>,
    Json(payload): Json<PatchSettingsRequest>,
) -> impl IntoResponse {
    // Authentication
    let requester_identity = match crate::require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Owner check
    let current_settings = state.settings.read().await;
    if requester_identity != current_settings.owner_beam_identity {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only server owner can modify settings" })),
        )
            .into_response();
    }

    // Drop read lock, will acquire write lock later
    drop(current_settings);

    // Load current config file from disk
    const CONFIG_FILE: &str = "phaselink.yaml";
    let toml_str = match fs::read_to_string(CONFIG_FILE).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read config file: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Cannot read config file" })),
            )
                .into_response();
        }
    };

    let mut config_file: crate::ConfigFile = match serde_yaml::from_str(&toml_str) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to parse config file: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Invalid config file" })),
            )
                .into_response();
        }
    };

    // Validate fields and update config_file

    // server_name: if Some, must be non-empty
    if let Some(ref name) = payload.server_name {
        if name.trim().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "server_name cannot be empty" })),
            )
                .into_response();
        }
        config_file.server_name = Some(name.clone());
    }

    // public_url: if Some, must be non-empty (no further validation)
    if let Some(ref url) = payload.public_url {
        if url.trim().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "public_url cannot be empty" })),
            )
                .into_response();
        }
        config_file.public_url = Some(url.clone());
    }

    // owner_beam_identity is stored in the DB, not the config file — skip here

    // about: if Some, can be any string (including empty?), we'll accept empty.
    if let Some(ref about) = payload.about {
        config_file.about = Some(about.clone());
    }

    // max_message_length: if Some, must be > 0
    if let Some(len) = payload.max_message_length {
        if len == 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "max_message_length must be > 0" })),
            )
                .into_response();
        }
        config_file.max_message_length = Some(len);
    }

    // max_upload_size: if Some, must be parseable and > 0
    if let Some(ref size_str) = payload.max_upload_size {
        if let Some(size) = parse_size(size_str) {
            if size == 0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "max_upload_size must be > 0" })),
                )
                    .into_response();
            }
            config_file.max_upload_size = Some(size_str.clone());
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid max_upload_size format. Use e.g., \"8MB\", \"500KB\"" })),
            )
            .into_response();
        }
    }

    // invites_anyone_can_create
    if let Some(val) = payload.invites_anyone_can_create {
        config_file.invites_anyone_can_create = Some(val);
    }

    // default_invite_expiry_hours
    if let Some(val) = payload.default_invite_expiry_hours {
        config_file.default_invite_expiry_hours = Some(val);
    }

    // default_invite_max_uses
    if let Some(val) = payload.default_invite_max_uses {
        config_file.default_invite_max_uses = Some(val);
    }

    // allow_new_members
    if let Some(val) = payload.allow_new_members {
        config_file.allow_new_members = Some(val);
    }

    // logo_attachment_id: if Some, must be >0 and exist in attachments table
    if let Some(att_id) = payload.logo_attachment_id {
        if att_id <= 0 {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "logo_attachment_id must be positive" })),
            )
                .into_response();
        }
        // Check DB
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
        let exists = match db.prepare("SELECT 1 FROM attachments WHERE id = ?1") {
            Ok(mut stmt) => match stmt.query_row(rusqlite::params![att_id], |_| Ok(true)) {
                Ok(_) => true,
                Err(rusqlite::Error::QueryReturnedNoRows) => false,
                Err(e) => {
                    error!("query attachment existence: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Database error" })),
                    )
                        .into_response();
                }
            },
            Err(e) => {
                error!("prepare attachment check: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Database error" })),
                )
                    .into_response();
            }
        };
        if !exists {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "logo_attachment_id does not refer to an existing attachment" })),
            )
            .into_response();
        }
        config_file.logo_attachment_id = Some(att_id);
    }

    // Serialize updated config_file to YAML
    let toml_content = match serde_yaml::to_string(&config_file) {
        Ok(content) => content,
        Err(e) => {
            error!("Failed to serialize config: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to serialize config" })),
            )
                .into_response();
        }
    };

    // Write directly to the config file.
    // Note: atomic rename (write-tmp then rename) fails with EBUSY when the
    // config file is a Docker bind-mount because the kernel pins the inode.
    // Direct overwrite is safe here since config writes are infrequent.
    if let Err(e) = fs::write(CONFIG_FILE, toml_content).await {
        error!("Failed to write config file: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to write config file" })),
        )
            .into_response();
    }

    // Update in-memory settings immediately
    let mut settings_guard = state.settings.write().await;

    // Apply changes directly
    if let Some(name) = payload.server_name {
        settings_guard.server_name = name;
    }
    if let Some(url) = payload.public_url {
        settings_guard.public_url = url;
    }
    if let Some(id) = payload.owner_beam_identity {
        // Persist to DB (source of truth for owner identity)
        let _ = state.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO server_meta (key, value) VALUES ('owner_beam_identity', ?1)",
            rusqlite::params![&id],
        );
        settings_guard.owner_beam_identity = id;
    }
    if let Some(about) = payload.about {
        settings_guard.about = Some(about);
    }
    if let Some(len) = payload.max_message_length {
        settings_guard.max_message_length = len;
    }
    if let Some(size_str) = payload.max_upload_size {
        if let Some(bytes) = parse_size(&size_str) {
            settings_guard.max_upload_bytes = bytes;
        }
    }
    if let Some(flag) = payload.invites_anyone_can_create {
        settings_guard.invites_anyone_can_create = flag;
    }
    if let Some(hours) = payload.default_invite_expiry_hours {
        settings_guard.default_invite_expiry_hours = hours;
    }
    if let Some(uses) = payload.default_invite_max_uses {
        settings_guard.default_invite_max_uses = uses;
    }
    if let Some(flag) = payload.allow_new_members {
        settings_guard.allow_new_members = flag;
    }
    if let Some(id) = payload.logo_attachment_id {
        settings_guard.logo_attachment_id = Some(id);
    }

    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}
