use axum::{
    Json,
    extract::Extension,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use serde::Deserialize;
use serde_json::json;

use std::sync::Arc;
use tracing::warn;

use crate::config::{parse_size, settings_to_config_file};

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
    #[serde(default)]
    banner_attachment_id: Option<i64>,
    // ── Membership requirements ───────────────────────────────────────────────
    #[serde(default)]
    require_email_verified: Option<bool>,
    #[serde(default)]
    require_phone_verified: Option<bool>,
    #[serde(default)]
    require_age_18_plus: Option<bool>,
    /// Valid values: "email", "id", "phone".  Empty = any method accepted.
    #[serde(default)]
    age_proof_methods: Option<Vec<String>>,
    // ── Access control ────────────────────────────────────────────────────────
    #[serde(default)]
    allow_bots: Option<bool>,
    #[serde(default)]
    min_account_age_days: Option<u64>,
    /// Replaces the entire whitelist; null/absent = no change.
    #[serde(default)]
    identity_whitelist: Option<Vec<String>>,
    /// Replaces the entire blacklist; null/absent = no change.
    #[serde(default)]
    identity_blacklist: Option<Vec<String>>,
    /// Replaces the entire domain list; null/absent = no change.
    #[serde(default)]
    allowed_email_domains: Option<Vec<String>>,
    #[serde(default)]
    max_members: Option<u64>,
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
        "banner_attachment_id":         settings.banner_attachment_id,
        "require_email_verified":       settings.require_email_verified,
        "require_phone_verified":       settings.require_phone_verified,
        "require_age_18_plus":          settings.require_age_18_plus,
        "age_proof_methods":            settings.age_proof_methods,
        "allow_bots":                   settings.allow_bots,
        "min_account_age_days":         settings.min_account_age_days,
        "identity_whitelist":           settings.identity_whitelist,
        "identity_blacklist":           settings.identity_blacklist,
        "allowed_email_domains":        settings.allowed_email_domains,
        "max_members":                  settings.max_members,
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

    // Drop read lock, will acquire write lock below
    drop(current_settings);

    // Validate fields before acquiring the write lock

    if let Some(ref name) = payload.server_name {
        if name.trim().is_empty() {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "server_name cannot be empty" }))).into_response();
        }
    }

    if let Some(ref url) = payload.public_url {
        if url.trim().is_empty() {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "public_url cannot be empty" }))).into_response();
        }
    }

    if let Some(len) = payload.max_message_length {
        if len == 0 {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "max_message_length must be > 0" }))).into_response();
        }
    }

    if let Some(ref size_str) = payload.max_upload_size {
        match parse_size(size_str) {
            Some(0) | None => {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Invalid max_upload_size. Use e.g. \"8MB\", \"500KB\"" }))).into_response();
            }
            _ => {}
        }
    }

    if let Some(att_id) = payload.logo_attachment_id {
        if att_id <= 0 {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "logo_attachment_id must be positive" }))).into_response();
        }
        let exists = {
            let db = match state.db.get() {
                Ok(db) => db,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
            };
            match db.prepare("SELECT 1 FROM attachments WHERE id = ?1") {
                Ok(mut stmt) => match stmt.query_row(rusqlite::params![att_id], |_| Ok(true)) {
                    Ok(_) => true,
                    Err(rusqlite::Error::QueryReturnedNoRows) => false,
                    Err(e) => {
                        warn!("query attachment existence: {e}");
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response();
                    }
                },
                Err(e) => {
                    warn!("prepare attachment check: {e}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response();
                }
            }
        };
        if !exists {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "logo_attachment_id does not refer to an existing attachment" }))).into_response();
        }
    }

    if let Some(att_id) = payload.banner_attachment_id {
        if att_id <= 0 {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "banner_attachment_id must be positive" }))).into_response();
        }
        let exists = {
            let db = match state.db.get() {
                Ok(db) => db,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
            };
            match db.prepare("SELECT 1 FROM attachments WHERE id = ?1") {
                Ok(mut stmt) => match stmt.query_row(rusqlite::params![att_id], |_| Ok(true)) {
                    Ok(_) => true,
                    Err(rusqlite::Error::QueryReturnedNoRows) => false,
                    Err(e) => {
                        warn!("query attachment existence: {e}");
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response();
                    }
                },
                Err(e) => {
                    warn!("prepare attachment check: {e}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Database error" }))).into_response();
                }
            }
        };
        if !exists {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "banner_attachment_id does not refer to an existing attachment" }))).into_response();
        }
    }

    if let Some(methods) = &payload.age_proof_methods {
        let valid = ["email", "id", "phone", "gmail"];
        for m in methods {
            if !valid.contains(&m.as_str()) {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Invalid age_proof_method '{m}'. Valid: email, id, phone, gmail") }))).into_response();
            }
        }
    }

    // NOTE: settings changed here are in-memory only — they reset on restart.
    // To make them permanent, set the corresponding env vars in your .env file.

    // Apply changes to in-memory settings
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
        let _ = state.db.get().expect("db pool").execute(
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
    if let Some(id) = payload.banner_attachment_id {
        let _ = state.db.get().expect("db pool").execute(
            "INSERT OR REPLACE INTO server_meta (key, value) VALUES ('banner_attachment_id', ?1)",
            rusqlite::params![id.to_string()],
        );
        settings_guard.banner_attachment_id = Some(id);
    }
    if let Some(val) = payload.require_email_verified {
        settings_guard.require_email_verified = val;
    }
    if let Some(val) = payload.require_phone_verified {
        settings_guard.require_phone_verified = val;
    }
    if let Some(val) = payload.require_age_18_plus {
        settings_guard.require_age_18_plus = val;
    }
    if let Some(methods) = payload.age_proof_methods {
        settings_guard.age_proof_methods = methods;
    }
    if let Some(val) = payload.allow_bots {
        settings_guard.allow_bots = val;
    }
    if let Some(days) = payload.min_account_age_days {
        settings_guard.min_account_age_days = days;
    }
    if let Some(list) = payload.identity_whitelist {
        settings_guard.identity_whitelist = list;
    }
    if let Some(list) = payload.identity_blacklist {
        settings_guard.identity_blacklist = list;
    }
    if let Some(list) = payload.allowed_email_domains {
        settings_guard.allowed_email_domains = list;
    }
    if let Some(val) = payload.max_members {
        settings_guard.max_members = val;
    }

    // Persist the updated settings to phaselink.yaml so they survive a restart.
    if let Some(ref path) = state.config_path {
        let config_file = settings_to_config_file(&settings_guard);
        drop(settings_guard); // release write lock before file I/O
        match serde_yml::to_string(&config_file) {
            Ok(yaml) => {
                if let Err(e) = std::fs::write(path, &yaml) {
                    warn!("failed to write phaselink.yaml: {e}");
                }
            }
            Err(e) => warn!("failed to serialize settings: {e}"),
        }
    }

    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}
