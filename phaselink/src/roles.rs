use axum::{
    Json,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::EVERYONE_ROLE;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

use crate::{AppState, require_auth};

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn check_owner_or_admin(
    state: &Arc<AppState>,
    identity: &str,
) -> Result<bool, (StatusCode, Json<serde_json::Value>)> {
    let owner = state.settings.read().await.owner_beam_identity.clone();
    let is_owner = !owner.is_empty() && identity == owner;
    if is_owner {
        return Ok(true);
    }
    let db = state.db.lock().map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" })))
    })?;
    let is_admin = matches!(
        db.query_row(
            "SELECT role FROM users WHERE beam_identity = ?1",
            rusqlite::params![identity],
            |row| row.get::<_, String>(0),
        ),
        Ok(ref r) if r == "Admin"
    );
    Ok(is_admin)
}

// ── User-role assignment ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct RoleInfo {
    pub user_id: String,
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub struct SetRoleBody {
    pub role: Option<String>,
}

/// GET /roles — list all user-role assignments
pub async fn list_roles(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match check_owner_or_admin(&state, &identity).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only server owner or Admins can manage roles" }))).into_response(),
        Err(e) => return e.into_response(),
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };
    let mut stmt = match db.prepare(
        "SELECT beam_identity, role FROM users WHERE role IS NOT NULL ORDER BY beam_identity",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("prepare list roles: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response();
        }
    };
    let roles: Vec<RoleInfo> = stmt
        .query_map([], |row| Ok(RoleInfo { user_id: row.get(0)?, role: row.get(1)? }))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    Json(roles).into_response()
}

/// PUT /roles/:user_id — set role for a user
pub async fn set_role(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(user_id): Path<String>,
    Json(body): Json<SetRoleBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match check_owner_or_admin(&state, &identity).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only server owner or Admins can manage roles" }))).into_response(),
        Err(e) => return e.into_response(),
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };

    // Validate role against the custom_roles table (null = remove role)
    let role_value: Option<String> = match &body.role {
        None => None,
        Some(name) => {
            let exists: bool = db.query_row(
                "SELECT 1 FROM custom_roles WHERE name = ?1",
                rusqlite::params![name],
                |_| Ok(true),
            ).unwrap_or(false);
            if !exists {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": format!("Role '{}' does not exist", name) }))).into_response();
            }
            Some(name.clone())
        }
    };

    let user_exists: bool = db.query_row(
        "SELECT 1 FROM users WHERE beam_identity = ?1",
        rusqlite::params![&user_id],
        |_| Ok(true),
    ).unwrap_or(false);
    if !user_exists {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "User not found" }))).into_response();
    }

    match db.execute(
        "UPDATE users SET role = ?1 WHERE beam_identity = ?2",
        rusqlite::params![role_value, &user_id],
    ) {
        Ok(_) => {
            info!("{identity} set role for {user_id} to {:?}", role_value);
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            error!("set role: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response()
        }
    }
}

/// DELETE /roles/:user_id — remove role from a user
pub async fn delete_role(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    match check_owner_or_admin(&state, &identity).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only server owner or Admins can manage roles" }))).into_response(),
        Err(e) => return e.into_response(),
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };
    match db.execute(
        "UPDATE users SET role = NULL WHERE beam_identity = ?1",
        rusqlite::params![&user_id],
    ) {
        Ok(_) => {
            info!("{identity} removed role for {user_id}");
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            error!("delete role: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response()
        }
    }
}

// ── Custom role definitions ────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
pub struct CustomRole {
    pub name: String,
    pub color: String,
    pub position: i64,
    pub hoist: bool,
    pub permissions: serde_json::Value,
}

#[derive(Deserialize)]
pub struct CreateCustomRoleBody {
    pub name: String,
    pub color: String,
    pub hoist: Option<bool>,
    pub permissions: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct UpdateCustomRoleBody {
    pub color: Option<String>,
    pub name: Option<String>,
    pub hoist: Option<bool>,
    pub permissions: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct ReorderBody {
    pub order: Vec<String>,
}

/// GET /custom_roles — list all custom role definitions (any authed user)
pub async fn list_custom_roles(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers).await {
        return e.into_response();
    }
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };
    let mut stmt = match db.prepare(
        "SELECT name, color, position, hoist, permissions FROM custom_roles ORDER BY position ASC, name ASC",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("prepare list custom_roles: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response();
        }
    };
    let roles: Vec<CustomRole> = stmt
        .query_map([], |row| {
            let hoist_int: i64 = row.get(3)?;
            let perms_str: String = row.get::<_, Option<String>>(4)?.unwrap_or_else(|| "{}".to_string());
            Ok(CustomRole {
                name: row.get(0)?,
                color: row.get(1)?,
                position: row.get(2)?,
                hoist: hoist_int != 0,
                permissions: serde_json::from_str(&perms_str).unwrap_or(serde_json::json!({})),
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    Json(roles).into_response()
}

/// POST /custom_roles — create a new custom role (owner only)
pub async fn create_custom_role(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<CreateCustomRoleBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only the server owner can create roles" }))).into_response();
    }

    let name = body.name.trim().to_string();
    if name.is_empty() || name.len() > 32 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Role name must be 1–32 characters" }))).into_response();
    }
    if !body.color.starts_with('#') || body.color.len() != 7 {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Color must be a hex value like #rrggbb" }))).into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };

    // position = next after current max
    let next_pos: i64 = db.query_row(
        "SELECT COALESCE(MAX(position), -1) + 1 FROM custom_roles",
        [],
        |row| row.get(0),
    ).unwrap_or(0);

    let hoist = body.hoist.unwrap_or(false) as i64;
    let permissions = serde_json::to_string(&body.permissions.unwrap_or(serde_json::json!({}))).unwrap_or_else(|_| "{}".to_string());

    match db.execute(
        "INSERT INTO custom_roles (name, color, position, hoist, permissions) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![name, body.color, next_pos, hoist, permissions],
    ) {
        Ok(_) => {
            info!("{identity} created custom role '{name}'");
            Json(json!({ "ok": true, "name": name, "color": body.color, "position": next_pos })).into_response()
        }
        Err(e) if e.to_string().contains("UNIQUE") => {
            (StatusCode::CONFLICT, Json(json!({ "error": "A role with that name already exists" }))).into_response()
        }
        Err(e) => {
            error!("create custom role: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response()
        }
    }
}

/// PUT /custom_roles/:name — update a custom role's name/color (owner only)
pub async fn update_custom_role(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(role_name): Path<String>,
    Json(body): Json<UpdateCustomRoleBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only the server owner can edit roles" }))).into_response();
    }

    if role_name == EVERYONE_ROLE && body.name.is_some() {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "@everyone cannot be renamed" }))).into_response();
    }
    if let Some(ref color) = body.color {
        if !color.starts_with('#') || color.len() != 7 {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Color must be a hex value like #rrggbb" }))).into_response();
        }
    }
    if let Some(ref new_name) = body.name {
        let n = new_name.trim();
        if n.is_empty() || n.len() > 32 {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": "Role name must be 1–32 characters" }))).into_response();
        }
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };

    let exists: bool = db.query_row(
        "SELECT 1 FROM custom_roles WHERE name = ?1",
        rusqlite::params![&role_name],
        |_| Ok(true),
    ).unwrap_or(false);
    if !exists {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Role not found" }))).into_response();
    }

    // Apply updates
    if let Some(ref color) = body.color {
        db.execute("UPDATE custom_roles SET color = ?1 WHERE name = ?2", rusqlite::params![color, &role_name]).ok();
    }
    if let Some(hoist) = body.hoist {
        db.execute("UPDATE custom_roles SET hoist = ?1 WHERE name = ?2", rusqlite::params![hoist as i64, &role_name]).ok();
    }
    if let Some(ref perms) = body.permissions {
        let s = serde_json::to_string(perms).unwrap_or_else(|_| "{}".to_string());
        db.execute("UPDATE custom_roles SET permissions = ?1 WHERE name = ?2", rusqlite::params![s, &role_name]).ok();
    }
    if let Some(ref new_name) = body.name {
        let new_name = new_name.trim().to_string();
        if new_name != role_name {
            // Rename: update the role definition and all user assignments
            match db.execute("UPDATE custom_roles SET name = ?1 WHERE name = ?2", rusqlite::params![new_name, &role_name]) {
                Ok(_) => {
                    db.execute("UPDATE users SET role = ?1 WHERE role = ?2", rusqlite::params![new_name, &role_name]).ok();
                }
                Err(e) if e.to_string().contains("UNIQUE") => {
                    return (StatusCode::CONFLICT, Json(json!({ "error": "A role with that name already exists" }))).into_response();
                }
                Err(e) => {
                    error!("rename custom role: {e}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response();
                }
            }
        }
    }

    info!("{identity} updated custom role '{role_name}'");
    Json(json!({ "ok": true })).into_response()
}

/// DELETE /custom_roles/:name — delete a custom role (owner only), un-assigning it from all users
pub async fn delete_custom_role(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(role_name): Path<String>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only the server owner can delete roles" }))).into_response();
    }

    if role_name == EVERYONE_ROLE {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "@everyone cannot be deleted" }))).into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };

    // Un-assign the role from all users first
    db.execute("UPDATE users SET role = NULL WHERE role = ?1", rusqlite::params![&role_name]).ok();

    match db.execute("DELETE FROM custom_roles WHERE name = ?1", rusqlite::params![&role_name]) {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({ "error": "Role not found" }))).into_response(),
        Ok(_) => {
            info!("{identity} deleted custom role '{role_name}'");
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => {
            error!("delete custom role: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response()
        }
    }
}

/// PATCH /custom_roles — reorder roles by providing the desired name order (owner only)
pub async fn reorder_custom_roles(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<ReorderBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Only the server owner can reorder roles" }))).into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };

    for (i, name) in body.order.iter().enumerate() {
        db.execute(
            "UPDATE custom_roles SET position = ?1 WHERE name = ?2",
            rusqlite::params![i as i64, name],
        ).ok();
    }

    info!("{identity} reordered custom roles");
    Json(json!({ "ok": true })).into_response()
}
