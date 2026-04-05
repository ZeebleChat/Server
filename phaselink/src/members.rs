use super::*;
use axum::extract::{Extension, Path};
use axum::Json;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateStatusBody {
    pub status: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct FrontendMember {
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<i64>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_owner: bool,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct MemberCategory {
    pub category: String,
    pub users: Vec<FrontendMember>,
}

/// GET /members  — list all unique users who have ever posted, sorted by message count
pub async fn get_members(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(e) = require_auth(&state, &headers).await {
        return e.into_response();
    }
    let owner = state.settings.read().await.owner_beam_identity.clone();
    let (rows, hoisted_roles) = {
        let db = match state.db.lock() {
            Ok(db) => db,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
        };
        let mut stmt = match db.prepare(
            "SELECT src.beam_identity, COUNT(m.id) as message_count, COALESCE(MAX(u.status), 'offline') as status, MAX(u.avatar_attachment_id) as avatar_id, MAX(u.role) as role
             FROM (
               SELECT beam_identity FROM users WHERE is_deleted = 0
               UNION
               SELECT DISTINCT beam_identity FROM messages
               WHERE beam_identity NOT IN (SELECT beam_identity FROM users WHERE is_deleted = 1)
             ) src
             LEFT JOIN users u ON u.beam_identity = src.beam_identity
             LEFT JOIN messages m ON m.beam_identity = src.beam_identity
             GROUP BY src.beam_identity
             ORDER BY message_count DESC",
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("prepare members: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response();
            }
        };
        let rows: Vec<(String, i64, String, Option<i64>, Option<String>)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let hoisted: Vec<String> = db
            .prepare("SELECT name FROM custom_roles WHERE hoist = 1 ORDER BY position ASC")
            .map(|mut s| s.query_map([], |row| row.get(0)).unwrap().filter_map(|r| r.ok()).collect())
            .unwrap_or_default();

        (rows, hoisted)
    };

    let mut hoisted_groups: Vec<(String, Vec<FrontendMember>)> =
        hoisted_roles.iter().map(|n| (n.clone(), Vec::new())).collect();
    let hoisted_set: std::collections::HashSet<&str> = hoisted_roles.iter().map(|s| s.as_str()).collect();
    let mut online = Vec::new();
    let mut offline = Vec::new();

    for (beam_identity, _message_count, status, avatar_id, role) in rows {
        let is_owner = !owner.is_empty() && beam_identity == owner;
        let member = FrontendMember {
            name: beam_identity,
            status: status.clone(),
            role: role.clone(),
            avatar: avatar_id,
            is_owner,
        };
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

    debug!("get_members: {} online, {} offline", online.len(), offline.len());
    let mut categories = Vec::new();
    for (role_name, users) in hoisted_groups {
        if !users.is_empty() {
            categories.push(MemberCategory { category: role_name, users });
        }
    }
    if !online.is_empty() {
        categories.push(MemberCategory { category: "Online".to_string(), users: online });
    }
    if !offline.is_empty() {
        categories.push(MemberCategory { category: "Offline".to_string(), users: offline });
    }

    Json(categories).into_response()
}

/// DELETE /v1/members/:identity — leave the server (soft-delete the user record)
pub async fn delete_member(
    Path(identity): Path<String>,
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let requester = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    if requester != identity {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Cannot remove another member" }))).into_response();
    }

    let owner = state.settings.read().await.owner_beam_identity.clone();
    if identity == owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Owner cannot leave; delete the server instead" }))).into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB unavailable" }))).into_response(),
    };

    match db.execute(
        "UPDATE users SET is_deleted = 1, status = 'offline' WHERE beam_identity = ?1",
        rusqlite::params![identity],
    ) {
        Ok(_) => {
            info!("{identity} left the server");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            error!("delete_member: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "DB error" }))).into_response()
        }
    }
}

pub async fn update_status(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<UpdateStatusBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
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
            // Broadcast member_update to connected clients
            if let Ok(guard) = state.settings.try_read() {
                let server_name = guard.server_name.clone();
                let payload = format!(r#"{{"type":"member_update","beam_identity":"{}","status":"{}","server_id":"{}"}}"#, identity, body.status, server_name);
                let _ = state.server_bus.send(payload);
            }
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
