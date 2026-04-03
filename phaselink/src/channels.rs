use axum::extract::Extension;
use std::sync::Arc;
// ── REST — channels ───────────────────────────────────────────────────────────

use super::*;

#[derive(Serialize, utoipa::ToSchema)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub topic: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub category_id: Option<i64>,
    pub position: i64,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateChannel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub topic: String,
    #[serde(default = "default_channel_type")]
    #[serde(rename = "type")]
    pub channel_type: String,
    pub category_id: Option<i64>,
    #[serde(default)]
    pub position: i64,
}

fn default_channel_type() -> String {
    "text".to_string()
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct RenameChannel {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub channel_type: Option<String>,
    #[serde(default)]
    pub category_id: Option<i64>,
    #[serde(default)]
    pub position: Option<i64>,
}

pub async fn list_channels(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    // Fetch all channels first, then drop the DB lock before calling resolve_channel_access
    let all_channels: Vec<Channel> = {
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
        let mut stmt = match db.prepare("SELECT id, name, topic, type, category_id, position FROM channels ORDER BY position ASC, name ASC") {
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
        match stmt.query_map([], |row| {
            Ok(Channel {
                id: row.get(0)?,
                name: row.get(1)?,
                topic: row.get(2)?,
                channel_type: row.get(3)?,
                category_id: row.get(4)?,
                position: row.get(5)?,
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
        }
    }; // DB lock dropped here
    // Filter channels based on per-role permissions
    let mut visible = Vec::with_capacity(all_channels.len());
    for ch in all_channels {
        let perms = crate::permissions::resolve_channel_access(&state, &identity, &ch.id).await;
        if perms.get("view_channel").copied().unwrap_or(false) {
            visible.push(ch);
        }
    }
    debug!("list_channels: returning {}/{} channels for {identity}", visible.len(), visible.len());
    Json(visible).into_response()
}

pub async fn create_channel(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<CreateChannel>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
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
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "DB unavailable" })),
                )
                    .into_response();
            }
        };
        db.execute(
            "INSERT INTO channels (id, name, topic, type, category_id, position) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                id,
                body.name.trim(),
                body.topic.trim(),
                body.channel_type,
                body.category_id,
                body.position
            ],
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
                    "type": body.channel_type,
                    "category_id": body.category_id,
                    "position": body.position,
                },
                "server_id": server_id,
            }))
            .unwrap();
            let _ = state.server_bus.send(broadcast);
            Json(json!({ 
                "id": id, 
                "name": body.name.trim(), 
                "topic": body.topic.trim(),
                "type": body.channel_type,
                "category_id": body.category_id,
                "position": body.position,
            }))
                .into_response()
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
    let identity = match require_auth(&state, &headers).await {
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
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "DB unavailable" })),
                )
                    .into_response();
            }
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
            }))
            .unwrap();
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
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only server owner can rename channels" })),
        )
            .into_response();
    }
    if channel_id == "general" {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Cannot rename the general channel" })),
        )
            .into_response();
    }
    if let Some(name) = &body.name {
        if name.trim().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Channel name cannot be empty" })),
            )
                .into_response();
        }
    }
    if body.name.is_none() && body.topic.is_none() && body.channel_type.is_none() && body.category_id.is_none() && body.position.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No name, topic, type, category, or position provided" })),
        )
            .into_response();
    }

    let update_result = {
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
        if let Some(channel_type) = &body.channel_type {
            set_clauses.push(format!("type = ?{}", idx));
            params.push(Box::new(channel_type.to_string()));
            idx += 1;
        }
        if let Some(category_id) = body.category_id {
            set_clauses.push(format!("category_id = ?{}", idx));
            params.push(Box::new(category_id));
            idx += 1;
        }
        if let Some(position) = body.position {
            set_clauses.push(format!("position = ?{}", idx));
            params.push(Box::new(position));
            idx += 1;
        }

        let sql = format!(
            "UPDATE channels SET {} WHERE id = ?{}",
            set_clauses.join(", "),
            idx
        );
        params.push(Box::new(channel_id.clone()));
        let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let result = db.execute(&sql, param_refs.as_slice());
        drop(db);

        // *** FIX: was missing `let update_result =` and had a stray `;` ***
        match result {
            Ok(0) => Err("Channel not found"),
            Ok(_) => {
                let db = state.db.lock().unwrap();
                let mut stmt = db
                    .prepare("SELECT id, name, topic, type, category_id, position FROM channels WHERE id = ?1")
                    .unwrap();
                let mut rows = stmt.query(rusqlite::params![channel_id]).unwrap();
                match rows.next() {
                    Ok(Some(row)) => {
                        let id: String = row.get(0).unwrap();
                        let name: String = row.get(1).unwrap();
                        let topic: String = row.get(2).unwrap();
                        let channel_type: String = row.get(3).unwrap();
                        let category_id: Option<i64> = row.get(4).unwrap();
                        let position: i64 = row.get(5).unwrap();
                        Ok((id, name, topic, channel_type, category_id, position))
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
        Ok((id, name, topic, channel_type, category_id, position)) => {
            info!("channel renamed: #{id} by {identity} → name={name:?} topic={topic:?} type={channel_type:?}");
            let server_id = state.settings.read().await.server_name.clone();
            let broadcast = serde_json::to_string(&json!({
                "type": "channel_renamed",
                "channel": {
                    "id": id.clone(),
                    "name": name.clone(),
                    "topic": topic.clone(),
                    "type": channel_type.clone(),
                    "category_id": category_id,
                    "position": position,
                },
                "server_id": server_id,
            }))
            .unwrap();
            let _ = state.server_bus.send(broadcast);
            (
                StatusCode::OK,
                Json(json!({ "id": id, "name": name, "topic": topic, "type": channel_type, "category_id": category_id, "position": position })),
            )
                .into_response()
        }
        Err(e) => match e {
            "Channel not found" => {
                (StatusCode::NOT_FOUND, Json(json!({ "error": e }))).into_response()
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response(),
        },
    }
}
