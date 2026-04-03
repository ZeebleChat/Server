use super::*;
use axum::extract::Extension;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, utoipa::ToSchema)]
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

#[derive(Serialize, Deserialize, Clone, utoipa::ToSchema)]
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

#[derive(Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MessagesQuery {
    #[param(default = "50")]
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub before: Option<i64>,
    #[serde(default)]
    pub before_id: Option<i64>,
}

fn default_limit() -> i64 {
    50
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateMessageBody {
    pub content: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct EditMessageBody {
    pub content: String,
}

/// Phase 4.1: Helper to build ChatMessage from query row data
fn build_message_from_row(
    msg_id: i64,
    channel_id: String,
    beam_identity: String,
    content: String,
    created_at: i64,
    edited_at: Option<i64>,
) -> ChatMessage {
    ChatMessage {
        id: msg_id,
        channel_id,
        beam_identity,
        content,
        created_at,
        edited_at,
        attachments: Vec::new(),
    }
}

/// Phase 4.1: Extracted function for fetching messages with attachments
/// Handles both paginated (before_id) and non-paginated cases
fn fetch_messages_with_attachments(
    db: &rusqlite::Connection,
    channel_id: &str,
    before_id: Option<i64>,
    limit: i64,
) -> rusqlite::Result<Vec<ChatMessage>> {
    let sql = if before_id.is_some() {
        "SELECT m.id, m.channel_id, m.beam_identity, m.content, m.created_at, m.edited_at, a.id, a.filename, a.mime_type, a.file_size
         FROM messages m
         LEFT JOIN attachments a ON m.id = a.message_id
         WHERE m.channel_id = ?1 AND m.id < ?2
         ORDER BY m.created_at DESC, m.id DESC LIMIT ?3"
    } else {
        "SELECT m.id, m.channel_id, m.beam_identity, m.content, m.created_at, m.edited_at, a.id, a.filename, a.mime_type, a.file_size
         FROM messages m
         LEFT JOIN attachments a ON m.id = a.message_id
         WHERE m.channel_id = ?1
         ORDER BY m.created_at DESC, m.id DESC LIMIT ?2"
    };

    let mut stmt = db.prepare(sql)?;
    let mut current_message_id: Option<i64> = None;
    let mut current_attachments: Vec<Attachment> = Vec::new();
    let mut current_message: Option<ChatMessage> = None;

    // Process rows - collecting attachments per message
    let mut rows = Vec::new();
    let params: Vec<Box<dyn rusqlite::ToSql>> = match before_id {
        Some(before) => vec![Box::new(channel_id), Box::new(before), Box::new(limit)],
        None => vec![Box::new(channel_id), Box::new(limit)],
    };
    let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let mut rows_iter = stmt.query(param_refs.as_slice())?;
    while let Some(row) = rows_iter.next()? {
        let msg_id: i64 = row.get(0)?;
        let row_channel_id: String = row.get(1)?;
        let beam_identity: String = row.get(2)?;
        let content: String = row.get(3)?;
        let created_at: i64 = row.get(4)?;
        let edited_at: Option<i64> = row.get(5)?;
        let att_id: Option<i64> = row.get(6)?;
        let att_filename: Option<String> = row.get(7)?;
        let att_mime_type: Option<String> = row.get(8)?;
        let att_file_size: Option<i64> = row.get(9)?;

        // Check if we've moved to a new message
        if let Some(prev_id) = current_message_id {
            if prev_id != msg_id {
                // Push the previous message with its attachments
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

        // Start tracking the current message
        current_message_id = Some(msg_id);
        current_message = Some(build_message_from_row(
            msg_id,
            row_channel_id,
            beam_identity,
            content,
            created_at,
            edited_at,
        ));

        // Add attachment if present
        if let (Some(id), Some(filename), Some(mime_type), Some(file_size)) =
            (att_id, att_filename, att_mime_type, att_file_size)
        {
            current_attachments.push(Attachment {
                id,
                filename,
                mime_type,
                file_size,
            });
        }
    }

    // Don't forget the last message
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

    Ok(rows)
}

pub async fn get_messages(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
    Query(q): Query<MessagesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let perms = crate::permissions::resolve_channel_access(&state, &identity, &channel_id).await;
    if !perms.get("view_channel").copied().unwrap_or(false) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "You do not have permission to view this channel" })),
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
    let before_id = q.before_id.or(q.before);
    let rows: Vec<ChatMessage> = match fetch_messages_with_attachments(&db, &channel_id, before_id, limit) {
        Ok(rows) => rows,
        Err(e) => {
            error!("fetch_messages: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
            .into_response();
        }
    };
    let mut rows = rows;
    rows.reverse();
    debug!(
        "get_messages: #{channel_id} returned {} messages",
        rows.len()
    );
    Json(rows).into_response()
}

pub async fn create_message(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreateMessageBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
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

    let perms = crate::permissions::resolve_channel_access(&state, &identity, &channel_id).await;
    if !perms.get("view_channel").copied().unwrap_or(false) || !perms.get("send_messages").copied().unwrap_or(false) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "You do not have permission to send messages in this channel" })),
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
                "type": "message",
                "id": message_id,
                "channel_id": channel_id,
                "beam_identity": identity,
                "content": content,
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
    let identity = match require_auth(&state, &headers).await {
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
                "type": "message_edited",
                "id": message_id,
                "channel_id": channel_id,
                "content": content,
                "edited_at": edited_at,
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
    let identity = match require_auth(&state, &headers).await {
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
                "type": "message_deleted",
                "id": message_id,
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
