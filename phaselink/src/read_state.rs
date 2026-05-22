use super::*;
use axum::extract::{Extension, Path};
use std::collections::HashMap;
use std::sync::Arc;

pub async fn mark_channel_read(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let db = state.db.get().expect("db pool");
    db.execute(
        "INSERT INTO channel_reads (beam_identity, channel_id, last_read_at)
         VALUES (?1, ?2, unixepoch())
         ON CONFLICT(beam_identity, channel_id)
         DO UPDATE SET last_read_at = excluded.last_read_at",
        rusqlite::params![identity, channel_id],
    )
    .ok();
    // Clear any pending mention count when the channel is opened.
    db.execute(
        "DELETE FROM channel_mentions WHERE beam_identity = ?1 AND channel_id = ?2",
        rusqlite::params![identity, channel_id],
    )
    .ok();
    StatusCode::NO_CONTENT.into_response()
}

pub async fn increment_mention(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let db = state.db.get().expect("db pool");
    db.execute(
        "INSERT INTO channel_mentions (beam_identity, channel_id, count)
         VALUES (?1, ?2, 1)
         ON CONFLICT(beam_identity, channel_id)
         DO UPDATE SET count = count + 1",
        rusqlite::params![identity, channel_id],
    )
    .ok();
    StatusCode::NO_CONTENT.into_response()
}

pub async fn get_unread_channels(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let db = state.db.get().expect("db pool");

    // Channels with messages newer than last read.
    let mut stmt = match db.prepare(
        "SELECT c.id FROM channels c
         WHERE c.type IN ('text', 'board')
         AND EXISTS (
             SELECT 1 FROM messages m
             WHERE m.channel_id = c.id
             AND m.created_at > COALESCE(
                 (SELECT last_read_at FROM channel_reads
                  WHERE beam_identity = ?1 AND channel_id = c.id),
                 0
             )
         )",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("get_unread_channels prepare: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response();
        }
    };

    let channel_ids: Vec<String> = stmt
        .query_map(rusqlite::params![identity], |row| row.get::<_, String>(0))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    // Pending mention counts per channel.
    let mut mstmt = match db.prepare(
        "SELECT channel_id, count FROM channel_mentions
         WHERE beam_identity = ?1 AND count > 0",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("get_unread_channels mentions prepare: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response();
        }
    };

    let mentions: HashMap<String, i64> = mstmt
        .query_map(rusqlite::params![identity], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    Json(json!({ "channel_ids": channel_ids, "mentions": mentions })).into_response()
}
