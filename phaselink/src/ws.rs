use super::*;
use crate::messages::{Attachment, WsBroadcast};
use axum::extract::Extension;
use std::sync::Arc;

// resolve_identity is defined in crate::auth and re-exported via crate::resolve_identity

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

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
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
                        match resolve_identity(&token, &state).await {
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
                                    state.broadcast_member_update().await;
                                } else {
                                    debug!("ws: {id} re-authenticated");
                                }
                            }
                        }
                    }
                    WsIncoming::Activate { server_id, token } => {
                        match resolve_identity(&token, &state).await {
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
                        match resolve_identity(&token, &state).await {
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
                        let id = match resolve_identity(&token, &state).await {
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
                        let id = match resolve_identity(&token, &state).await {
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
                        let id = match resolve_identity(&token, &state).await {
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
