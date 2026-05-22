use std::sync::Arc;

use axum::{
    extract::{
        Extension,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use redis::AsyncCommands;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::{AppState, auth::validate_jwt};

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsIncoming {
    Auth {
        token: String,
    },
    Ping,
    VoiceJoin {
        channel_id: String,
    },
    VoiceLeave {
        channel_id: String,
    },
    /// Base64-encoded Opus audio frame(s) for a voice channel.
    VoiceAudio {
        channel_id: String,
        data: String,
    },
    /// Claim broadcaster slot and start a live stream on a channel.
    StreamStart {
        channel_id: String,
    },
    /// End the active live stream (broadcaster only).
    StreamStop {
        channel_id: String,
    },
    /// Subscribe to a live stream as a viewer.
    StreamJoin {
        channel_id: String,
    },
    /// Unsubscribe from a live stream.
    StreamLeave {
        channel_id: String,
    },
    /// Base64-encoded Opus frame from the broadcaster, fanned out to all viewers.
    StreamAudio {
        channel_id: String,
        data: String,
    },
    /// Base64-encoded JPEG screen-share frame, fanned out to all voice subscribers.
    StreamFrame {
        channel_id: String,
        data: String,
    },
}

async fn send_err(socket: &mut WebSocket, msg: &str) {
    if let Err(e) = socket
        .send(Message::Text(
            json!({ "type": "error", "message": msg }).to_string(),
        ))
        .await
    {
        warn!("ws: failed to send error frame to client: {e}");
    }
}

// ── Redis helpers ─────────────────────────────────────────────────────────────
// These log errors instead of silently discarding them.

async fn redis_sadd(redis: &mut redis::aio::ConnectionManager, key: &str, member: &str) {
    if let Err(e) = redis.sadd::<_, _, ()>(key, member).await {
        error!("redis SADD {key} failed: {e}");
    }
}

async fn redis_srem(redis: &mut redis::aio::ConnectionManager, key: &str, member: &str) {
    if let Err(e) = redis.srem::<_, _, ()>(key, member).await {
        error!("redis SREM {key} failed: {e}");
    }
}

async fn redis_scard(redis: &mut redis::aio::ConnectionManager, key: &str) -> i64 {
    match redis.scard::<_, i64>(key).await {
        Ok(n) => n,
        Err(e) => {
            error!("redis SCARD {key} failed: {e}");
            0
        }
    }
}

async fn redis_set_ex(redis: &mut redis::aio::ConnectionManager, key: &str, val: &str, secs: u64) {
    if let Err(e) = redis.set_ex::<_, _, ()>(key, val, secs).await {
        error!("redis SETEX {key} failed: {e}");
    }
}

async fn redis_del(redis: &mut redis::aio::ConnectionManager, key: &str) {
    if let Err(e) = redis.del::<_, ()>(key).await {
        error!("redis DEL {key} failed: {e}");
    }
}

async fn redis_publish(redis: &mut redis::aio::ConnectionManager, channel: &str, msg: &str) {
    if let Err(e) = redis.publish::<_, _, ()>(channel, msg).await {
        warn!("redis PUBLISH {channel} failed (voice events may not reach other nodes): {e}");
    }
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

fn is_origin_allowed(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
    let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
        Some(o) => o,
        None => return true,
    };
    if origin == "null" {
        return false;
    }
    let origin = origin.trim_end_matches('/');
    allowed_origins.iter().any(|a| a.trim_end_matches('/') == origin)
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_origin_allowed(&headers, &state.allowed_origins) {
        return (StatusCode::FORBIDDEN, "Origin not allowed").into_response();
    }
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

pub async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut voice_rx: Option<broadcast::Receiver<String>> = None;
    let mut stream_rx: Option<broadcast::Receiver<String>> = None;
    let mut current_voice_channel: Option<String> = None;
    let mut current_stream_channel: Option<String> = None;
    let mut broadcasting_channel: Option<String> = None;
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
                    Err(e) => {
                        warn!("malformed WS frame from {:?}: {e}", identity);
                        send_err(&mut socket, "Malformed message format").await;
                        break;
                    }
                };

                match ws_incoming {
                    WsIncoming::Ping => {
                        if let Err(e) = socket.send(Message::Text(json!({ "type": "pong" }).to_string())).await {
                            warn!("ws: ping/pong send failed: {e}");
                        }
                    }

                    WsIncoming::Auth { token } => {
                        match validate_jwt(&token, &state.jwks).await {
                            None => {
                                warn!("ws: auth failed (invalid/expired token)");
                                send_err(&mut socket, "Invalid or expired token").await;
                                break;
                            }
                            Some(id) => {
                                identity = Some(id.clone());
                                info!("ws: {id} authenticated");

                                // Send a snapshot of current voice presence so the client
                                // immediately sees who is in each channel.
                                let rooms: std::collections::HashMap<String, Vec<String>> = {
                                    let members = state.voice_members.lock().unwrap();
                                    members.iter()
                                        .filter(|(_, v)| !v.is_empty())
                                        .map(|(ch, ids)| (ch.clone(), ids.iter().cloned().collect()))
                                        .collect()
                                };
                                if !rooms.is_empty() {
                                    let _ = socket.send(Message::Text(
                                        serde_json::json!({ "type": "voice_snapshot", "rooms": rooms }).to_string()
                                    )).await;
                                }
                            }
                        }
                    }

                    WsIncoming::VoiceJoin { channel_id } => {
                        let id = match &identity {
                            Some(id) => id.clone(),
                            None => {
                                warn!("ws: VoiceJoin rejected — unauthenticated");
                                send_err(&mut socket, "Not authenticated").await;
                                continue;
                            }
                        };

                        // Leave previous voice channel if in one.
                        if let Some(ref old_ch) = current_voice_channel.take() {
                            state.voice_leave(old_ch, &id);
                            let mut r = state.redis.clone();
                            redis_srem(&mut r, &format!("voice:room:{old_ch}"), &id).await;
                            if redis_scard(&mut r, &format!("voice:room:{old_ch}")).await == 0 {
                                redis_srem(&mut r, "voice:rooms", old_ch).await;
                            }
                            let evt = json!({
                                "type": "voice_state", "channel_id": old_ch,
                                "identity": id, "action": "leave"
                            }).to_string();
                            let _ = state.server_bus.send(evt.clone());
                            redis_publish(&mut r, "zeeble:voice:events", &evt).await;
                        }
                        state.voice_join(&channel_id, &id);
                        let mut r = state.redis.clone();
                        redis_sadd(&mut r, "voice:rooms", &channel_id).await;
                        redis_sadd(&mut r, &format!("voice:room:{channel_id}"), &id).await;
                        voice_rx = Some(state.voice_bus_for(&channel_id).subscribe());
                        current_voice_channel = Some(channel_id.clone());

                        let evt = json!({
                            "type": "voice_state", "channel_id": channel_id,
                            "identity": id, "action": "join"
                        }).to_string();
                        let _ = state.server_bus.send(evt.clone());
                        redis_publish(&mut r, "zeeble:voice:events", &evt).await;

                        if let Err(e) = socket.send(Message::Text(
                            json!({ "type": "voice_joined", "channel_id": channel_id }).to_string()
                        )).await {
                            warn!("ws: failed to confirm voice_joined to {id}: {e}");
                        }
                        info!("voice: {id} joined #{channel_id}");
                    }

                    WsIncoming::VoiceLeave { channel_id } => {
                        let id = match &identity {
                            Some(id) => id.clone(),
                            None => continue,
                        };
                        if current_voice_channel.as_deref() == Some(&channel_id) {
                            state.voice_leave(&channel_id, &id);
                            let mut r = state.redis.clone();
                            redis_srem(&mut r, &format!("voice:room:{channel_id}"), &id).await;
                            if redis_scard(&mut r, &format!("voice:room:{channel_id}")).await == 0 {
                                redis_srem(&mut r, "voice:rooms", &channel_id).await;
                            }
                            voice_rx = None;
                            current_voice_channel = None;

                            let evt = json!({
                                "type": "voice_state", "channel_id": channel_id,
                                "identity": id, "action": "leave"
                            }).to_string();
                            let _ = state.server_bus.send(evt.clone());
                            redis_publish(&mut r, "zeeble:voice:events", &evt).await;
                            info!("voice: {id} left #{channel_id}");
                        }
                    }

                    WsIncoming::VoiceAudio { channel_id, data } => {
                        let id = match &identity {
                            Some(id) => id.clone(),
                            None => continue,
                        };
                        if current_voice_channel.as_deref() != Some(&channel_id) {
                            continue;
                        }
                        let frame = json!({
                            "type": "voice_audio",
                            "channel_id": channel_id,
                            "from": id,
                            "data": data,
                        }).to_string();
                        if let Err(e) = state.voice_bus_for(&channel_id).send(frame) {
                            // Only receivers = 0 case; not a hard error, just debug noise.
                            warn!("voice: no receivers on #{channel_id} for {id}'s audio frame: {e}");
                        }
                    }

                    WsIncoming::StreamStart { channel_id } => {
                        let id = match &identity {
                            Some(id) => id.clone(),
                            None => {
                                warn!("ws: StreamStart rejected — unauthenticated");
                                send_err(&mut socket, "Not authenticated").await;
                                continue;
                            }
                        };

                        if !state.claim_stream(&channel_id, &id) {
                            warn!("stream: {id} tried to start in #{channel_id} but slot already taken");
                            send_err(&mut socket, "A stream is already live in this channel").await;
                            continue;
                        }

                        let mut r = state.redis.clone();
                        redis_set_ex(&mut r, &format!("stream:{channel_id}"), &id, 4 * 3600).await;
                        redis_sadd(&mut r, "stream:live", &channel_id).await;
                        broadcasting_channel = Some(channel_id.clone());

                        let evt = json!({
                            "type": "stream_start",
                            "channel_id": channel_id,
                            "broadcaster": id,
                        }).to_string();
                        let _ = state.server_bus.send(evt.clone());
                        redis_publish(&mut r, "zeeble:voice:events", &evt).await;

                        if let Err(e) = socket.send(Message::Text(
                            json!({ "type": "stream_started", "channel_id": channel_id }).to_string()
                        )).await {
                            warn!("ws: failed to confirm stream_started to {id}: {e}");
                        }
                        info!("stream: {id} started live stream in #{channel_id}");
                    }

                    WsIncoming::StreamStop { channel_id } => {
                        let id = match &identity {
                            Some(id) => id.clone(),
                            None => continue,
                        };
                        if broadcasting_channel.as_deref() != Some(&channel_id) {
                            warn!("stream: {id} tried to stop #{channel_id} but is not the broadcaster");
                            send_err(&mut socket, "You are not broadcasting in this channel").await;
                            continue;
                        }
                        state.release_stream(&channel_id, &id);
                        let mut r = state.redis.clone();
                        redis_del(&mut r, &format!("stream:{channel_id}")).await;
                        redis_srem(&mut r, "stream:live", &channel_id).await;
                        broadcasting_channel = None;

                        let evt = json!({ "type": "stream_end", "channel_id": channel_id }).to_string();
                        let _ = state.server_bus.send(evt.clone());
                        // Also push onto the stream bus so viewers on stream_rx receive it.
                        let _ = state.stream_bus_for(&channel_id).send(evt.clone());
                        redis_publish(&mut r, "zeeble:voice:events", &evt).await;
                        info!("stream: {id} stopped live stream in #{channel_id}");
                    }

                    WsIncoming::StreamJoin { channel_id } => {
                        let id = match &identity {
                            Some(id) => id.clone(),
                            None => {
                                warn!("ws: StreamJoin rejected — unauthenticated");
                                send_err(&mut socket, "Not authenticated").await;
                                continue;
                            }
                        };

                        current_stream_channel = None;
                        stream_rx = None;

                        let broadcaster = state.stream_broadcaster(&channel_id);
                        if broadcaster.is_none() {
                            warn!("stream: {id} tried to join #{channel_id} but no stream is live");
                            send_err(&mut socket, "No stream is live in this channel").await;
                            continue;
                        }

                        stream_rx = Some(state.stream_bus_for(&channel_id).subscribe());
                        current_stream_channel = Some(channel_id.clone());

                        if let Err(e) = socket.send(Message::Text(
                            json!({
                                "type": "stream_joined",
                                "channel_id": channel_id,
                                "broadcaster": broadcaster,
                            }).to_string()
                        )).await {
                            warn!("ws: failed to confirm stream_joined to {id}: {e}");
                        }
                        info!("stream: {id} joined stream in #{channel_id}");
                    }

                    WsIncoming::StreamLeave { channel_id } => {
                        if current_stream_channel.as_deref() == Some(&channel_id) {
                            stream_rx = None;
                            current_stream_channel = None;
                        }
                    }

                    WsIncoming::StreamAudio { channel_id, data } => {
                        if broadcasting_channel.as_deref() != Some(&channel_id) {
                            continue;
                        }
                        let frame = json!({
                            "type": "stream_audio",
                            "channel_id": channel_id,
                            "data": data,
                        }).to_string();
                        if let Err(e) = state.stream_bus_for(&channel_id).send(frame) {
                            warn!("stream: no receivers on #{channel_id} for audio frame: {e}");
                        }
                    }

                    WsIncoming::StreamFrame { channel_id, data } => {
                        let id = match &identity {
                            Some(id) => id.clone(),
                            None => continue,
                        };
                        if current_voice_channel.as_deref() != Some(&channel_id) {
                            continue;
                        }
                        let frame = json!({
                            "type": "stream_frame",
                            "channel_id": channel_id,
                            "from": id,
                            "data": data,
                        }).to_string();
                        if let Err(e) = state.voice_bus_for(&channel_id).send(frame) {
                            warn!("stream: no receivers on #{channel_id} for frame from {id}: {e}");
                        }
                    }
                }
            }

            Some(voice_frame) = async {
                match voice_rx.as_mut() {
                    Some(r) => match r.recv().await {
                        Ok(m) => Some(m),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("voice: client {:?} lagged, dropped {n} audio frames", identity);
                            None
                        }
                        Err(e) => {
                            error!("voice: broadcast channel closed unexpectedly: {e}");
                            None
                        }
                    },
                    None => std::future::pending::<Option<String>>().await,
                }
            } => {
                if let Err(e) = socket.send(Message::Text(voice_frame)).await {
                    warn!("voice: failed to send audio frame to {:?}: {e}", identity);
                    break;
                }
            }

            Some(stream_frame) = async {
                match stream_rx.as_mut() {
                    Some(r) => match r.recv().await {
                        Ok(m) => Some(m),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("stream: viewer {:?} lagged, dropped {n} frames", identity);
                            None
                        }
                        Err(e) => {
                            error!("stream: broadcast channel closed unexpectedly: {e}");
                            None
                        }
                    },
                    None => std::future::pending::<Option<String>>().await,
                }
            } => {
                if let Err(e) = socket.send(Message::Text(stream_frame)).await {
                    warn!("stream: failed to send frame to viewer {:?}: {e}", identity);
                    break;
                }
            }

            else => break,
        }
    }

    // ── Disconnect cleanup ────────────────────────────────────────────────────

    if let Some(ref id) = identity {
        let left_channels = state.voice_leave_all(id);
        for channel_id in left_channels {
            let mut r = state.redis.clone();
            redis_srem(&mut r, &format!("voice:room:{channel_id}"), id).await;
            if redis_scard(&mut r, &format!("voice:room:{channel_id}")).await == 0 {
                redis_srem(&mut r, "voice:rooms", &channel_id).await;
            }
            let evt = json!({
                "type": "voice_state", "channel_id": channel_id,
                "identity": id, "action": "leave"
            }).to_string();
            let _ = state.server_bus.send(evt.clone());
            redis_publish(&mut r, "zeeble:voice:events", &evt).await;
        }

        if let Some(ref channel_id) = broadcasting_channel {
            state.release_stream(channel_id, id);
            let mut r = state.redis.clone();
            redis_del(&mut r, &format!("stream:{channel_id}")).await;
            redis_srem(&mut r, "stream:live", channel_id).await;
            let evt = json!({ "type": "stream_end", "channel_id": channel_id }).to_string();
            let _ = state.server_bus.send(evt.clone());
            let _ = state.stream_bus_for(channel_id).send(evt.clone());
            redis_publish(&mut r, "zeeble:voice:events", &evt).await;
            info!("stream: {id} disconnected — stream in #{channel_id} ended");
        }
    }

    info!("{} disconnected from zvoice", identity.as_deref().unwrap_or("unauthenticated"));
}
