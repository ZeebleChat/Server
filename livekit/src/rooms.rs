use livekit_api::services::room::{CreateRoomOptions, RoomClient};
use serde::{Deserialize, Serialize};
use crate::error::{AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct CreateRoomRequest {
    pub name: String,

    /// Max participants (0 = unlimited)
    #[serde(default)]
    pub max_participants: u32,

    /// Room empty timeout in seconds (default 5 min)
    #[serde(default = "default_empty_timeout")]
    pub empty_timeout: u32,

    /// Enable audio recording
    #[serde(default)]
    #[allow(dead_code)]
    pub record: bool,
}

fn default_empty_timeout() -> u32 { 300 }

#[derive(Debug, Serialize)]
pub struct RoomInfo {
    pub name: String,
    pub sid: String,
    pub num_participants: u32,
    pub max_participants: u32,
    pub creation_time: i64,
    pub active_recording: bool,
}

pub async fn create_room(
    client: &RoomClient,
    req: CreateRoomRequest,
) -> AppResult<RoomInfo> {
    let opts = CreateRoomOptions {
        max_participants: req.max_participants,
        empty_timeout: req.empty_timeout,
        ..Default::default()
    };

    let room = client
        .create_room(&req.name, opts)
        .await
        .map_err(|e| AppError::LiveKit(e.to_string()))?;

    Ok(RoomInfo {
        name: room.name,
        sid: room.sid,
        num_participants: room.num_participants,
        max_participants: room.max_participants,
        creation_time: room.creation_time,
        active_recording: room.active_recording,
    })
}

pub async fn list_rooms(client: &RoomClient) -> AppResult<Vec<RoomInfo>> {
    let rooms = client
        .list_rooms(vec![])
        .await
        .map_err(|e| AppError::LiveKit(e.to_string()))?;

    Ok(rooms
        .into_iter()
        .map(|r| RoomInfo {
            name: r.name,
            sid: r.sid,
            num_participants: r.num_participants,
            max_participants: r.max_participants,
            creation_time: r.creation_time,
            active_recording: r.active_recording,
        })
        .collect())
}

pub async fn delete_room(client: &RoomClient, room_name: &str) -> AppResult<()> {
    client
        .delete_room(room_name)
        .await
        .map_err(|e| AppError::LiveKit(e.to_string()))?;
    Ok(())
}

pub async fn list_participants(
    client: &RoomClient,
    room_name: &str,
) -> AppResult<Vec<serde_json::Value>> {
    let participants = client
        .list_participants(room_name)
        .await
        .map_err(|e| AppError::LiveKit(e.to_string()))?;

    Ok(participants
        .into_iter()
        .map(|p| serde_json::json!({
            "identity": p.identity,
            "name": p.name,
            "sid": p.sid,
            "state": format!("{:?}", p.state()),
            "joined_at": p.joined_at,
            "is_publisher": p.is_publisher,
        }))
        .collect())
}
