use livekit_api::access_token::{AccessToken, VideoGrants};
use serde::{Deserialize, Serialize};
use crate::error::{AppError, AppResult};

/// What a participant is allowed to do in the room
#[derive(Debug, Deserialize)]
pub struct ParticipantPermissions {
    /// Can publish audio (VoIP)
    #[serde(default = "default_true")]
    pub can_publish_audio: bool,

    /// Can publish video (webcam or screen share)
    #[serde(default = "default_true")]
    pub can_publish_video: bool,

    /// Can publish data messages (live zeeble-chat)
    #[serde(default = "default_true")]
    pub can_publish_data: bool,

    /// Can subscribe to other participants' tracks
    #[serde(default = "default_true")]
    pub can_subscribe: bool,

    /// Is this participant a hidden server-side agent?
    #[serde(default)]
    pub hidden: bool,
}

fn default_true() -> bool { true }

impl Default for ParticipantPermissions {
    fn default() -> Self {
        Self {
            can_publish_audio: true,
            can_publish_video: true,
            can_publish_data: true,
            can_subscribe: true,
            hidden: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub room: String,
    pub identity: String,
    pub expires_at: i64,
}

pub fn generate_token(
    api_key: &str,
    api_secret: &str,
    room_name: &str,
    participant_identity: &str,
    participant_name: Option<&str>,
    permissions: &ParticipantPermissions,
    ttl_seconds: u64,
) -> AppResult<TokenResponse> {
    let grants = VideoGrants {
        room: room_name.to_string(),
        room_join: true,
        can_publish: permissions.can_publish_audio || permissions.can_publish_video,
        can_publish_data: permissions.can_publish_data,
        can_subscribe: permissions.can_subscribe,
        hidden: permissions.hidden,
        ..Default::default()
    };

    let now = chrono::Utc::now().timestamp();
    let expires_at = now + ttl_seconds as i64;

    let token = AccessToken::with_api_key(api_key, api_secret)
        .with_identity(participant_identity)
        .with_name(participant_name.unwrap_or(participant_identity))
        .with_grants(grants)
        .with_ttl(std::time::Duration::from_secs(ttl_seconds))
        .to_jwt()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Token generation failed: {}", e)))?;

    Ok(TokenResponse {
        token,
        room: room_name.to_string(),
        identity: participant_identity.to_string(),
        expires_at,
    })
}
