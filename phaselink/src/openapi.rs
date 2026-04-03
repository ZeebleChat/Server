#![allow(dead_code)]

use axum::{Json, Router};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use crate::channels::{Channel, CreateChannel, RenameChannel};
use crate::messages::{ChatMessage, Attachment, MessagesQuery, CreateMessageBody, EditMessageBody};
use crate::invites::{CreateInvite, InviteInfo};
use crate::files::{AttachmentUploadResponse, UploadResult};
use crate::members::{FrontendMember, MemberCategory, UpdateStatusBody};
use crate::categories::{Category, CreateCategory, UpdateCategory};
use crate::roles::{CustomRole};

/// Main API documentation for Zeeble Server
#[derive(OpenApi)]
#[openapi(
    paths(
        health_endpoint,
        server_info_endpoint,
        list_channels_endpoint,
        create_channel_endpoint,
        delete_channel_endpoint,
        patch_channel_endpoint,
        get_messages_endpoint,
        create_message_endpoint,
        edit_message_endpoint,
        delete_message_endpoint,
        list_invites_endpoint,
        create_invite_endpoint,
        get_invite_endpoint,
        delete_invite_endpoint,
        redeem_invite_endpoint,
        upload_file_endpoint,
        get_attachment_endpoint,
        list_members_endpoint,
        update_status_endpoint,
    ),
    components(
        schemas(
            // Channel schemas
            Channel,
            CreateChannel,
            RenameChannel,
            // Message schemas
            ChatMessage,
            Attachment,
            MessagesQuery,
            CreateMessageBody,
            EditMessageBody,
            // Invite schemas
            CreateInvite,
            InviteInfo,
            // File schemas
            AttachmentUploadResponse,
            UploadResult,
            // Member schemas
            FrontendMember,
            MemberCategory,
            UpdateStatusBody,
            // Category schemas
            Category,
            CreateCategory,
            UpdateCategory,
            // Role schemas
            CustomRole,
            // Error schemas
            ErrorResponse,
            ServerInfoResponse,
            CreateMessageResponse,
            EditMessageResponse,
            DeleteMessageResponse,
            DeleteChannelResponse,
            DeleteInviteResponse,
            RedeemInviteResponse,
            StatusResponse,
            HealthResponse,
            // Response wrapper schemas
            ChannelListResponse,
            ChannelResponse,
            MessageListResponse,
            InviteListResponse,
            InviteResponse,
            AttachmentResponse,
            MemberListResponse,
        )
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "server", description = "Server information and configuration"),
        (name = "channels", description = "Channel management"),
        (name = "messages", description = "Message operations"),
        (name = "invites", description = "Invite link management"),
        (name = "files", description = "File upload and attachment retrieval"),
        (name = "members", description = "Member management and presence"),
    ),
    info(
        title = "Zeeble Server API",
        version = "0.1.0",
        description = "REST API for Zeeble chat server. All protected endpoints require Bearer token authentication via the Authorization header.",
        license(
            name = "MIT",
        ),
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            );
        }
    }
}

/// Error response schema
#[derive(utoipa::ToSchema)]
struct ErrorResponse {
    /// Error message
    error: String,
}

/// Server information response
#[derive(utoipa::ToSchema)]
struct ServerInfoResponse {
    /// Server display name
    server_name: String,
    /// Public URL of the server
    public_url: String,
    /// Server description
    about: String,
    /// Owner's beam identity
    owner: String,
    /// List of channels
    channels: Vec<serde_json::Value>,
    /// Whether new members are allowed
    allow_new_members: bool,
    /// Whether anyone can create invites
    invites_anyone: bool,
    /// Logo attachment ID
    logo_attachment_id: Option<i64>,
}

/// Channel list response
#[derive(utoipa::ToSchema)]
struct ChannelListResponse(Vec<Channel>);

/// Single channel response
#[derive(utoipa::ToSchema)]
struct ChannelResponse {
    /// Channel ID
    id: String,
    /// Channel name
    name: String,
    /// Channel topic/description
    topic: String,
    /// Channel type (text, voice)
    #[schema(rename = "type")]
    channel_type: String,
    /// Category ID the channel belongs to
    category_id: Option<i64>,
    /// Position in the channel list
    position: i64,
}

/// Message list response
#[derive(utoipa::ToSchema)]
struct MessageListResponse(Vec<ChatMessage>);

/// Message creation response
#[derive(utoipa::ToSchema)]
struct CreateMessageResponse {
    /// Message ID
    id: i64,
    /// Creation timestamp (Unix epoch)
    created_at: i64,
}

/// Message edit response
#[derive(utoipa::ToSchema)]
struct EditMessageResponse {
    /// Success flag
    ok: bool,
    /// Edit timestamp (Unix epoch)
    edited_at: i64,
}

/// Message deletion response
#[derive(utoipa::ToSchema)]
struct DeleteMessageResponse {
    /// Deletion success flag
    deleted: bool,
}

/// Invite list item
#[derive(utoipa::ToSchema)]
struct InviteListItem {
    /// Invite code
    code: String,
    /// Creator's beam identity
    created_by: String,
    /// Creation timestamp (Unix epoch)
    created_at: i64,
    /// Expiration timestamp (Unix epoch, null if never)
    expires_at: Option<i64>,
    /// Maximum number of uses (null if unlimited)
    max_uses: Option<i64>,
    /// Current use count
    use_count: i64,
    /// Whether the invite is still valid
    valid: bool,
}

/// Invite list response
#[derive(utoipa::ToSchema)]
struct InviteListResponse(Vec<InviteListItem>);

/// Invite creation/retrieval response
#[derive(utoipa::ToSchema)]
struct InviteResponse {
    /// Invite code
    code: String,
    /// Web URL to join
    web_url: String,
    /// Deep link URL
    deep_url: String,
    /// Expiration timestamp (Unix epoch, null if never)
    expires_at: Option<i64>,
    /// Maximum number of uses (null if unlimited)
    max_uses: Option<i64>,
}

/// Redeem invite response
#[derive(utoipa::ToSchema)]
struct RedeemInviteResponse {
    /// Success flag
    ok: bool,
}

/// Attachment/file response
#[derive(utoipa::ToSchema)]
struct AttachmentResponse(String);

/// Member list response
#[derive(utoipa::ToSchema)]
struct MemberListResponse(Vec<MemberCategory>);

/// Status update response
#[derive(utoipa::ToSchema)]
struct StatusResponse {
    /// New status value
    status: String,
}

/// Health check response
#[derive(utoipa::ToSchema)]
struct HealthResponse {
    /// Status message
    status: String,
    /// Server name
    server_name: String,
    /// API version
    version: String,
}

/// Channel deletion response
#[derive(utoipa::ToSchema)]
struct DeleteChannelResponse {
    /// Deletion success flag
    deleted: bool,
}

/// Invite deletion response
#[derive(utoipa::ToSchema)]
struct DeleteInviteResponse {
    /// Deletion success flag
    deleted: bool,
}

/// Get OpenAPI JSON spec
#[utoipa::path(
    get,
    path = "/api-docs.json",
    responses(
        (status = 200, description = "OpenAPI JSON specification", body = serde_json::Value),
    ),
    tag = "docs"
)]
async fn openapi_json() -> Json<serde_json::Value> {
    let json_str = ApiDoc::openapi().to_pretty_json().expect("valid openapi");
    Json(serde_json::from_str(&json_str).expect("valid json"))
}

/// Health check
/// 
/// Returns server health status and version information.
/// This endpoint is always accessible, even when the server is locked.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Server is healthy", body = HealthResponse),
    ),
    tag = "health"
)]
async fn health_endpoint() {}

/// Get server information
/// 
/// Returns detailed server information including channels, settings, and metadata.
/// Requires Bearer token authentication.
#[utoipa::path(
    get,
    path = "/v1/server/info",
    responses(
        (status = 200, description = "Server information retrieved successfully", body = ServerInfoResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "server"
)]
async fn server_info_endpoint() {}

/// List all channels
/// 
/// Returns a list of all channels visible to the authenticated user.
/// Channels are filtered based on the user's role permissions.
#[utoipa::path(
    get,
    path = "/v1/channels",
    responses(
        (status = 200, description = "List of channels", body = ChannelListResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "channels"
)]
async fn list_channels_endpoint() {}

/// Create a new channel
/// 
/// Creates a new channel with the specified ID and name.
/// Only the server owner can create channels.
#[utoipa::path(
    post,
    path = "/v1/channels",
    request_body = CreateChannel,
    responses(
        (status = 200, description = "Channel created successfully", body = ChannelResponse),
        (status = 400, description = "Invalid channel ID format", body = ErrorResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - Only server owner can create channels", body = ErrorResponse),
        (status = 409, description = "Conflict - Channel ID already exists", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "channels"
)]
async fn create_channel_endpoint() {}

/// Delete a channel
/// 
/// Deletes a channel and all its messages.
/// Only the server owner can delete channels. The "general" channel cannot be deleted.
#[utoipa::path(
    delete,
    path = "/v1/channels/{id}",
    params(
        ("id" = String, Path, description = "Channel ID to delete"),
    ),
    responses(
        (status = 200, description = "Channel deleted successfully", body = DeleteChannelResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - Only server owner can delete channels or cannot delete general channel", body = ErrorResponse),
        (status = 404, description = "Channel not found", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "channels"
)]
async fn delete_channel_endpoint() {}

/// Rename/update a channel
/// 
/// Updates channel properties including name, topic, type, category, and position.
/// Only the server owner can rename channels. The "general" channel cannot be renamed.
#[utoipa::path(
    patch,
    path = "/v1/channels/{id}",
    params(
        ("id" = String, Path, description = "Channel ID to update"),
    ),
    request_body = RenameChannel,
    responses(
        (status = 200, description = "Channel updated successfully", body = ChannelResponse),
        (status = 400, description = "Invalid request - No valid fields to update", body = ErrorResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - Only server owner can rename channels or cannot rename general channel", body = ErrorResponse),
        (status = 404, description = "Channel not found", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "channels"
)]
async fn patch_channel_endpoint() {}

/// Get messages in a channel
/// 
/// Retrieves paginated messages from a channel.
/// Supports before_id pagination for infinite scroll.
#[utoipa::path(
    get,
    path = "/v1/channels/{channel_id}/messages",
    params(
        ("channel_id" = String, Path, description = "Channel ID"),
        MessagesQuery,
    ),
    responses(
        (status = 200, description = "List of messages", body = MessageListResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - No permission to view this channel", body = ErrorResponse),
        (status = 404, description = "Channel not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "messages"
)]
async fn get_messages_endpoint() {}

/// Send a message
/// 
/// Creates a new message in the specified channel.
/// Requires permission to send messages in the channel.
#[utoipa::path(
    post,
    path = "/v1/channels/{channel_id}/messages",
    params(
        ("channel_id" = String, Path, description = "Channel ID"),
    ),
    request_body = CreateMessageBody,
    responses(
        (status = 200, description = "Message created successfully", body = CreateMessageResponse),
        (status = 400, description = "Invalid message content", body = ErrorResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - No permission to send messages", body = ErrorResponse),
        (status = 404, description = "Channel not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "messages"
)]
async fn create_message_endpoint() {}

/// Edit a message
/// 
/// Updates the content of an existing message.
/// Users can only edit their own messages.
#[utoipa::path(
    patch,
    path = "/v1/messages/{message_id}",
    params(
        ("message_id" = i64, Path, description = "Message ID"),
    ),
    request_body = EditMessageBody,
    responses(
        (status = 200, description = "Message edited successfully", body = EditMessageResponse),
        (status = 400, description = "Invalid message content", body = ErrorResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 404, description = "Message not found or not owned by user", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "messages"
)]
async fn edit_message_endpoint() {}

/// Delete a message
/// 
/// Deletes a message from a channel.
/// Users can only delete their own messages.
#[utoipa::path(
    delete,
    path = "/v1/messages/{message_id}",
    params(
        ("message_id" = i64, Path, description = "Message ID"),
    ),
    responses(
        (status = 200, description = "Message deleted successfully", body = DeleteMessageResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 404, description = "Message not found or not owned by user", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "messages"
)]
async fn delete_message_endpoint() {}

/// List all invites
/// 
/// Returns a list of all invite codes.
/// Only the server owner can list all invites.
#[utoipa::path(
    get,
    path = "/v1/invites",
    responses(
        (status = 200, description = "List of invites", body = InviteListResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - Only server owner can list invites", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "invites"
)]
async fn list_invites_endpoint() {}

/// Create an invite
/// 
/// Creates a new invite link for the server.
/// Regular users can create invites if the server setting `invites_anyone_can_create` is enabled.
#[utoipa::path(
    post,
    path = "/v1/invites",
    request_body = CreateInvite,
    responses(
        (status = 200, description = "Invite created successfully", body = InviteResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - Not allowed to create invites", body = ErrorResponse),
        (status = 429, description = "Too many requests - Rate limited", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "invites"
)]
async fn create_invite_endpoint() {}

/// Get invite info
/// 
/// Returns information about an invite without consuming it.
/// Used by the join page to display server information.
#[utoipa::path(
    get,
    path = "/v1/invites/{code}",
    params(
        ("code" = String, Path, description = "Invite code"),
    ),
    responses(
        (status = 200, description = "Invite information", body = InviteInfo),
        (status = 404, description = "Invite not found"),
        (status = 410, description = "Invite expired or at max uses"),
        (status = 423, description = "Server is locked"),
    ),
    tag = "invites"
)]
async fn get_invite_endpoint() {}

/// Delete/revoke an invite
/// 
/// Deletes an invite code, preventing further use.
/// Only the invite creator or server owner can revoke invites.
#[utoipa::path(
    delete,
    path = "/v1/invites/{code}",
    params(
        ("code" = String, Path, description = "Invite code to revoke"),
    ),
    responses(
        (status = 200, description = "Invite deleted successfully", body = DeleteInviteResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - Only creator or owner can revoke", body = ErrorResponse),
        (status = 404, description = "Invite not found", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "invites"
)]
async fn delete_invite_endpoint() {}

/// Redeem an invite
/// 
/// Consumes one use of an invite code.
/// Called after the user has authenticated.
#[utoipa::path(
    post,
    path = "/v1/invites/{code}/redeem",
    params(
        ("code" = String, Path, description = "Invite code to redeem"),
    ),
    responses(
        (status = 200, description = "Invite redeemed successfully", body = RedeemInviteResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 403, description = "Forbidden - Server not accepting new members", body = ErrorResponse),
        (status = 404, description = "Invite not found", body = ErrorResponse),
        (status = 410, description = "Invite expired or at max uses", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "invites"
)]
async fn redeem_invite_endpoint() {}

/// Upload files
/// 
/// Uploads one or more files and returns attachment IDs.
/// Supports multipart/form-data with file fields.
#[utoipa::path(
    post,
    path = "/v1/upload",
    request_body = UploadResult,
    responses(
        (status = 200, description = "Files uploaded successfully", body = UploadResult),
        (status = 400, description = "No valid files uploaded", body = ErrorResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 413, description = "Payload too large - File size exceeds limit", body = ErrorResponse),
        (status = 429, description = "Too many requests - Rate limited", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "files"
)]
async fn upload_file_endpoint() {}

/// Get attachment
/// 
/// Retrieves a file by its attachment ID.
/// Returns the file with appropriate Content-Type header.
/// Can be accessed via Bearer token or token query parameter.
#[utoipa::path(
    get,
    path = "/v1/attachments/{id}",
    params(
        ("id" = i64, Path, description = "Attachment ID"),
        ("token" = Option<String>, Query, description = "Optional JWT token for access"),
    ),
    responses(
        (status = 200, description = "File retrieved successfully", body = AttachmentResponse, content_type = "application/octet-stream"),
        (status = 401, description = "Unauthorized - Invalid or expired token"),
        (status = 404, description = "Attachment not found"),
        (status = 500, description = "Internal server error"),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "files"
)]
async fn get_attachment_endpoint() {}

/// List members
/// 
/// Returns a categorized list of all server members.
/// Members are grouped by hoisted roles and online/offline status.
#[utoipa::path(
    get,
    path = "/v1/members",
    responses(
        (status = 200, description = "List of member categories", body = MemberListResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "members"
)]
async fn list_members_endpoint() {}

/// Update status
/// 
/// Updates the current user's online status.
/// Valid statuses: online, idle, dnd, offline
#[utoipa::path(
    patch,
    path = "/v1/account/status",
    request_body = UpdateStatusBody,
    responses(
        (status = 200, description = "Status updated successfully", body = StatusResponse),
        (status = 400, description = "Invalid status value", body = ErrorResponse),
        (status = 401, description = "Unauthorized - Invalid or expired token", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
        (status = 423, description = "Server is locked"),
    ),
    security(("bearer_auth" = [])),
    tag = "members"
)]
async fn update_status_endpoint() {}

/// Create OpenAPI router with Swagger UI
/// Note: This router doesn't need AppState, so it returns Router<()>
pub fn openapi_routes() -> Router<()> {
    Router::new()
        .merge(SwaggerUi::new("/api-docs").url("/api-docs.json", ApiDoc::openapi()))
}
