# Zeeble Server

A self-hosted chat server for the Zeeble platform. Built with Rust, Axum, and SQLite.

## Quick Start

```bash
# Build and run
cargo run --release

# Or with Docker
docker build -t zeeble-server .
docker run -p 4000:4000 -v $(pwd)/data:/app/data zeeble-server
```

The server will:
1. Create `phaselink.yaml` if it doesn't exist
2. Start on port 4000 (configurable via `PORT` env var)
3. Generate a startup invite code for first-time access
4. Display local network URLs in the terminal

## Configuration

Configuration is loaded from `phaselink.yaml` with environment variable overrides:

```yaml
port: 4000
server_name: "My Zeeble Server"
public_url: "https://chat.example.com"
max_upload_size: "8MB"
max_message_length: 4000
allow_new_members: true
invites_anyone_can_create: true
```

**Hot-reloadable settings** (no restart needed):
- `server_name`, `public_url`, `about`
- `max_message_length`, `max_upload_size`
- `allow_new_members`, `invites_anyone_can_create`
- `default_invite_expiry_hours`, `default_invite_max_uses`

**Startup-only settings** (restart required):
- `port`, `db_path`, `auth_server_url`
- `livekit_api_url`, `livekit_server_url`

## Architecture

### Request Flow Diagram

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Client    │────▶│  Load Balancer │────▶│  Zeeble Server  │
│  (Web/App)  │     │  (Optional)   │     │   (Axum/Rust)   │
└─────────────┘     └──────────────┘     └─────────────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────┐
                    │                             │             │
                    ▼                             ▼             ▼
            ┌─────────────┐              ┌──────────────┐  ┌──────────┐
            │   Auth      │              │    SQLite    │  │ Memory   │
            │  (JWKS)     │              │   (WAL mode) │  │ Channels │
            └─────────────┘              └──────────────┘  └──────────┘
                                                 │
                    ┌────────────────────────────┼────────────┐
                    │                            │            │
                    ▼                            ▼            ▼
            ┌─────────────┐              ┌──────────────┐  ┌──────────┐
            │  Messages   │              │ Attachments  │  │  Users   │
            │  Channels   │              │  (BLOB/File) │  │ Invites  │
            └─────────────┘              └──────────────┘  └──────────┘
```

### Component Overview

**1. HTTP Layer (Axum)**
- RESTful API endpoints under `/v1/*`
- WebSocket handler at `/v1/ws` for real-time messaging
- Static file serving for attachments
- Compression and CORS middleware

**2. Authentication Flow**
```
Client ──▶ Auth Server ──▶ JWT Token ──▶ Zeeble Server
                │                              │
                │                              ▼
                │                        validate_jwt()
                │                       (Ed25519 via JWKS)
                │                              │
                └──────── JWKS fetch ◀─────────┘
```

**3. Real-time Messaging**
- In-memory broadcast channels per channel ID
- Server-wide broadcast for member updates
- WebSocket connections handle: Auth, Join, Message, Edit, Delete, Ping/Pong

**4. Database Layer**
- SQLite with WAL (Write-Ahead Logging) mode for concurrent reads/writes
- Connection pooling via `Arc<Mutex<Connection>>`
- Automatic migrations on startup

## Performance Characteristics

### SQLite Limits & Behavior

Zeeble uses SQLite with WAL mode enabled for optimal concurrency:

| Metric | Limit | Notes |
|--------|-------|-------|
| Database Size | 281 TB | Theoretical maximum |
| Table Size | 281 TB | Per-table limit |
| Row Size | 1 GB | Excluding BLOBs |
| Concurrent Readers | Unlimited | WAL mode benefit |
| Concurrent Writers | 1 | SQLite's fundamental limit |

### Realistic Performance Estimates

Based on typical SQLite performance and the Zeeble architecture:

| Workload | Expected Performance |
|----------|---------------------|
| **Light** (< 100 users, < 10 channels) | Handles gracefully with sub-10ms response times |
| **Moderate** (100-500 users, 10-50 channels) | Response times 10-50ms, occasional write contention |
| **Heavy** (500-1000 users, 50+ channels) | Response times 50-200ms, noticeable write queuing |
| **Maximum Recommended** | ~500 concurrent active users, ~50 channels |

**Note:** These are estimates for active users (those sending messages). The server can handle many more idle connections via WebSockets.

### Bottleneck Analysis

1. **Write Contention**: SQLite serializes writes. Heavy message rates in multiple channels will queue.
2. **Broadcast Memory**: Each channel maintains an in-memory broadcast channel (256 message buffer).
3. **File Uploads**: Attachments default to SQLite BLOBs; configure `attachments_dir` for filesystem storage.
4. **Member List**: Broadcasts to all connected clients on every presence change (scales O(n) with users).

### When to Consider PostgreSQL

Consider migrating to PostgreSQL when you experience:

- **> 500 concurrent active users** sending messages simultaneously
- **> 100 messages/second** sustained write throughput
- **> 1 million messages/day** with high read/write ratios
- **Multiple write-heavy channels** causing visible latency
- Need for **horizontal scaling** (read replicas, connection pooling)

**Migration path:** PostgreSQL support is planned. The abstraction around `rusqlite::Connection` is designed to be replaceable.

### Optimization Tips

1. **Enable filesystem attachments**:
   ```yaml
   attachments_dir: "/var/lib/zeeble/attachments"
   ```

2. **Use a reverse proxy** for TLS termination and static file serving

3. **Monitor WAL file size**: Large WAL files indicate checkpoints aren't keeping up

4. **Consider connection pooling** if adding PostgreSQL support in forks

## Security Model

### Token Flow

Zeeble uses a delegated authentication model with the Beam Auth Server:

```
┌─────────┐        ┌─────────────┐        ┌───────────────┐        ┌─────────────┐
│ Client  │───────▶│ Auth Server │───────▶│  JWT Token    │───────▶│ Zeeble      │
│         │ Login  │ (Ed25519)   │        │ (beam_identity│ Verify │ Server      │
└─────────┘        └─────────────┘        └───────────────┘        └─────────────┘
                                                │                       │
                                                │                       ▼
                                                │               ┌──────────────┐
                                                └──────────────▶│  JWKS Cache  │
                                                               │  (in-memory) │
                                                               └──────────────┘
```

**Token Validation:**
1. Extract `kid` from JWT header
2. Fetch corresponding Ed25519 public key from JWKS cache
3. Verify signature with `ed25519_dalek`
4. Check expiration (`exp` claim)
5. Validate audience (`aud` matches `public_url`)
6. Extract `beam_identity` or `sub` claim

**Token Lifetime:** Determined by auth server (typically 24 hours). No refresh tokens implemented in server.

### Permission Model

Zeeble implements Discord-style permission overrides:

```
Effective Permission =
  BASE(@everyone permissions)
  OR member's role permissions
  WITH channel/category overrides applied
```

**Permission Hierarchy:**
1. **Owner** → All permissions granted (bypasses all checks)
2. **Administrator role** → All permissions granted
3. **Server-wide role permissions** → Base grant
4. **Channel overrides** → @everyone deny/allow
5. **Channel overrides** → Member's role deny/allow

**Server Permissions:**
- `administrator`, `manage_server`, `manage_roles`
- `kick_members`, `ban_members`
- `create_invites`, `manage_invites`
- `manage_channels`, `manage_messages`, `manage_nicknames`

**Channel Permissions:**
- `view_channel`, `send_messages`, `read_message_history`
- `embed_links`, `attach_files`, `add_reactions`
- `mention_everyone`, `manage_messages`
- Voice: `connect`, `speak`, `video`, `mute_members`, `move_members`

**Permission Storage:**
- Role permissions: `custom_roles.permissions` (JSON)
- Channel overrides: `channel_permissions.allow/deny` (JSON)
- Category overrides: `category_permissions.allow/deny` (JSON)

### Rate Limiting

Zeeble implements sliding-window rate limiting per endpoint:

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| `/admin/unlock` | 5 attempts | 15 minutes | Per IP |
| `/v1/upload` | 10 uploads | 1 minute | Per user |
| `/v1/invites` (POST) | 10 creates | 1 minute | Per user |
| Bot message send | 60 messages | 1 minute | Per bot |

**Rate Limit Implementation:**
- In-memory sliding window buckets
- Automatic cleanup of expired entries
- Returns `429 Too Many Requests` with `Retry-After` header
- IP extraction respects `trusted_proxies` configuration

**Trusted Proxies:**
Configure `TRUSTED_PROXIES` (comma-separated IPs/CIDRs) to safely extract client IPs from `X-Forwarded-For` headers. Without this, rate limiting uses the direct connection IP.

### Content Security Policy (CSP)

All HTML responses include security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:
```

**CSP applies to:**
- Invite landing pages (`/join/:code`)
- Server unlock page (`/admin/unlock`)
- Any future server-rendered HTML

### Additional Security Features

**Startup Lock:**
- Server boots in locked mode until owner authenticates
- Requires `owner_beam_identity` to be set via `/admin/unlock`
- Rate-limited to prevent brute force

**TLS Enforcement:**
- Set `REQUIRE_TLS=true` to reject non-HTTPS requests
- Checks `X-Forwarded-Proto` header for reverse proxy setups

**File Upload Security:**
- MIME type whitelist (images, videos, audio, documents, archives)
- Filename sanitization (removes path traversal)
- Size limits enforced before streaming
- Optional filesystem storage instead of database BLOBs

**CORS:**
- Configurable via `ALLOWED_ORIGINS` environment variable
- Defaults to `public_url` if not set
- Allows credentials for authenticated requests

**Bot Authentication:**
- Separate token namespace with `Bot <token>` prefix
- Database-stored tokens with unique constraints
- Separate rate limiting from user tokens

## API Endpoints

### Channels
- `GET /v1/channels` - List all channels
- `POST /v1/channels` - Create channel (owner only)
- `DELETE /v1/channels/:id` - Delete channel (owner only)
- `PATCH /v1/channels/:id` - Rename channel (owner only)
- `GET /v1/channels/:id/permissions` - List channel permissions
- `PUT /v1/channels/:id/permissions/:role` - Set channel permissions

### Messages
- `GET /v1/channels/:id/messages` - Get messages (paginated)
- `POST /v1/channels/:id/messages` - Send message
- `PATCH /v1/messages/:id` - Edit own message
- `DELETE /v1/messages/:id` - Delete own message

### Invites
- `GET /v1/invites` - List active invites
- `POST /v1/invites` - Create invite
- `GET /v1/invites/:code` - Get invite info
- `POST /v1/invites/:code/redeem` - Redeem invite
- `DELETE /v1/invites/:code` - Revoke invite (creator only)

### Members & Roles
- `GET /v1/members` - List all members
- `PATCH /v1/account/status` - Update own status
- `GET /v1/roles` - List custom roles
- `PUT /v1/roles/:user_id` - Assign role to user (owner only)

### Files
- `POST /v1/upload` - Upload attachment(s)
- `GET /v1/attachments/:id` - Download attachment

### WebSocket
- `GET /v1/ws` - Real-time connection

**WebSocket Message Types:**
- `Auth` - Authenticate with JWT
- `Activate` - Subscribe to server-wide broadcasts
- `Join` - Subscribe to channel messages
- `Message` - Send message
- `EditMessage` - Edit message
- `DeleteMessage` - Delete message
- `Leave` - Unsubscribe from channel
- `Ping/Pong` - Heartbeat

## Development

```bash
# Run with hot reload
cargo watch -x run

# Run tests
cargo test

# Check formatting
cargo fmt -- --check

# Run clippy
cargo clippy -- -D warnings
```

## License

MIT License - See LICENSE file for details.
