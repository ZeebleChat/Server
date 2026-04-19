# Zeeble Server (PhaseLink)

Self-hosted backend for Zeeble — a chat platform with real-time messaging, voice rooms, file uploads, and a bot API. Connect the official Zeeble client to your own server instead of a shared cloud instance.

Authentication is handled by the **Zeeble auth service** (hosted at `api.zeeble.xyz`). You don't need to run any auth infrastructure — just point the server at the auth URL and register an account on the Zeeble client.

## Architecture

```
Client (HTTPS/WSS)
│
▼
Caddy :8081 / :8444
(reverse proxy, optional TLS)
│
├── /ws, /v1/ws  → PhaseLink :4000  (REST + WebSocket)
└── /rtc         → LiveKit  :7880   (voice/video)

PhaseLink validates tokens against api.zeeble.xyz
```

**Services (Docker Compose):**

| Service | Role | External port |
|---|---|---|
| `caddy` | Reverse proxy | 8081 (HTTP), 8444 (HTTPS) |
| `phaselink` | Chat server (Rust/Axum) | internal only |
| `livekit` | Voice/video server | 7970, 7971, 7972/udp, 50200–50220/udp |
| `livekit-api` | LiveKit token bridge | 3100 |
| `redis` | LiveKit state | internal only |

### LiveKit port requirements

LiveKit uses WebRTC, which requires direct UDP connectivity — it cannot work through HTTP-only proxies or tunnels. All LiveKit ports must be open and reachable from the internet:

| Port | Protocol | Purpose |
|---|---|---|
| 7970 | TCP | HTTP / WebSocket signaling |
| 7971 | TCP | RTC over TCP (fallback for strict firewalls) |
| 7972 | UDP | RTC media (primary — preferred path) |
| 50200–50220 | UDP | ICE candidate range for peer connections |

**Why the UDP range matters:** WebRTC negotiates a direct media path between the server and each participant using ICE. Each active voice connection needs its own UDP port from this range. A range of 20 ports supports roughly 20 simultaneous voice connections. Widen the range in `docker-compose.yml` and `livekit.yaml` if you expect more concurrent users.

If UDP ports are blocked or not forwarded, LiveKit will attempt TCP fallback on port 7971 — this works but increases latency and reduces quality. If both are blocked, voice won't connect at all.

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- A Zeeble account (register at `api.zeeble.xyz` via the Zeeble client)
- A domain or public IP (for the Zeeble client to connect to)

### 1. Configure `phaselink.yaml`

Edit `phaselink.yaml` — at minimum set:

```yaml
owner_beam_identity: "yourname»abc12"   # your Zeeble beam identity
public_url: "https://yourdomain.com"    # or http://your-ip:8081 for local dev
```

### 2. Create `.env` (optional)

Most settings can be left as defaults. Override them here:

```env
# Required for voice (get these from livekit.io or self-host LiveKit Cloud)
LIVEKIT_API_KEY=your_key
LIVEKIT_API_SECRET=your_secret_min_32_chars

# Optional
AUTH_SERVER_URL=https://api.zeeble.xyz   # default — no need to change
PUBLIC_URL=https://yourdomain.com
OWNER_BEAM_IDENTITY=yourname»abc12
```

### 3. Start

```bash
docker compose up -d
```

### 4. Unlock the server

On first start (and every restart) the server is locked. All `/v1/` endpoints return `423 Locked` until the owner authenticates.

**Via web form** (recommended for headless/Docker):

Open `http://yourdomain:8081/admin/unlock` in a browser and enter your beam identity and password.

**Via API:**
```bash
curl -X POST http://yourdomain:8081/admin/unlock \
  -H "Content-Type: application/json" \
  -d '{"beam_identity":"yourname»abc12","password":"yourpassword"}'
```

---

## TLS

> **Note:** Cloudflare Tunnel does **not** work with LiveKit. LiveKit uses direct UDP connections for WebRTC — tunnels that proxy only HTTP/WebSocket will break voice completely. You need real ports exposed to the internet.

**Manual TLS certs (recommended):** Set in your `.env`:

```env
CADDYFILE=./caddy/Caddyfile.tls
CERTS_PATH=/etc/letsencrypt/live/yourdomain.com
TLS_CERT=/certs/fullchain.pem
TLS_KEY=/certs/privkey.pem
```

Then add the cert volume to `caddy` in `docker-compose.yml`:
```yaml
- ${CERTS_PATH}:/certs:ro
```

Generate a self-signed cert for local testing:
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/privkey.pem \
  -out certs/fullchain.pem -days 365 -nodes -subj "/CN=localhost"
```

---

## Configuration Reference (`phaselink.yaml`)

Settings marked **live** apply immediately on save (hot-reload). **Restart** settings need a container restart.

| Setting | Default | Reload | Description |
|---|---|---|---|
| `port` | `4000` | restart | Internal listen port |
| `db_path` | `zeeble.db` | restart | SQLite database file path |
| `public_url` | `http://localhost:8081` | live | Base URL shown in invite links |
| `server_name` | `"Zeeble Server"` | live | Display name of this server |
| `owner_beam_identity` | *(empty)* | live | Beam identity of the server owner |
| `about` | *(none)* | live | Short server description |
| `max_message_length` | `4000` | live | Maximum characters per message |
| `max_upload_size` | `8MB` | live | Maximum file upload size |
| `invites_anyone_can_create` | `true` | live | Allow any member to create invites |
| `default_invite_expiry_hours` | `0` | live | Default invite expiry (`0` = never) |
| `default_invite_max_uses` | `0` | live | Default max redemptions (`0` = unlimited) |
| `allow_new_members` | `true` | live | Whether new members can join via invite |

**Environment variable overrides** (take precedence over `phaselink.yaml`):

| Variable | Description |
|---|---|
| `AUTH_SERVER_URL` | Auth service base URL (default: `https://api.zeeble.xyz`) |
| `OWNER_BEAM_IDENTITY` | Server owner's beam identity |
| `PUBLIC_URL` | Overrides `public_url` |
| `LIVEKIT_API_URL` | Internal LiveKit API bridge URL |
| `LIVEKIT_SERVER_URL` | Internal LiveKit server URL |

---

## REST API

All `/v1/` endpoints require the server to be unlocked. Most require `Authorization: Bearer <jwt>` (JWT obtained from the Zeeble auth service).

### Server

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Server status |
| `GET` | `/admin/unlock` | none | Unlock web form |
| `POST` | `/admin/unlock` | none | Unlock server — body: `{beam_identity, password}` |
| `GET` | `/v1/server/info` | user JWT | Public server info |
| `GET` | `/v1/server/settings` | owner JWT | Get full server settings |
| `PATCH` | `/v1/server/settings` | owner JWT | Update settings |

### Channels

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/channels` | user JWT | List all channels |
| `POST` | `/v1/channels` | owner JWT | Create a channel — body: `{name, topic?}` |
| `DELETE` | `/v1/channels/:id` | owner JWT | Delete a channel |
| `PATCH` | `/v1/channels/:id` | owner JWT | Rename channel — body: `{name}` |

### Messages

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/channels/:channel_id/messages` | user JWT | Get messages (`?before=<id>&limit=50`) |
| `POST` | `/v1/channels/:channel_id/messages` | user JWT | Send a message — body: `{content, attachment_ids?}` |
| `GET` | `/v1/channels/:channel_id/posts` | user JWT | Get board posts |
| `GET` | `/v1/channels/:channel_id/posts/:post_id/replies` | user JWT | Get post replies |
| `PATCH` | `/v1/messages/:message_id` | sender JWT | Edit a message — body: `{content}` |
| `DELETE` | `/v1/messages/:message_id` | sender JWT | Delete a message |

### Files

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/upload` | user JWT | Upload a file (multipart/form-data) |
| `GET` | `/v1/attachments/:id` | none | Download an attachment |

### Members

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/members` | user JWT | List members |
| `DELETE` | `/v1/members/:identity` | owner JWT | Kick a member |
| `PATCH` | `/v1/account/status` | user JWT | Update own status — body: `{status}` |

### Invites

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/invites` | user JWT | List active invites |
| `POST` | `/v1/invites` | user JWT | Create invite — body: `{expiry_hours?, max_uses?}` |
| `GET` | `/v1/invites/:code` | none | Get invite info |
| `DELETE` | `/v1/invites/:code` | owner JWT | Delete invite |
| `POST` | `/v1/invites/:code/redeem` | user JWT | Redeem an invite |
| `POST` | `/v1/join/:code` | user JWT | Join via invite |
| `GET` | `/join/:code` | none | Human-readable invite landing page |
| `POST` | `/v1/first-time-setup` | owner JWT | Create first invite (initial setup) |

### Categories & Roles

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/categories` | user JWT | List channel categories |
| `POST` | `/v1/categories` | owner JWT | Create category |
| `PATCH` | `/v1/categories/:id` | owner JWT | Update category |
| `DELETE` | `/v1/categories/:id` | owner JWT | Delete category |
| `GET` | `/v1/categories/:id/permissions` | owner JWT | List category permissions |
| `PUT` | `/v1/categories/:id/permissions/:role` | owner JWT | Set category permission |
| `DELETE` | `/v1/categories/:id/permissions/:role` | owner JWT | Delete category permission |
| `GET` | `/v1/channels/:id/permissions` | owner JWT | List channel permissions |
| `PUT` | `/v1/channels/:id/permissions/:role` | owner JWT | Set channel permission |
| `DELETE` | `/v1/channels/:id/permissions/:role` | owner JWT | Delete channel permission |
| `GET` | `/v1/roles` | user JWT | List user roles |
| `PUT` | `/v1/roles/:user_id` | owner JWT | Set a role |
| `DELETE` | `/v1/roles/:user_id` | owner JWT | Remove a role |
| `GET` | `/v1/custom_roles` | user JWT | List custom roles |
| `POST` | `/v1/custom_roles` | owner JWT | Create custom role |
| `PATCH` | `/v1/custom_roles` | owner JWT | Reorder custom roles |
| `PUT` | `/v1/custom_roles/:name` | owner JWT | Update custom role |
| `DELETE` | `/v1/custom_roles/:name` | owner JWT | Delete custom role |

### Voice

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/voice/token` | user JWT | Get a LiveKit access token — query: `?room=<name>` |
| `GET` | `/v1/voice/rooms` | user JWT | List active voice rooms |
| `GET` | `/v1/voice/participants/:channel_id` | user JWT | List participants in a voice channel |

---

## WebSocket

Connect to `wss://yourdomain.com/v1/ws`. All frames are JSON.

### Client → Server

```json
{ "type": "auth", "token": "<jwt>" }
{ "type": "join", "channel_id": "<id>" }
{ "type": "message", "channel_id": "<id>", "content": "Hello!", "attachment_ids": [] }
{ "type": "edit_message", "message_id": 42, "content": "Corrected text" }
{ "type": "delete_message", "message_id": 42 }
{ "type": "leave", "channel_id": "<id>" }
{ "type": "ping" }
```

Tokens are re-validated on every message. JWTs expire in 15 minutes — clients should refresh and resend as needed. The server sends `{"type":"error","message":"Token expired"}` and disconnects on invalid tokens.

**Bot authentication:** send `"token": "Bot <your_bot_token>"` in any auth-bearing message.

### Server → Client

| `type` | Fields | Description |
|---|---|---|
| `pong` | — | Reply to ping |
| `message` | `id, channel_id, beam_identity, content, created_at, attachments` | New message |
| `message_edited` | `id, channel_id, content, edited_at` | Message edited |
| `message_deleted` | `id, channel_id` | Message deleted |
| `activated` | `server_id` | Server activation acknowledged |
| `error` | `message` | Error — connection may close |

---

## Bot API

Bots are server-side automation accounts managed by the server owner. They authenticate with `Authorization: Bot <token>`.

### Creating a bot

```bash
curl -X POST https://yourdomain.com/v1/bots \
  -H "Authorization: Bearer <owner_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"name": "MyBot"}'
```

Response:
```json
{ "id": "a3f8...", "name": "MyBot", "token": "d4e2f1..." }
```

**The token is shown once — store it securely.** If lost, delete and recreate the bot.

### Bot endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/v1/bots` | owner JWT | Create bot — body: `{name}` |
| `GET` | `/v1/bots` | owner JWT | List all bots (tokens omitted) |
| `DELETE` | `/v1/bots/:id` | owner JWT | Delete a bot |
| `POST` | `/v1/bot/channels/:channel_id/messages` | Bot token | Send a message |
| `GET` | `/v1/bot/channels/:channel_id/messages` | Bot token | Read last 50 messages |

Bot messages appear as `bot:<BotName>` and are broadcast in real time to all WebSocket clients.

---

## Beam Identity Format

```
displayName<separator>tag
```

| Account type | Separator | Example |
|---|---|---|
| Primary | `»` | `alice»k4mx9` |
| Alt | `§` | `alice§ab1cd` |
| Sub/Child | `‡` | `alice‡xyz99` |
| Bot | `λ` | `MyBotλ00001` |

Display names are 1–12 characters, lowercase. Tags are 5 random alphanumeric characters assigned at registration.

---

## Development

### Running without Docker

```bash
cd phaselink
cargo run
```

The server reads `phaselink.yaml` from the working directory (or `/data/phaselink.yaml` in Docker).

### Building

```bash
cd phaselink
cargo build --release
```

### Database

PhaseLink uses SQLite. The database is created automatically on first run at the path set by `db_path`. Schema migrations run automatically on startup.

### Logs

Set `RUST_LOG=zeeble_server=debug` for verbose output. Default: `zeeble_server=info`.
