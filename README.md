# Zeeble-Server

Self-hosted backend for Zeeble — a chat platform with real-time messaging, voice rooms, file uploads, and a bot API. Connect the official Zeeble client (or any compatible client) to your own server instead of a shared cloud instance.

## Architecture

```
Client (WSS/HTTPS)
│
▼

caddy :443 ───────────────────────────────┐
(Auto TLS, reverse proxy)                  │
                                           │
▼                                           │
PhaseLink :4000 (internal Docker network) │
├── REST API                                │
├── WebSocket (/ws)                         │
└── SQLite DB                               │
                                           │
LiveKit (voice/video) ◄────────────────────┘
LiveKit API (token bridge)
Redis (LiveKit state)
```

**Services (Docker Compose):**
| Service | Role | External port |
|---|---|---|
| `caddy` | Auto-TLS reverse proxy | 80, 443 |
| `phaselink` | Chat server (Rust/Axum) | internal only |
| `livekit` | Voice/video server | 7880, 7881, 7882/udp |
| `livekit-api` | LiveKit token bridge | 3000 |
| `redis` | LiveKit state | 6379 |

Authentication is handled by a separate **zeeble-auth** server (not included in this repo), which issues Ed25519-signed JWTs. PhaseLink validates tokens locally using the auth server's public key.

---

## Quick start

### Prerequisites

- Docker + Docker Compose
- A running **zeeble-auth** instance (zeeble-gate) - see [zeeble-gate repository](https://github.com/zeeble/zeeble-gate)

### 1. Caddy handles TLS automatically

Caddy provides automatic HTTPS out of the box:

- **Development**: Uses a self-signed cert automatically (browse to `http://localhost` and accept the warning)
- **Production**: Automatically obtains Let's Encrypt certificates for your domain

No manual certificate setup required!

**Production:** Caddy automatically obtains Let's Encrypt certificates — just set your domain as the hostname in `phaselink.yaml` and ensure ports 80/443 are reachable.

### 2. Register your owner account on zeeble-auth

The server locks itself on startup until the owner authenticates. You must have a registered account on your zeeble-auth instance.

```bash
curl -X POST http://localhost:3001/register \
  -H "Content-Type: application/json" \
  -d '{"display_name": "yourname", "password": "yourpassword"}'
```

Note the `beam_identity` from the response (e.g. `yourname»abc12`).

### 3. Configure phaselink.yaml

Edit `phaselink.yaml` — at minimum set:

```yaml
owner_beam_identity: "yourname»abc12"   # from the registration response
public_url: "https://yourdomain.com"    # or https://localhost for local dev
```

### 4. Start

```bash
docker compose up -d
```

### 5. Unlock the server

On first start (and every restart) the server is locked. All API endpoints return `423 Locked` until the owner authenticates.

**Interactively** (if running with a TTY attached):
```
$ docker compose run phaselink
Beam identity: yourname»abc12
Password: ••••••••
✓ Server unlocked
```

**Via web form** (headless/Docker):
Open `https://yourlocalhost/admin/unlock` in a browser and enter your beam identity and password.

**Via API:**
```bash
curl -X POST https://localhost/admin/unlock \
  -H "Content-Type: application/json" \
  -k -d '{"beam_identity":"yourname»abc12","password":"yourpassword"}'
```

---

## Configuration reference

All settings live in `phaselink.yaml`. Settings marked **live** apply immediately on save (hot-reload); **restart required** settings need a container restart.

| Setting | Default | Reload | Description |
|---|---|---|---|
| `port` | `4000` | restart | Internal listen port |
| `db_path` | `zeeble.db` | restart | SQLite database file path |
| `public_url` | `http://localhost:4000` | live | Base URL shown in invite links |
| `server_name` | `"Zeeble Server"` | live | Display name of this server |
| `owner_beam_identity` | *(empty)* | live | Beam identity of the server owner — required for admin actions |
| `about` | *(none)* | live | Short server description |
| `max_message_length` | `4000` | live | Maximum characters per message |
| `max_upload_size` | `8MB` | live | Maximum file upload size (e.g. `"25MB"`, `"1GB"`) |
| `invites_anyone_can_create` | `true` | live | Allow any member to create invite links |
| `default_invite_expiry_hours` | `0` | live | Default invite expiry in hours (`0` = never) |
| `default_invite_max_uses` | `0` | live | Default max redemptions (`0` = unlimited) |
| `allow_new_members` | `true` | live | Whether new members can join via invite |

**Environment variable overrides** (take precedence over `phaselink.yaml`):

| Variable | Overrides |
|---|---|
| `PORT` | `port` |
| `DB_PATH` | `db_path` |
| `AUTH_SERVER_URL` | Auth server base URL (default: `http://localhost:3001`) |
| `LIVEKIT_API_URL` | LiveKit API bridge URL |
| `OWNER_BEAM_IDENTITY` | `owner_beam_identity` |

---

## REST API

All endpoints except `/health`, `/admin/unlock`, and `/join/:code` require the server to be unlocked. Most require a `Authorization: Bearer <jwt>` header (JWT issued by zeeble-auth).

### Auth

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Server status |
| `GET` | `/admin/unlock` | none | Unlock web form |
| `POST` | `/admin/unlock` | none | Unlock server — body: `{beam_identity, password}` |

### Channels

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/channels` | user JWT | List all channels |
| `POST` | `/channels` | owner JWT | Create a channel — body: `{name, topic?}` |
| `DELETE` | `/channels/:id` | owner JWT | Delete a channel |
| `PATCH` | `/channels/:id` | owner JWT | Rename channel — body: `{name}` |

### Messages

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/channels/:id/messages` | user JWT | Get recent messages (`?before=<id>&limit=50`) |
| `POST` | `/channels/:id/messages` | user JWT | Send a message — body: `{content, attachment_ids?}` |
| `PATCH` | `/messages/:id` | sender JWT | Edit a message — body: `{content}` |
| `DELETE` | `/messages/:id` | sender JWT | Delete a message |

### Files

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/upload` | user JWT | Upload a file (multipart/form-data) — returns `{id, filename, ...}` |
| `GET` | `/attachments/:id` | none | Download an attachment |

### Members

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/members` | user JWT | List online members |
| `PATCH` | `/account/status` | user JWT | Update own status — body: `{status}` |

### Invites

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/invites` | user JWT | List active invites |
| `POST` | `/invites` | user JWT or owner | Create invite — body: `{expiry_hours?, max_uses?}` |
| `GET` | `/invites/:code` | none | Get invite info |
| `DELETE` | `/invites/:code` | owner JWT | Delete invite |
| `POST` | `/invites/:code/redeem` | user JWT | Redeem an invite |
| `GET` | `/join/:code` | none | Human-readable invite landing page |

### Categories & Roles

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/categories` | user JWT | List channel categories |
| `POST` | `/categories` | owner JWT | Create category |
| `PATCH` | `/categories/:id` | owner JWT | Update category |
| `DELETE` | `/categories/:id` | owner JWT | Delete category |
| `GET` | `/roles` | user JWT | List user roles |
| `PUT` | `/roles/:user_id` | owner JWT | Set a role — body: `{role}` |
| `DELETE` | `/roles/:user_id` | owner JWT | Remove a user's role |

### Server

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/server/info` | none | Public server info (name, channels, etc.) |
| `PATCH` | `/server/settings` | owner JWT | Update settings |

### Voice

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/voice/token` | user JWT | Get a LiveKit access token — query: `?room=<name>` |
| `GET` | `/voice/rooms` | user JWT | List active voice rooms |

---

## WebSocket

Connect to `wss://yourdomain.com/ws`. All frames are JSON.

### Client → Server messages

**Authenticate**
```json
{ "type": "auth", "token": "<jwt>" }
```

**Join a channel** (subscribe to its message stream)
```json
{ "type": "join", "token": "<jwt>", "channel_id": "<id>" }
```

**Send a message**
```json
{ "type": "message", "token": "<jwt>", "channel_id": "<id>", "content": "Hello!", "attachment_ids": [] }
```

**Edit a message** (own messages only)
```json
{ "type": "edit_message", "token": "<jwt>", "message_id": 42, "content": "Corrected text" }
```

**Delete a message** (own messages only)
```json
{ "type": "delete_message", "token": "<jwt>", "message_id": 42 }
```

**Leave a channel**
```json
{ "type": "leave", "channel_id": "<id>" }
```

**Ping**
```json
{ "type": "ping" }
```

Tokens are re-validated on every message that requires auth. Since JWTs expire in 15 minutes, clients should refresh and resend the token as needed (the server will send `{"type":"error","message":"Token expired"}` and disconnect if a token is invalid).

### Server → Client messages

| `type` | Fields | Description |
|---|---|---|
| `pong` | — | Reply to ping |
| `message` | `id, channel_id, beam_identity, content, created_at, attachments` | New message |
| `message_edited` | `id, channel_id, content, edited_at` | Message edited |
| `message_deleted` | `id, channel_id` | Message deleted |
| `activated` | `server_id` | Server activation acknowledged |
| `error` | `message` | Error — connection may close after this |

**Bot authentication via WebSocket:** send `"token": "Bot <your_bot_token>"` in any auth-bearing message to connect as a bot identity.

---

## Bot API

Bots are server-side automation accounts managed by the server owner. They authenticate with a long-lived secret token via `Authorization: Bot <token>`.

### Creating a bot

```bash
curl -X POST https://yourdomain.com/bots \
  -H "Authorization: Bearer <owner_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"name": "MyBot"}'
```

Response:
```json
{
  "id": "a3f8...",
  "name": "MyBot",
  "token": "d4e2f1..."
}
```

**The token is shown once — store it securely.** If lost, delete and recreate the bot.

### Bot management endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/bots` | owner JWT | Create bot — body: `{name}` |
| `GET` | `/bots` | owner JWT | List all bots (tokens omitted) |
| `DELETE` | `/bots/:id` | owner JWT | Delete a bot |

### Bot action endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/bot/channels/:id/messages` | Bot token | Send a message — body: `{content}` |
| `GET` | `/bot/channels/:id/messages` | Bot token | Read last 50 messages |

Bot messages appear in channels as `bot:<BotName>` and are broadcast in real time to all connected WebSocket clients.

### Example: sending a message as a bot

```bash
curl -X POST https://yourdomain.com/bot/channels/CHANNEL_ID/messages \
  -H "Authorization: Bot d4e2f1..." \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello from MyBot!"}'
```

### Bot WebSocket usage

Bots can connect to the WebSocket and authenticate using their token:

```json
{ "type": "auth", "token": "Bot d4e2f1..." }
```

After authenticating, a bot can join channels and send/receive messages the same way a user does.

---

## Beam identity format

Zeeble uses *beam identities* instead of user IDs. The format is:

```
displayName<separator>tag
```

| Account type | Separator | Example |
|---|---|---|
| Primary | `»` | `alice»k4mx9` |
| Alt | `§` | `alice§ab1cd` |
| Child | `‡` | `alice‡xyz99` |
| Bot | `λ` | `MyBotλ00001` |

Display names are 1–12 characters, lowercase. Tags are 5 random alphanumeric characters assigned at registration. Bot identities in messages are formatted as `bot:<BotName>` (e.g. `bot:MyBot`).

---

## Development

### Running without Docker

```bash
# Start zeeble-auth separately (see its README)

# In phaselink/
cargo run
```

The server reads `phaselink.yaml` from the working directory (or `/data/phaselink.yaml` in Docker).

### Building

```bash
cd phaselink
cargo build --release
```

### Database

PhaseLink uses SQLite. The database is created automatically on first run at the path set by `db_path` in config. Schema migrations run automatically on startup.

### Logs

Set `RUST_LOG=zeeble_server=debug` for verbose output. Default: `zeeble_server=info`.

---

## Caddy TLS configuration

The zeeble-gate repository includes a `Caddyfile` that handles:
- Automatic HTTPS (self-signed in dev, Let's Encrypt in production)
- WebSocket upgrade headers for `/ws` and `/rtc`
- All routing to backend services
- CORS headers for desktop clients
- 50MB upload limit

No manual certificate management needed!
