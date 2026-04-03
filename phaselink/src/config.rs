use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "phaselink.yaml";

/// The canonical name for the default role — used across permissions, roles, and seeding.
pub const EVERYONE_ROLE: &str = "@everyone";

/// Rate limit constants for bot message sending.
pub const BOT_MSG_MAX_PER_WINDOW: u32 = 60;
pub const BOT_MSG_WINDOW_SECS: u64 = 60;

/// Parse a comma-separated list of origins/URLs/IPs/CIDRs into a Vec<String>.
/// Used for TRUSTED_PROXIES and ALLOWED_ORIGINS.
pub fn parse_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Parse human-readable byte sizes like "8MB", "500KB", "2GB", "1024".
/// Case-insensitive. Returns None if the string can't be parsed.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_part, unit) = match s.find(|c: char| c.is_alphabetic()) {
        Some(i) => (&s[..i], s[i..].trim().to_uppercase()),
        None => (s, String::new()),
    };
    let num: f64 = num_part.trim().parse().ok()?;
    if num < 0.0 {
        return None;
    }
    if num < 0.0 {
        return None;
    }
    let multiplier: u64 = match unit.as_str() {
        "" | "B" => 1,
        "KB" => 1_024,
        "MB" => 1_024 * 1_024,
        "GB" => 1_024 * 1_024 * 1_024,
        "TB" => 1_024 * 1_024 * 1_024 * 1_024,
        _ => return None,
    };
    Some((num * multiplier as f64) as u64)
}

/// Raw deserialized shape of `phaselink.yaml`.
/// All fields optional — resolution happens in `Config::load` / `Settings::from_file`.
#[derive(Deserialize, Default, Clone, Serialize)]
pub struct ConfigFile {
    // ── Startup-only ──────────────────────────────
    pub port: Option<u16>,
    pub db_path: Option<String>,
    pub auth_server_url: Option<String>,
    pub livekit_api_url: Option<String>,
    pub livekit_server_url: Option<String>,
    pub livekit_api_key: Option<String>,
    pub livekit_api_secret: Option<String>,

    // ── Hot-reloadable ────────────────────────────
    pub server_name: Option<String>,
    pub public_url: Option<String>,
    pub about: Option<String>,
    pub max_message_length: Option<u64>,
    pub max_upload_size: Option<String>,
    pub invites_anyone_can_create: Option<bool>,
    pub default_invite_expiry_hours: Option<u64>,
    pub default_invite_max_uses: Option<u64>,
    pub allow_new_members: Option<bool>,
    pub logo_attachment_id: Option<i64>,
}

/// Startup-only config (never changes after boot).
pub struct Config {
    pub port: u16,
    pub db_path: String,
    pub auth_server_url: String,
    pub livekit_api_url: String,
    /// Internal URL of the LiveKit server (unused; clients connect directly via
    /// `livekit_url` from the token response). Kept for backwards compatibility.
    pub livekit_server_url: String,
    /// LiveKit API secret (startup-only, used for validation warning at boot).
    pub livekit_api_secret: String,
    /// Path to the config file that was loaded (or None if not found).
    pub config_path: Option<String>,
    /// Comma-separated list of trusted proxy IPs/CIDRs. Only when the connecting
    /// socket IP matches one of these will `X-Forwarded-For` / `X-Real-IP` be
    /// honoured for rate-limiting. Empty = never trust those headers.
    pub trusted_proxies: Vec<String>,
    /// When true, `/admin/unlock` POST and `/join/:code` POST are rejected
    /// unless the request has `x-forwarded-proto: https` or a secure socket.
    pub require_tls: bool,
    /// Directory where uploaded files are stored on disk. When empty/None,
    /// files fall back to the legacy SQLite BLOB storage.
    pub attachments_dir: Option<String>,
    /// Auto-delete attachments older than N days. 0 = keep forever.
    pub attachment_max_age_days: u64,
}

/// Hot-reloadable settings — read with `state.settings.read().await`.
#[derive(Clone, Debug)]
pub struct Settings {
    pub server_name: String,
    pub public_url: String,
    pub owner_beam_identity: String,
    pub about: Option<String>,
    pub max_message_length: u64,
    pub max_upload_bytes: u64,
    pub invites_anyone_can_create: bool,
    pub default_invite_expiry_hours: u64,
    pub default_invite_max_uses: u64,
    pub allow_new_members: bool,
    pub logo_attachment_id: Option<i64>,
    /// Comma-separated list of allowed CORS origins. If empty when evaluated,
    /// the resolver falls back to `public_url` only.
    pub allowed_origins: Vec<String>,
}

impl Settings {
    pub fn from_file(file: &ConfigFile, port: u16) -> Self {
        let public_url_default = format!("http://localhost:{port}");

        // Owner identity is stored in the DB (set on first unlock).
        // OWNER_BEAM_IDENTITY env var can override for emergency access.
        let owner_beam_identity = std::env::var("OWNER_BEAM_IDENTITY").unwrap_or_default();

        let max_upload_bytes = std::env::var("MAX_UPLOAD_SIZE")
            .ok()
            .or_else(|| file.max_upload_size.clone())
            .and_then(|s| parse_size(&s))
            .unwrap_or(8 * 1024 * 1024); // 8 MB default

        let about = std::env::var("ABOUT")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| file.about.clone());

        let max_message_length = std::env::var("MAX_MESSAGE_LENGTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.max_message_length)
            .unwrap_or(4000);

        let invites_anyone_can_create = std::env::var("INVITES_ANYONE_CAN_CREATE")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
            .or(file.invites_anyone_can_create)
            .unwrap_or(true);

        let default_invite_expiry_hours = std::env::var("DEFAULT_INVITE_EXPIRY_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.default_invite_expiry_hours)
            .unwrap_or(0);

        let default_invite_max_uses = std::env::var("DEFAULT_INVITE_MAX_USES")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.default_invite_max_uses)
            .unwrap_or(0);

        let allow_new_members = std::env::var("ALLOW_NEW_MEMBERS")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
            .or(file.allow_new_members)
            .unwrap_or(true);

        let logo_attachment_id = std::env::var("LOGO_ATTACHMENT_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.logo_attachment_id);

        // CORS allowed origins: env var (comma-separated) overrides nothing; always present.
        let allowed_origins = std::env::var("ALLOWED_ORIGINS")
            .ok()
            .map(|s| parse_list(&s))
            .unwrap_or_default();

        Self {
            server_name: std::env::var("SERVER_NAME")
                .ok()
                .or_else(|| file.server_name.clone())
                .unwrap_or_else(|| "Zeeble Server".into()),

            public_url: std::env::var("PUBLIC_URL")
                .ok()
                .or_else(|| file.public_url.clone())
                .unwrap_or(public_url_default),

            owner_beam_identity,
            about,
            max_message_length,
            max_upload_bytes,
            invites_anyone_can_create,
            default_invite_expiry_hours,
            default_invite_max_uses,
            allow_new_members,
            logo_attachment_id,
            allowed_origins,
        }
    }
}

const CONFIG_EXAMPLE: &str = r#"# ─────────────────────────────────────────────────────────────────────────────
#  PHASELINK  —  phaselink.yaml
#
#  Most settings marked "live" are applied immediately when you save this file.
#  Settings marked "restart required" only take effect after a server restart.
#  Environment variables always override values in this file.
# ─────────────────────────────────────────────────────────────────────────────

# ── Network ──────────────────────────────────────────────────────────────────
# [restart required]
port: 4000

# Publicly reachable base URL — used in invite links and the join page.
# Defaults to http://localhost:<port> if not set.
# [live]
# public_url: "https://zeeble-chat.example.com"

# ── Storage ───────────────────────────────────────────────────────────────────
# [restart required]
db_path: "zeeble.db"

# Maximum size for a single file upload.
# Supports human-readable units: KB, MB, GB  (e.g. "25MB", "1GB")
# [live]
max_upload_size: "8MB"

# ── Chat ──────────────────────────────────────────────────────────────────────
# Maximum number of characters in a single message.
# [live]
max_message_length: 4000

# ── Invites ───────────────────────────────────────────────────────────────────
# Allow any authenticated user to create invite links.
# Set to false to restrict invite creation to the server owner only.
# [live]
invites_anyone_can_create: true

# Default expiry for new invites, in hours. 0 = never expires.
# [live]
default_invite_expiry_hours: 0

# Default max redemptions for new invites. 0 = unlimited.
# [live]
default_invite_max_uses: 0

# Set to false to stop new members from joining via invite links.
# [live]
allow_new_members: true

# ── Identity ──────────────────────────────────────────────────────────────────
# Display name shown on invite pages and in /server/info.
# [live]
server_name: "Zeeble Server"

# A short description of this server, shown in /server/info.
# [live]
# about: "A chill place to hang out."
"#;

impl Config {
    /// Load startup config with the following priority (highest → lowest):
    ///   1. Environment variables
    ///   2. `phaselink.yaml` (if present)
    ///   3. Built-in defaults
    pub fn load() -> (Self, ConfigFile) {
        // Load .env file if present (lowest priority — real env vars win)
        let _ = dotenvy::dotenv();

        // Try to read and parse phaselink.yaml
        let (file, config_path) = match std::fs::read_to_string(CONFIG_FILE) {
            Ok(contents) => {
                let parsed: ConfigFile = serde_yaml::from_str(&contents)
                    .unwrap_or_else(|e| panic!("Invalid {CONFIG_FILE}: {e}"));
                (parsed, Some(CONFIG_FILE.to_string()))
            }
            Err(_) => {
                // File absent — write an example so the user knows what's available
                if let Err(e) = std::fs::write(CONFIG_FILE, CONFIG_EXAMPLE) {
                    eprintln!("Warning: could not write example {CONFIG_FILE}: {e}");
                }
                (ConfigFile::default(), None)
            }
        };

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .or(file.port)
            .unwrap_or(4000);

        let db_path = std::env::var("DB_PATH")
            .ok()
            .or_else(|| file.db_path.clone())
            .unwrap_or_else(|| "zeeble.db".into());

        let auth_server_url = std::env::var("AUTH_SERVER_URL")
            .ok()
            .or_else(|| file.auth_server_url.clone())
            .unwrap_or_else(|| "http://localhost:3001".into());

        let livekit_api_url = std::env::var("LIVEKIT_API_URL")
            .ok()
            .or_else(|| file.livekit_api_url.clone())
            .unwrap_or_else(|| "http://localhost:3000".into());

        let livekit_server_url = std::env::var("LIVEKIT_SERVER_URL")
            .ok()
            .or_else(|| file.livekit_server_url.clone())
            .unwrap_or_else(|| "http://livekit:7880".into());

        let livekit_api_secret = std::env::var("LIVEKIT_API_SECRET")
            .ok()
            .or_else(|| file.livekit_api_secret.clone())
            .unwrap_or_default();

        let trusted_proxies = std::env::var("TRUSTED_PROXIES")
            .ok()
            .map(|s| parse_list(&s))
            .unwrap_or_default();

        let require_tls = std::env::var("REQUIRE_TLS")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                _ => Some(false),
            })
            .unwrap_or(false);

        let attachments_dir = std::env::var("ATTACHMENTS_DIR")
            .ok()
            .filter(|s| !s.is_empty());

        let attachment_max_age_days = std::env::var("ATTACHMENT_MAX_AGE_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        (
            Self {
                port,
                db_path,
                auth_server_url,
                livekit_api_url,
                livekit_server_url,
                livekit_api_secret,
                config_path,
                trusted_proxies,
                require_tls,
                attachments_dir,
                attachment_max_age_days,
            },
            file,
        )
    }
}

// =============================================================================
// Phase 0 — Unit tests for config.rs
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_list ────────────────────────────────────────────────────────

    #[test]
    fn parse_list_basic() {
        let v = parse_list("a,b,c");
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_list_trims_whitespace() {
        let v = parse_list(" a ,  b , c ");
        assert_eq!(v, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_list_skips_empty_elements() {
        let v = parse_list("a,,b,,");
        assert_eq!(v, vec!["a", "b"]);
    }

    #[test]
    fn parse_list_single_element() {
        let v = parse_list("only-one");
        assert_eq!(v, vec!["only-one"]);
    }

    #[test]
    fn parse_list_empty_string() {
        let v = parse_list("");
        assert!(v.is_empty());
    }

    #[test]
    fn parse_list_commas_only() {
        let v = parse_list(",,,");
        assert!(v.is_empty());
    }

    // ── parse_size ───────────────────────────────────────────────────────

    #[test]
    fn parse_size_bytes() {
        assert_eq!(parse_size("100"), Some(100));
        assert_eq!(parse_size("0"), Some(0));
    }

    #[test]
    fn parse_size_b_unit() {
        assert_eq!(parse_size("512B"), Some(512));
        assert_eq!(parse_size("512b"), Some(512)); // case-insensitive
    }

    #[test]
    fn parse_size_kilobytes() {
        assert_eq!(parse_size("1KB"), Some(1_024));
        assert_eq!(parse_size("2kb"), Some(2_048));
    }

    #[test]
    fn parse_size_megabytes() {
        assert_eq!(parse_size("1MB"), Some(1_024 * 1_024));
        assert_eq!(parse_size("8MB"), Some(8 * 1_024 * 1_024));
    }

    #[test]
    fn parse_size_gigabytes() {
        assert_eq!(parse_size("1GB"), Some(1_024 * 1_024 * 1_024));
        assert_eq!(parse_size("2GB"), Some(2 * 1_024 * 1_024 * 1_024));
    }

    #[test]
    fn parse_size_terabytes() {
        assert_eq!(parse_size("1TB"), Some(1_024 * 1_024 * 1_024 * 1_024));
    }

    #[test]
    fn parse_size_float_values() {
        assert_eq!(parse_size("1.5GB"), Some((1.5 * 1_024.0 * 1_024.0 * 1_024.0) as u64));
        assert_eq!(parse_size("0.5MB"), Some((0.5 * 1_024.0 * 1_024.0) as u64));
    }

    #[test]
    fn parse_size_with_spaces() {
        assert_eq!(parse_size(" 8MB "), Some(8 * 1_024 * 1_024));
        assert_eq!(parse_size("8  MB"), Some(8 * 1_024 * 1_024));
    }

    #[test]
    fn parse_size_invalid() {
        assert!(parse_size("abc").is_none());
        assert!(parse_size("8XB").is_none());
        assert!(parse_size("-5MB").is_none());
    }

    // ── ip_matches (CIDR) — tested in main.rs where ip_matches is defined

    // ── generate_invite_code — tested in main.rs where the function is defined

    // ── Constants ────────────────────────────────────────────────────────

    #[test]
    fn everyone_role_value() {
        assert_eq!(EVERYONE_ROLE, "@everyone");
    }

    #[test]
    fn bot_rate_limit_constants() {
        assert_eq!(BOT_MSG_MAX_PER_WINDOW, 60);
        assert_eq!(BOT_MSG_WINDOW_SECS, 60);
    }

    // ── generate_invite_code — tested in main.rs where the function is defined

    // ── Settings::from_file (defaults) ─────────────────────────────────

    #[test]
    fn settings_defaults() {
        let file = ConfigFile::default();
        let s = Settings::from_file(&file, 4000);
        assert_eq!(s.server_name, "Zeeble Server");
        assert_eq!(s.public_url, "http://localhost:4000");
        assert_eq!(s.max_message_length, 4000);
        assert_eq!(s.max_upload_bytes, 8 * 1024 * 1_024);
        assert!(s.invites_anyone_can_create);
        assert_eq!(s.default_invite_expiry_hours, 0);
        assert_eq!(s.default_invite_max_uses, 0);
        assert!(s.allow_new_members);
        assert!(s.logo_attachment_id.is_none());
    }

    #[test]
    fn settings_port_affects_public_url_default() {
        let file = ConfigFile::default();
        let s = Settings::from_file(&file, 8080);
        assert_eq!(s.public_url, "http://localhost:8080");
    }
}
