use serde::{Deserialize, Serialize};

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
    pub redis_url: Option<String>,

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
    pub banner_attachment_id: Option<i64>,

    // ── Membership requirements ─────────────────
    pub require_email_verified: Option<bool>,
    pub require_phone_verified: Option<bool>,
    pub require_age_18_plus: Option<bool>,
    pub age_proof_methods: Option<Vec<String>>,

    // ── Access control ──────────────────────────
    /// Allow JWT accounts flagged as bots by the auth server. Default: true.
    pub allow_bots: Option<bool>,
    /// Minimum account age in days (requires `account_created_at` claim in JWT). 0 = off.
    pub min_account_age_days: Option<u64>,
    /// If non-empty, ONLY these beam identities may join (whitelist).
    pub identity_whitelist: Option<Vec<String>>,
    /// Beam identities that are always denied, even with a valid invite (blacklist).
    pub identity_blacklist: Option<Vec<String>>,
    /// If non-empty, only users whose verified email matches one of these domains may join.
    pub allowed_email_domains: Option<Vec<String>>,
    /// Maximum number of members. 0 = unlimited.
    pub max_members: Option<u64>,
}

/// Startup-only config (never changes after boot).
pub struct Config {
    pub port: u16,
    pub db_path: String,
    pub auth_server_url: String,
    pub redis_url: String,
    /// Path to phaselink.yaml that was loaded (None if file not found).
    /// Settings changes made via the API are written back here.
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
    /// Redis maxmemory limit applied at startup via CONFIG SET.
    /// "0" or empty = no limit (Redis default).  Accepts human-readable units
    /// (e.g. "512MB", "2GB").  When set, the eviction policy is also set to
    /// allkeys-lru so cache entries are dropped before hard OOM.
    pub redis_max_memory: String,
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
    pub banner_attachment_id: Option<i64>,
    /// Comma-separated list of allowed CORS origins. If empty when evaluated,
    /// the resolver falls back to `public_url` only.
    pub allowed_origins: Vec<String>,
    // ── Membership requirements ───────────────────────────────────────────────
    pub require_email_verified: bool,
    pub require_phone_verified: bool,
    pub require_age_18_plus: bool,
    pub age_proof_methods: Vec<String>,

    // ── Access control ────────────────────────────────────────────────────────
    /// Allow bot-flagged JWT accounts. Default true.
    pub allow_bots: bool,
    /// Minimum account age in days. 0 = no requirement.
    pub min_account_age_days: u64,
    /// Whitelist: if non-empty, only listed identities can join.
    pub identity_whitelist: Vec<String>,
    /// Blacklist: these identities are always denied.
    pub identity_blacklist: Vec<String>,
    /// Email domain restriction: if non-empty, only these domains are accepted.
    pub allowed_email_domains: Vec<String>,
    /// Maximum member count. 0 = unlimited.
    pub max_members: u64,
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

        let banner_attachment_id = std::env::var("BANNER_ATTACHMENT_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.banner_attachment_id);

        // CORS allowed origins: env var (comma-separated) overrides nothing; always present.
        let allowed_origins = std::env::var("ALLOWED_ORIGINS")
            .ok()
            .map(|s| parse_list(&s))
            .unwrap_or_default();

        let require_email_verified = std::env::var("REQUIRE_EMAIL_VERIFIED")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
            .or(file.require_email_verified)
            .unwrap_or(false);

        let require_phone_verified = std::env::var("REQUIRE_PHONE_VERIFIED")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
            .or(file.require_phone_verified)
            .unwrap_or(false);

        let require_age_18_plus = std::env::var("REQUIRE_AGE_18_PLUS")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
            .or(file.require_age_18_plus)
            .unwrap_or(false);

        let age_proof_methods = std::env::var("AGE_PROOF_METHODS")
            .ok()
            .map(|s| parse_list(&s))
            .or_else(|| file.age_proof_methods.clone())
            .unwrap_or_else(|| vec!["email".into(), "id".into(), "phone".into()]);

        let allow_bots = std::env::var("ALLOW_BOTS")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            })
            .or(file.allow_bots)
            .unwrap_or(true);

        let min_account_age_days = std::env::var("MIN_ACCOUNT_AGE_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.min_account_age_days)
            .unwrap_or(0);

        let identity_whitelist = std::env::var("IDENTITY_WHITELIST")
            .ok()
            .map(|s| parse_list(&s))
            .or_else(|| file.identity_whitelist.clone())
            .unwrap_or_default();

        let identity_blacklist = std::env::var("IDENTITY_BLACKLIST")
            .ok()
            .map(|s| parse_list(&s))
            .or_else(|| file.identity_blacklist.clone())
            .unwrap_or_default();

        let allowed_email_domains = std::env::var("ALLOWED_EMAIL_DOMAINS")
            .ok()
            .map(|s| parse_list(&s))
            .or_else(|| file.allowed_email_domains.clone())
            .unwrap_or_default();

        let max_members = std::env::var("MAX_MEMBERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(file.max_members)
            .unwrap_or(0);

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
            banner_attachment_id,
            allowed_origins,
            require_email_verified,
            require_phone_verified,
            require_age_18_plus,
            age_proof_methods,
            allow_bots,
            min_account_age_days,
            identity_whitelist,
            identity_blacklist,
            allowed_email_domains,
            max_members,
        }
    }
}

impl Config {
    /// Load startup config.
    /// Priority (highest → lowest): real env vars → .env file → phaselink.yaml.
    /// Writes settings changes made via the API back to phaselink.yaml.
    pub fn load() -> (Self, ConfigFile) {
        let _ = dotenvy::dotenv();

        // Try to load phaselink.yaml (or CONFIG_PATH override).
        let yaml_path = std::env::var("CONFIG_PATH")
            .unwrap_or_else(|_| "/data/phaselink.yaml".to_string());
        let (file, config_path) = match std::fs::read_to_string(&yaml_path) {
            Ok(contents) => {
                let parsed: ConfigFile = serde_yaml::from_str(&contents).unwrap_or_default();
                (parsed, Some(yaml_path))
            }
            Err(_) => (ConfigFile::default(), None),
        };

        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(4000);

        let db_path = std::env::var("DB_PATH")
            .ok()
            .unwrap_or_else(|| "zeeble.db".into());

        let auth_server_url = std::env::var("AUTH_SERVER_URL")
            .ok()
            .unwrap_or_else(|| "https://api.zeeble.xyz".into());

        let redis_url = std::env::var("REDIS_URL")
            .ok()
            .unwrap_or_else(|| "redis://127.0.0.1:6379".into());

        let trusted_proxies = std::env::var("TRUSTED_PROXIES")
            .ok()
            .map(|s| parse_list(&s))
            .unwrap_or_default();

        let require_tls = std::env::var("REQUIRE_TLS")
            .ok()
            .map(|s| matches!(s.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);

        let attachments_dir = std::env::var("ATTACHMENTS_DIR")
            .ok()
            .filter(|s| !s.is_empty());

        let attachment_max_age_days = std::env::var("ATTACHMENT_MAX_AGE_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let redis_max_memory = std::env::var("REDIS_MAX_MEMORY")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "0".to_string());

        (
            Self {
                port,
                db_path,
                auth_server_url,
                redis_url,
                config_path,
                trusted_proxies,
                require_tls,
                attachments_dir,
                attachment_max_age_days,
                redis_max_memory,
            },
            file,
        )
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Convert the live in-memory settings back into a ConfigFile suitable for
/// serialising to phaselink.yaml.  Startup-only fields (port, db_path, …)
/// are intentionally left as None so they stay in the .env file.
pub fn settings_to_config_file(s: &Settings) -> ConfigFile {
    let max_upload_size = {
        let b = s.max_upload_bytes;
        if b % (1024 * 1024 * 1024) == 0 { format!("{}GB", b / (1024 * 1024 * 1024)) }
        else if b % (1024 * 1024) == 0    { format!("{}MB", b / (1024 * 1024)) }
        else if b % 1024 == 0             { format!("{}KB", b / 1024) }
        else                              { format!("{}B", b) }
    };
    ConfigFile {
        // Startup-only — keep in .env, not yaml
        port: None,
        db_path: None,
        auth_server_url: None,
        redis_url: None,
        // Hot-reloadable
        server_name:                Some(s.server_name.clone()),
        public_url:                 Some(s.public_url.clone()),
        about:                      s.about.clone(),
        max_message_length:         Some(s.max_message_length),
        max_upload_size:            Some(max_upload_size),
        invites_anyone_can_create:  Some(s.invites_anyone_can_create),
        default_invite_expiry_hours: Some(s.default_invite_expiry_hours),
        default_invite_max_uses:    Some(s.default_invite_max_uses),
        allow_new_members:          Some(s.allow_new_members),
        logo_attachment_id:         s.logo_attachment_id,
        banner_attachment_id:       s.banner_attachment_id,
        require_email_verified:     Some(s.require_email_verified),
        require_phone_verified:     Some(s.require_phone_verified),
        require_age_18_plus:        Some(s.require_age_18_plus),
        age_proof_methods:          Some(s.age_proof_methods.clone()),
        allow_bots:                 Some(s.allow_bots),
        min_account_age_days:       Some(s.min_account_age_days),
        identity_whitelist:  if s.identity_whitelist.is_empty()   { None } else { Some(s.identity_whitelist.clone()) },
        identity_blacklist:  if s.identity_blacklist.is_empty()   { None } else { Some(s.identity_blacklist.clone()) },
        allowed_email_domains: if s.allowed_email_domains.is_empty() { None } else { Some(s.allowed_email_domains.clone()) },
        max_members:                Some(s.max_members),
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
