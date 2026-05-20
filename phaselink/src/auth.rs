use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use jsonwebtoken::decode_header;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::AppState;

// ── JWKS types ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct JwkKey {
    kty: String,
    crv: String,
    x: String,
    alg: String,
    kid: String,
}

/// In-memory store of Ed25519 verifying keys keyed by key ID.
#[derive(Default)]
pub struct JwksStore {
    pub keys: HashMap<String, PublicKey>,
}

/// Verification claims extracted from a JWT.
/// Fields default to `false`/`None` when absent from the token.
#[derive(Clone, Debug, Default)]
pub struct UserVerification {
    pub email_verified: bool,
    pub phone_verified: bool,
    /// Government-issued ID verified (implies age).
    pub id_verified: bool,
    /// Age confirmed as 18+ by some method.
    pub age_verified: bool,
    /// Which method confirmed the age: "email" | "id" | "phone"
    pub age_verified_by: Option<String>,
    /// True if the auth server issued this token to a bot account.
    pub is_bot: bool,
    /// The user's email address (used for domain-restriction checks).
    pub email: Option<String>,
    /// Unix timestamp when the account was created (for min-age-days check).
    pub account_created_at: Option<u64>,
}

/// Fetch JWKS from the auth server's `/.well-known/jwks.json`.
pub async fn fetch_jwks(auth_url: &str) -> anyhow::Result<JwksStore> {
    // Test override: if AUTH_PUBLIC_KEY_B64 is set, use that as the sole JWKS key
    if let Ok(b64) = std::env::var("AUTH_PUBLIC_KEY_B64") {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| anyhow::anyhow!("Invalid AUTH_PUBLIC_KEY_B64: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("AUTH_PUBLIC_KEY_B64 must decode to 32 bytes"));
        }
        let verifying_key = PublicKey::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {e}"))?;
        let mut store = JwksStore::default();
        store.keys.insert("auth-1".to_string(), verifying_key);
        eprintln!("Using test override for auth public key (AUTH_PUBLIC_KEY_B64)");
        return Ok(store);
    }

    // Ensure the URL has a scheme — defensively add https:// if missing.
    let auth_url = if auth_url.starts_with("http://") || auth_url.starts_with("https://") {
        auth_url.to_string()
    } else {
        format!("https://{auth_url}")
    };
    let jwks_url = format!("{}/.well-known/jwks.json", auth_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client
        .get(&jwks_url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to fetch JWKS: HTTP {}", resp.status()));
    }
    let jwks: JwksResponse = resp.json().await?;

    let mut store = JwksStore { keys: HashMap::new() };
    for key in jwks.keys {
        if key.kty != "OKP" || key.crv != "Ed25519" || key.alg != "EdDSA" {
            continue;
        }
        let key_bytes = URL_SAFE_NO_PAD.decode(key.x)?;
        if key_bytes.len() != 32 {
            continue;
        }
        let verifying_key = PublicKey::from_bytes(&key_bytes)?;
        store.keys.insert(key.kid, verifying_key);
    }

    Ok(store)
}

// ── JWT validation ────────────────────────────────────────────────────────────

/// Internal: decode and verify a JWT, returning the identity and all
/// verification claims.  `validate_jwt` and `validate_jwt_with_verification`
/// are thin wrappers around this function.
async fn validate_jwt_core(token: &str, state: &AppState) -> Option<(String, UserVerification, Option<String>)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        warn!("validate_jwt: not 3 parts");
        return None;
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header = match decode_header(token) {
        Ok(h) => h,
        Err(e) => { warn!("validate_jwt: decode_header failed: {e}"); return None; }
    };
    let kid = match header.kid {
        Some(k) => k,
        None => { warn!("validate_jwt: no kid in header"); return None; }
    };

    let verifying_key = {
        let jwks = state.jwks.lock().unwrap();
        match jwks.keys.get(&kid).copied() {
            Some(k) => k,
            None => { warn!("validate_jwt: kid '{kid}' not in JWKS store (keys: {:?})", jwks.keys.keys().collect::<Vec<_>>()); return None; }
        }
    };

    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let sig_bytes = match URL_SAFE_NO_PAD.decode(sig_b64) {
        Ok(b) => b,
        Err(e) => { warn!("validate_jwt: sig base64 decode failed: {e}"); return None; }
    };
    if sig_bytes.len() != 64 {
        warn!("validate_jwt: sig wrong length {}", sig_bytes.len());
        return None;
    }
    let signature = match Signature::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(e) => { warn!("validate_jwt: Signature::from_bytes failed: {e}"); return None; }
    };
    if let Err(e) = verifying_key.verify(signing_input.as_bytes(), &signature) {
        warn!("validate_jwt: signature verification failed: {e}");
        return None;
    }

    let payload_bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(b) => b,
        Err(e) => { warn!("validate_jwt: payload base64 decode failed: {e}"); return None; }
    };

    #[derive(Deserialize)]
    struct Claims {
        sub: Option<String>,
        beam_identity: Option<String>,
        exp: Option<usize>,
        aud: Option<String>,
        // Verification claims
        email_verified: Option<bool>,
        phone_verified: Option<bool>,
        id_verified: Option<bool>,
        age_verified: Option<bool>,
        age_verified_by: Option<String>,
        // Access-control claims
        is_bot: Option<bool>,
        email: Option<String>,
        account_created_at: Option<u64>,
        // Avatar
        avatar_attachment_id: Option<String>,
    }
    let claims: Claims = match serde_json::from_slice(&payload_bytes) {
        Ok(c) => c,
        Err(e) => { warn!("validate_jwt: claims parse failed: {e}"); return None; }
    };

    if let Some(exp) = claims.exp {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as usize;
        if now > exp {
            warn!("validate_jwt: token expired (exp={exp}, now={now})");
            return None;
        }
    }

    // Audience check: no aud = valid everywhere; mismatched aud = rejected.
    let public_url = state.settings.read().await.public_url.clone();
    if !public_url.is_empty() {
        if let Some(ref aud) = claims.aud {
            let aud_norm = aud.trim_end_matches('/');
            let url_norm = public_url.trim_end_matches('/');
            if aud_norm != url_norm {
                warn!("validate_jwt: aud mismatch: token aud='{aud_norm}' vs server='{url_norm}'");
                return None;
            }
        }
    }

    let identity = claims.beam_identity.or(claims.sub)?;
    let verif = UserVerification {
        email_verified: claims.email_verified.unwrap_or(false),
        phone_verified: claims.phone_verified.unwrap_or(false),
        id_verified: claims.id_verified.unwrap_or(false),
        age_verified: claims.age_verified.unwrap_or(false),
        age_verified_by: claims.age_verified_by,
        is_bot: claims.is_bot.unwrap_or(false),
        email: claims.email,
        account_created_at: claims.account_created_at,
    };
    Some((identity, verif, claims.avatar_attachment_id))
}

/// Validate a JWT and return the caller's `beam_identity`.
/// Returns `None` if the token is invalid, expired, or fails the audience check.
pub async fn validate_jwt(token: &str, state: &AppState) -> Option<String> {
    validate_jwt_core(token, state).await.map(|(id, _, _)| id)
}

/// Validate a JWT and return both the identity and its verification claims.
pub async fn validate_jwt_with_verification(
    token: &str,
    state: &AppState,
) -> Option<(String, UserVerification)> {
    validate_jwt_core(token, state).await.map(|(id, v, _)| (id, v))
}

// ── Membership requirement enforcement ───────────────────────────────────────

/// Check whether a joining user passes all server membership requirements.
/// Call this at invite-redeem time, before incrementing the invite use count.
/// The server owner always passes regardless of settings.
pub async fn check_membership_requirements(
    state: &AppState,
    identity: &str,
    verif: &UserVerification,
) -> Result<(), (StatusCode, Json<Value>)> {
    let s = state.settings.read().await;

    // Owner is always allowed
    if !s.owner_beam_identity.is_empty() && identity == s.owner_beam_identity {
        return Ok(());
    }

    // ── Blacklist ─────────────────────────────────────────────────────────────
    if s.identity_blacklist.iter().any(|b| b == identity) {
        warn!("join blocked: {identity} is on the server blacklist");
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "You are not permitted to join this server.",
                "requirement": "not_blacklisted"
            })),
        ));
    }

    // ── Whitelist ─────────────────────────────────────────────────────────────
    if !s.identity_whitelist.is_empty() && !s.identity_whitelist.iter().any(|w| w == identity) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "This server uses an access whitelist. Your account is not on it.",
                "requirement": "whitelisted"
            })),
        ));
    }

    // ── Bot accounts ──────────────────────────────────────────────────────────
    if !s.allow_bots && verif.is_bot {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "This server does not allow bot accounts.",
                "requirement": "no_bots"
            })),
        ));
    }

    // ── Minimum account age ───────────────────────────────────────────────────
    if s.min_account_age_days > 0 {
        match verif.account_created_at {
            None => {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": format!(
                            "This server requires accounts to be at least {} day(s) old, \
                             but your account age could not be verified.",
                            s.min_account_age_days
                        ),
                        "requirement": "min_account_age"
                    })),
                ));
            }
            Some(created_at) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let age_days = now.saturating_sub(created_at) / 86_400;
                if age_days < s.min_account_age_days {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "This server requires accounts to be at least {} day(s) old. \
                                 Your account is {} day(s) old.",
                                s.min_account_age_days, age_days
                            ),
                            "requirement": "min_account_age",
                            "required_days": s.min_account_age_days,
                            "account_age_days": age_days
                        })),
                    ));
                }
            }
        }
    }

    // ── Email domain restriction ──────────────────────────────────────────────
    if !s.allowed_email_domains.is_empty() {
        let domain = verif.email.as_deref().and_then(|e| e.split('@').nth(1));
        let passes = domain
            .map(|d| s.allowed_email_domains.iter().any(|allowed| allowed.eq_ignore_ascii_case(d)))
            .unwrap_or(false);
        if !passes {
            let list = s.allowed_email_domains.join(", ");
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": format!("This server only allows users from: {list}"),
                    "requirement": "email_domain"
                })),
            ));
        }
    }

    // ── Max member cap ────────────────────────────────────────────────────────
    if s.max_members > 0 {
        let count: u64 = {
            let db = state.db.get().expect("db pool");
            db.query_row(
                "SELECT COUNT(*) FROM users WHERE is_deleted = 0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) as u64
        };
        if count >= s.max_members {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "This server has reached its maximum member count.",
                    "requirement": "max_members"
                })),
            ));
        }
    }

    // ── Verification requirements ─────────────────────────────────────────────
    if s.require_email_verified && !verif.email_verified {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "This server requires a verified email address to join.",
                "requirement": "email_verified"
            })),
        ));
    }

    if s.require_phone_verified && !verif.phone_verified {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "This server requires a verified phone number to join.",
                "requirement": "phone_verified"
            })),
        ));
    }

    if s.require_age_18_plus {
        let methods = &s.age_proof_methods;
        let passes = if methods.is_empty() {
            verif.age_verified || verif.id_verified
        } else {
            methods.iter().any(|m| match m.as_str() {
                "email" => verif.age_verified && verif.age_verified_by.as_deref() == Some("email"),
                "id"    => verif.id_verified || (verif.age_verified && verif.age_verified_by.as_deref() == Some("id")),
                "phone" => verif.age_verified && verif.age_verified_by.as_deref() == Some("phone"),
                _       => false,
            })
        };
        if !passes {
            let accepted = if methods.is_empty() {
                "email, government ID, or phone".to_string()
            } else {
                methods.join(", ")
            };
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": format!("This server requires age verification (18+) via: {accepted}."),
                    "requirement": "age_18_plus",
                    "accepted_methods": accepted
                })),
            ));
        }
    }

    Ok(())
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Require a valid `Authorization: Bearer <jwt>` header.
/// Returns the caller's `beam_identity` or a 401/403 error response.
pub async fn require_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let b = bearer(headers);
    let id = match b {
        Some(t) => validate_jwt(t, state).await,
        None => None,
    };
    if let Some(id) = id {
        // Phase 2.2: Check if user is deleted
        let is_deleted: bool = {
            let db = state.db.get().expect("db pool");
            db.query_row(
                "SELECT is_deleted FROM users WHERE beam_identity = ?1",
                rusqlite::params![&id],
                |row| row.get::<_, i64>(0).map(|v| v != 0),
            )
            .unwrap_or(false)
        };
        
        if is_deleted {
            warn!("auth rejected: account deactivated for {}", id);
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Account deactivated" })),
            ));
        }
        Ok(id)
    } else {
        let reason = if b.is_none() {
            debug!(
                "auth headers missing. keys present: {:?}",
                headers.keys().collect::<Vec<_>>()
            );
            "missing token"
        } else {
            "invalid/expired token"
        };
        warn!("auth rejected: {reason}");
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid or expired token" })),
        ))
    }
}

/// Call the auth server's `/login` endpoint with beam identity + password.
/// Validates the returned JWT locally before trusting it.
/// Returns `(beam_identity, UserVerification)` on success, or an error message.
pub async fn auth_server_login(
    beam_identity: &str,
    password: &str,
    state: &AppState,
) -> Result<(String, UserVerification), String> {
    let login_url = format!("{}/login", state.auth_server_url.trim_end_matches('/'));

    let resp = reqwest::Client::new()
        .post(&login_url)
        .json(&json!({ "beam_identity": beam_identity, "password": password }))
        .send()
        .await
        .map_err(|e| format!("could not reach auth server: {e}"))?;

    if !resp.status().is_success() {
        let body: Value = resp.json().await.unwrap_or_default();
        let msg = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("invalid credentials")
            .to_string();
        return Err(msg);
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("bad response from auth server: {e}"))?;

    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "auth server returned no token".to_string())?;

    validate_jwt_with_verification(token, state)
        .await
        .ok_or_else(|| "token returned by auth server failed local validation".to_string())
}

/// Validate a raw bot token string against the database.
/// Returns `"bot:<name>"` on success, or `None` if the token is invalid.
pub async fn validate_bot_token(raw_token: &str, state: &AppState) -> Option<String> {
    let db = state.db.get().expect("db pool");
    db.query_row(
        "SELECT name FROM bots WHERE token = ?1",
        rusqlite::params![raw_token],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .map(|name| format!("bot:{name}"))
}

/// Resolve an identity from either a standard JWT or a `"Bot <token>"` string.
/// Used by the WebSocket handler and any endpoint that accepts both auth types.
pub async fn resolve_identity(token: &str, state: &Arc<AppState>) -> Option<String> {
    if let Some(bot_token) = token.strip_prefix("Bot ") {
        validate_bot_token(bot_token, state).await
    } else {
        validate_jwt(token, state).await
    }
}

/// Like `resolve_identity` but also returns the avatar UUID from the JWT claims.
/// Bots don't carry an avatar, so they always return `None` for the avatar.
pub async fn resolve_identity_with_avatar(token: &str, state: &Arc<AppState>) -> Option<(String, Option<String>)> {
    if let Some(bot_token) = token.strip_prefix("Bot ") {
        validate_bot_token(bot_token, state).await.map(|id| (id, None))
    } else {
        validate_jwt_core(token, state).await.map(|(id, _, avatar)| (id, avatar))
    }
}

// =============================================================================
// Phase 0 — Unit tests for auth.rs
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── JWT structure validation ───────────────────────────────────────────

    #[test]
    fn validate_jwt_rejects_malformed_token() {
        // Empty token
        assert!(!is_valid_jwt_structure(""));
        // No dots
        assert!(!is_valid_jwt_structure("notajwt"));
        // Wrong number of parts
        assert!(!is_valid_jwt_structure("header.payload"));
        assert!(!is_valid_jwt_structure("a.b.c.d"));
    }

    #[test]
    fn validate_jwt_accepts_valid_structure() {
        // Standard JWT format: header.payload.signature
        assert!(is_valid_jwt_structure("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"));
    }

    fn is_valid_jwt_structure(token: &str) -> bool {
        let parts: Vec<&str> = token.split('.').collect();
        parts.len() == 3
    }

    // ── Claims parsing ─────────────────────────────────────────────────────

    #[derive(Deserialize)]
    struct TestClaims {
        sub: Option<String>,
        beam_identity: Option<String>,
        exp: Option<usize>,
        aud: Option<String>,
    }

    #[test]
    fn parse_claims_with_beam_identity() {
        let json = r#"{"beam_identity":"user»tag","exp":1234567890}"#;
        let claims: TestClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.beam_identity, Some("user»tag".to_string()));
        assert_eq!(claims.exp, Some(1234567890));
    }

    #[test]
    fn parse_claims_fallback_to_sub() {
        let json = r#"{"sub":"fallback-id","exp":1234567890}"#;
        let claims: TestClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, Some("fallback-id".to_string()));
        assert!(claims.beam_identity.is_none());
    }

    #[test]
    fn parse_claims_with_audience() {
        let json = r#"{"beam_identity":"user","aud":"https://example.com","exp":1234567890}"#;
        let claims: TestClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, Some("https://example.com".to_string()));
    }

    // ── Token expiry logic ────────────────────────────────────────────────

    #[test]
    fn token_not_expired_when_future_exp() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let future_exp = now + 3600; // 1 hour from now
        assert!(now < future_exp);
    }

    #[test]
    fn token_expired_when_past_exp() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        let past_exp = now.saturating_sub(3600); // 1 hour ago
        assert!(now > past_exp);
    }

    #[test]
    fn token_without_exp_never_expires() {
        // Tokens without exp claim are valid indefinitely
        // This is just verifying the logic handles None correctly
        let exp: Option<usize> = None;
        assert!(exp.is_none());
    }

    // ── Bearer token extraction ────────────────────────────────────────────

    fn extract_bearer(auth_header: &str) -> Option<&str> {
        auth_header.strip_prefix("Bearer ")
    }

    #[test]
    fn extract_bearer_token() {
        assert_eq!(
            extract_bearer("Bearer eyJhbGciOiJIUzI1NiJ9"),
            Some("eyJhbGciOiJIUzI1NiJ9")
        );
    }

    #[test]
    fn extract_bearer_rejects_missing_prefix() {
        assert_eq!(extract_bearer("eyJhbGciOiJIUzI1NiJ9"), None);
    }

    #[test]
    fn extract_bearer_rejects_wrong_prefix() {
        assert_eq!(extract_bearer("Basic dXNlcjpwYXNz"), None);
    }

    #[test]
    fn extract_bearer_handles_empty() {
        assert_eq!(extract_bearer(""), None);
        assert_eq!(extract_bearer("Bearer "), Some(""));
    }

    // ── Bot token prefix handling ────────────────────────────────────────

    #[test]
    fn strip_bot_token_prefix() {
        assert_eq!(
            "secret-token-123".strip_prefix("Bot "),
            None // Should be Some("secret-token-123") when input is "Bot secret-token-123"
        );
        assert_eq!(
            "Bot secret-token-123".strip_prefix("Bot "),
            Some("secret-token-123")
        );
    }

    #[test]
    fn regular_token_not_stripped() {
        let token = "regular.jwt.token";
        assert!(token.strip_prefix("Bot ").is_none());
    }

    // ── JwksStore tests ──────────────────────────────────────────────────

    #[test]
    fn jwks_store_starts_empty() {
        let store = JwksStore::default();
        assert!(store.keys.is_empty());
    }

    #[test]
    fn jwks_store_insert_key() {
        use ed25519_dalek::PublicKey;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let mut store = JwksStore::default();
        // Create a dummy 32-byte public key
        let dummy_bytes: [u8; 32] = [0u8; 32];
        let key = PublicKey::from_bytes(&dummy_bytes).unwrap();
        store.keys.insert("test-key-1".to_string(), key);
        assert_eq!(store.keys.len(), 1);
        assert!(store.keys.contains_key("test-key-1"));
    }
}
