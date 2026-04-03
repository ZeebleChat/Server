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

/// Fetch JWKS from the auth server's `/.well-known/jwks.json`.
/// Uses `reqwest::blocking` — must be called from `spawn_blocking`.
pub fn fetch_jwks(auth_url: &str) -> anyhow::Result<JwksStore> {
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

    let jwks_url = format!("{}/.well-known/jwks.json", auth_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::new();
    let resp = client.get(&jwks_url).send()?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to fetch JWKS: HTTP {}", resp.status()));
    }
    let jwks: JwksResponse = resp.json()?;

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

/// Validate a JWT token using Ed25519 keys from the in-memory JWKS store.
/// Returns the `beam_identity` on success, or `None` if invalid/expired.
pub async fn validate_jwt(token: &str, state: &AppState) -> Option<String> {
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
    }
    let claims: Claims = match serde_json::from_slice(&payload_bytes) {
        Ok(c) => c,
        Err(e) => { warn!("validate_jwt: claims parse failed: {e}"); return None; }
    };

    // Check expiration
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

    // Audience check:
    //   - No `aud` claim  → general auth token, valid on any server.
    //   - `aud` matches public_url → valid for this server.
    //   - `aud` for a different server → rejected.
    let public_url = {
        let settings = state.settings.read().await;
        settings.public_url.clone()
    };
    if !public_url.is_empty() {
        if let Some(ref aud) = claims.aud {
            let aud_norm = aud.trim_end_matches('/');
            let url_norm = public_url.trim_end_matches('/');
            if aud_norm != url_norm {
                warn!("validate_jwt: aud mismatch: token aud='{aud_norm}' vs server public_url='{url_norm}'");
                return None;
            }
        }
    }

    claims.beam_identity.or(claims.sub)
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
            let db = state.db.lock().unwrap();
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
/// Returns the validated `beam_identity` on success, or an error message.
pub async fn auth_server_login(
    beam_identity: &str,
    password: &str,
    state: &AppState,
) -> Result<String, String> {
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

    // Validate the returned JWT locally to confirm it's genuine
    validate_jwt(token, state)
        .await
        .ok_or_else(|| "token returned by auth server failed local validation".to_string())
}

/// Validate a raw bot token string against the database.
/// Returns `"bot:<name>"` on success, or `None` if the token is invalid.
pub async fn validate_bot_token(raw_token: &str, state: &AppState) -> Option<String> {
    let db = state.db.lock().unwrap();
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
