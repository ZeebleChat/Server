use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

#[derive(Default)]
pub struct JwksStore {
    pub keys: HashMap<String, PublicKey>,
}

pub async fn fetch_jwks(auth_url: &str) -> anyhow::Result<JwksStore> {
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
// Audience check is intentionally omitted: zvoice is a companion service that
// accepts any JWT signed by the shared auth server.

pub async fn validate_jwt(token: &str, jwks: &Arc<Mutex<JwksStore>>) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
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
        let store = jwks.lock().unwrap();
        match store.keys.get(&kid).copied() {
            Some(k) => k,
            None => {
                warn!("validate_jwt: kid '{kid}' not in JWKS store");
                return None;
            }
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

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;

    #[derive(Deserialize)]
    struct Claims {
        sub: Option<String>,
        beam_identity: Option<String>,
        exp: Option<usize>,
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

    claims.beam_identity.or(claims.sub)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

pub async fn require_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let token = bearer(headers);
    let id = match token {
        Some(t) => validate_jwt(t, &state.jwks).await,
        None => None,
    };
    match id {
        Some(id) => Ok(id),
        None => {
            let reason = if token.is_none() { "missing token" } else { "invalid/expired token" };
            debug!("auth rejected: {reason}");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or expired token" })),
            ))
        }
    }
}
