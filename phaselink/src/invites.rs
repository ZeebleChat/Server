use super::*;
use axum::extract::{ConnectInfo, Extension};
use axum::http::HeaderMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::rate_limit::{check_invite_rate_limit, check_login_rate_limit, extract_client_ip};

/// Escape a string for safe embedding inside an HTML attribute value.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateInvite {
    /// Hours until expiry. 0 or absent = never expires.
    #[serde(default)]
    pub expires_in_hours: Option<u64>,
    /// Max redemptions. 0 or absent = unlimited.
    #[serde(default)]
    pub max_uses: Option<u64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct InviteInfo {
    pub code: String,
    pub server_name: String,
    pub ws_url: String,
    pub api_url: String,
    pub uses_left: Option<i64>,  // None = unlimited
    pub expires_at: Option<i64>, // None = never
    pub created_by: String,
}

/// GET /invites  — list all active invites (owner only)
pub async fn list_invites(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Only server owner can list all invites
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only the server owner can list invites" })),
        )
            .into_response();
    }

    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = match db.prepare(
        "SELECT code, created_by, created_at, expires_at, max_uses, use_count
         FROM invites ORDER BY created_at DESC",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("prepare list invites: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB error" })),
            )
                .into_response();
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let invites: Vec<Value> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .map(
            |(code, created_by, created_at, expires_at, max_uses, use_count)| {
                let expired = expires_at.map(|e| now > e).unwrap_or(false);
                let exhausted = max_uses.map(|m| use_count >= m).unwrap_or(false);
                json!({
                    "code": code,
                    "created_by": created_by,
                    "created_at": created_at,
                    "expires_at": expires_at,
                    "max_uses": max_uses,
                    "use_count": use_count,
                    "valid": !expired && !exhausted,
                })
            },
        )
        .collect();

    Json(invites).into_response()
}

/// POST /invites  — create an invite link (any authenticated user)
pub async fn create_invite(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<CreateInvite>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Check if non-owners are allowed to create invites
    {
        let s = state.settings.read().await;
        if !s.invites_anyone_can_create
            && !s.owner_beam_identity.is_empty()
            && identity != s.owner_beam_identity
        {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Only the server owner can create invites" })),
            )
            .into_response();
        }
    }

    // ── Rate limit check ──────────────────────────────────────────────
    if let Err(e) = check_invite_rate_limit(&state.rate_limits, &identity) {
        return e.into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Use request body if provided, otherwise fall back to configured defaults
    let settings_snapshot = state.settings.read().await;
    let default_expiry = settings_snapshot.default_invite_expiry_hours;
    let default_max_uses = settings_snapshot.default_invite_max_uses;
    drop(settings_snapshot);

    let expiry_hours = body.expires_in_hours.unwrap_or(default_expiry);
    let use_limit = body.max_uses.unwrap_or(default_max_uses);

    let expires_at: Option<i64> = if expiry_hours > 0 {
        Some(now + (expiry_hours as i64) * 3600)
    } else {
        None
    };

    let max_uses: Option<i64> = if use_limit > 0 {
        Some(use_limit as i64)
    } else {
        None
    };

    // Generate a unique code (retry on collision — vanishingly rare)
    let code = loop {
        let candidate = generate_invite_code();
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        let exists: bool = db
            .query_row(
                "SELECT 1 FROM invites WHERE code = ?1",
                rusqlite::params![candidate],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !exists {
            break candidate;
        }
    };

    {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = db.execute(
            "INSERT INTO invites (code, created_by, expires_at, max_uses)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![code, identity, expires_at, max_uses],
        ) {
            error!("insert invite: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to create invite" })),
            )
                .into_response();
        }
    }

    let public_url = state.settings.read().await.public_url.clone();
    let web_url = format!("{}/join/{}", public_url, code);
    let deep_url = format!("zeeble://join/{}", code);

    info!("{identity} created invite {code} (expires={expires_at:?}, max_uses={max_uses:?})");

    Json(json!({
        "code":      code,
        "web_url":   web_url,
        "deep_url":  deep_url,
        "expires_at": expires_at,
        "max_uses":  max_uses,
    }))
    .into_response()
}

/// GET /invites/:code  — peek at an invite (no side-effects, used by the join page)
pub async fn get_invite(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let row = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        db.query_row(
            "SELECT code, created_by, expires_at, max_uses, use_count
             FROM invites WHERE code = ?1",
            rusqlite::params![code],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
    }; // db lock dropped here, before any .await

    let (code, created_by, expires_at, max_uses, use_count) = match row {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Invite not found" })),
            )
                .into_response();
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if let Some(exp) = expires_at
        && now > exp
    {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "This invite has expired" })),
        )
            .into_response();
    }
    if let Some(max) = max_uses
        && use_count >= max
    {
        return (
            StatusCode::GONE,
            Json(json!({ "error": "This invite has reached its maximum uses" })),
        )
            .into_response();
    }

    let (server_name, public_url) = {
        let s = state.settings.read().await;
        (s.server_name.clone(), s.public_url.clone())
    };
    let base = public_url.trim_end_matches('/');
    let ws_url = base
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1)
        + "/ws";

    debug!("invite peeked: {code}");
    Json(InviteInfo {
        code,
        server_name,
        ws_url,
        api_url: public_url,
        uses_left: max_uses.map(|m| m - use_count),
        expires_at,
        created_by,
    })
    .into_response()
}

/// POST /invites/:code/redeem  — consume one use (call once the client has connected)
pub async fn redeem_invite(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // Check allow_new_members gate
    if !state.settings.read().await.allow_new_members {
        warn!(
            "invite redeem blocked: allow_new_members=false (attempted by {identity}, code={code})"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "This server is not accepting new members at this time." })),
        )
            .into_response();
    }

    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Atomic update: increment only if invite exists, not expired, and under max_uses
    let rows_affected = db.execute(
        "UPDATE invites SET use_count = use_count + 1 \
         WHERE code = ?1 AND (expires_at IS NULL OR expires_at > ?2) \
         AND (max_uses IS NULL OR use_count < max_uses)",
        rusqlite::params![code, now],
    );

    match rows_affected {
        Ok(1) => {
            info!("{identity} redeemed invite {code}");
            Json(json!({ "ok": true })).into_response()
        }
        Ok(0) => {
            // Check if invite exists to provide appropriate error
            let exists: bool = db
                .query_row(
                    "SELECT 1 FROM invites WHERE code = ?1",
                    rusqlite::params![code],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if !exists {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Invite not found" })),
                )
                    .into_response()
            } else {
                // Retrieve details to determine exact failure reason
                let row = db.query_row(
                    "SELECT expires_at, max_uses, use_count FROM invites WHERE code = ?1",
                    rusqlite::params![code],
                    |row| {
                        Ok((
                            row.get::<_, Option<i64>>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                );

                match row {
                    Ok((expires_at, max_uses, use_count)) => {
                        if let Some(exp) = expires_at
                            && now >= exp
                        {
                            return (StatusCode::GONE, Json(json!({ "error": "Invite expired" })))
                                .into_response();
                        }
                        if let Some(max) = max_uses
                            && use_count >= max
                        {
                            return (
                                StatusCode::GONE,
                                Json(json!({ "error": "Invite at max uses" })),
                            )
                                .into_response();
                        }
                        // Fallback if something else prevented the update
                        (
                            StatusCode::GONE,
                            Json(json!({ "error": "Invite cannot be redeemed" })),
                        )
                            .into_response()
                    }
                    Err(_) => (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "Invite not found" })),
                    )
                        .into_response(),
                }
            }
        }
        Err(e) => {
            error!("redeem invite: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to redeem invite" })),
            )
                .into_response()
        }
        _ => unreachable!(),
    }
}

/// DELETE /invites/:code  — revoke (creator only)
pub async fn delete_invite(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let owner = state.settings.read().await.owner_beam_identity.clone();
    let is_owner = !owner.is_empty() && identity == owner;

    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let created_by: Option<String> = db
        .query_row(
            "SELECT created_by FROM invites WHERE code = ?1",
            rusqlite::params![code],
            |row| row.get(0),
        )
        .ok();

    match created_by {
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Invite not found" })),
        )
            .into_response(),
        Some(creator) if creator != identity && !is_owner => (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Only the invite creator or server owner can revoke it" })),
        )
            .into_response(),
        Some(_) => {
            db.execute(
                "DELETE FROM invites WHERE code = ?1",
                rusqlite::params![code],
            )
            .ok();
            info!("{identity} revoked invite {code}");
            (StatusCode::OK, Json(json!({ "deleted": true }))).into_response()
        }
    }
}

/// GET /join/:code  — browser-friendly landing page
pub async fn join_page(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
) -> impl IntoResponse {
    let api_url = state.settings.read().await.public_url.clone();
    let api_url_base = api_url.trim_end_matches('/');
    let api_url = &api_url_base;
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Join — Zeeble</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#212328;color:#f3f4f6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}}
    .card{{background:#26282e;border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:36px;width:100%;max-width:440px;box-shadow:0 8px 32px rgba(0,0,0,0.4);animation:rise 0.4s cubic-bezier(.16,1,.3,1) both}}
    @keyframes rise{{from{{opacity:0;transform:translateY(16px)}}}}
    .logo{{font-size:22px;font-weight:700;letter-spacing:-0.5px;margin-bottom:24px;color:#f3f4f6}}
    .logo span{{color:#6366f1}}
    h2{{font-size:18px;font-weight:600;margin-bottom:6px}}
    .sub{{font-size:13px;color:#9ca3af}}
    .sub b{{color:#f3f4f6;font-family:monospace;font-weight:600}}
    .badge{{margin-top:16px;padding:10px 14px;border-radius:8px;font-size:13px;font-weight:500;background:rgba(99,102,241,0.1);color:#6366f1;display:flex;align-items:center;gap:8px;border:1px solid rgba(99,102,241,0.2)}}
    .dot{{width:8px;height:8px;border-radius:50%;background:#6366f1;flex-shrink:0;box-shadow:0 0 6px rgba(99,102,241,0.6)}}
    .info{{margin-top:20px;display:flex;flex-direction:column;gap:8px}}
    .info-row{{display:flex;justify-content:space-between;align-items:center;font-size:13px;padding:8px 12px;background:#1b1d21;border-radius:8px;border:1px solid rgba(255,255,255,0.06)}}
    .info-label{{color:#9ca3af;font-weight:500}}
    .info-value{{color:#f3f4f6;font-weight:600;font-family:monospace;font-size:12px}}
    .divider{{height:1px;background:rgba(255,255,255,0.06);margin:20px 0}}
    .btn-group{{display:flex;flex-direction:column;gap:8px}}
    .btn{{display:flex;align-items:center;justify-content:center;gap:8px;padding:11px 20px;border-radius:8px;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer;border:none;transition:background 0.15s;width:100%}}
    .btn-primary{{background:#6366f1;color:#fff}}
    .btn-primary:hover{{background:#4f46e5}}
    .btn-primary:active{{background:#4338ca}}
    .btn-secondary{{background:transparent;border:1px solid rgba(255,255,255,0.1);color:#f3f4f6}}
    .btn-secondary:hover{{background:rgba(255,255,255,0.05)}}
    .loading{{text-align:center;color:#9ca3af;font-size:13px;padding:16px 0}}
    .dot-anim::after{{content:'';animation:dots 1.2s steps(4,end) infinite}}
    @keyframes dots{{0%,20%{{content:''}}40%{{content:'.'}}60%{{content:'..'}}80%,100%{{content:'...'}}}}
    .error-wrap{{text-align:center;padding:16px 0}}
    .error-icon{{font-size:2rem;margin-bottom:10px}}
    .error-title{{font-size:15px;font-weight:700;color:#ef4444;margin-bottom:6px}}
    .error-msg{{font-size:13px;color:#9ca3af}}
    .form-title{{font-size:14px;font-weight:600;color:#f3f4f6;margin-bottom:4px}}
    label{{display:block;font-size:12px;font-weight:600;color:#9ca3af;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:6px}}
    input{{width:100%;padding:10px 12px;font-size:14px;background:#1b1d21;color:#f3f4f6;border:1px solid rgba(255,255,255,0.1);border-radius:8px;outline:none;transition:border-color 0.15s;margin-bottom:16px;font-family:inherit}}
    input:focus{{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,0.2)}}
    input::placeholder{{color:#6b7280}}
    #ji-msg{{margin-top:12px;padding:10px 14px;border-radius:8px;font-size:13px;font-weight:500;display:none;align-items:center;gap:8px}}
    #ji-msg.ok{{background:rgba(16,185,129,0.12);color:#10b981;border:1px solid rgba(16,185,129,0.2);display:flex}}
    #ji-msg.err{{background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.2);display:flex}}
  </style>
</head>
<body>
<div class="card">
  <div class="logo">Zee<span>ble</span></div>
  <div id="cfg" data-code="{code_html}" data-api-url="{api_url_html}" style="display:none"></div>
  <div id="root"><div class="loading">Fetching invite<span class="dot-anim"></span></div></div>
</div>
<script>
const CODE    = document.getElementById('cfg').dataset.code;
const API_URL = document.getElementById('cfg').dataset.apiUrl;

async function load() {{
  try {{
    const r = await fetch(`${{API_URL}}/v1/invites/${{CODE}}`);
    const d = await r.json();
    if (!r.ok) {{ renderError(d.error || 'Invalid invite'); return; }}
    render(d);
  }} catch {{ renderError('Could not reach the server.'); }}
}}

function fmt_expiry(ts) {{
  if (!ts) return 'Never';
  return new Date(ts * 1000).toLocaleDateString(undefined, {{month:'short', day:'numeric', year:'numeric'}});
}}

function fmt_uses(n) {{
  if (n === null || n === undefined) return 'Unlimited';
  return n === 1 ? '1 use left' : `${{n}} uses left`;
}}

function render(inv) {{
  document.getElementById('root').innerHTML = `
    <h2>${{inv.server_name}}</h2>
    <p class="sub">Invited by <b>${{inv.created_by}}</b></p>
    <div class="badge"><div class="dot"></div>You've been invited</div>
    <div class="info">
      <div class="info-row"><span class="info-label">Expires</span><span class="info-value">${{fmt_expiry(inv.expires_at)}}</span></div>
      <div class="info-row"><span class="info-label">Uses remaining</span><span class="info-value">${{fmt_uses(inv.uses_left)}}</span></div>
      <div class="info-row"><span class="info-label">Code</span><span class="info-value">${{CODE}}</span></div>
    </div>
    <div class="divider"></div>
    <div class="btn-group">
      <a class="btn btn-primary" href="zeeble://join?code=${{CODE}}">Open in Zeeble</a>
      <button class="btn btn-secondary" onclick="copyLink(this)">Copy invite link</button>
    </div>
    <div class="divider"></div>
    <p class="form-title">Sign in to join</p>
    <p class="sub" style="margin-bottom:16px">Use your Zeeble account — including subaccounts.</p>
    <label for="ji-id">Beam Identity</label>
    <input id="ji-id" placeholder="name»tag" autocomplete="username">
    <label for="ji-pw">Password</label>
    <input id="ji-pw" type="password" placeholder="••••••••" autocomplete="current-password">
    <button class="btn btn-primary" id="ji-btn" onclick="joinSubmit()" style="margin-top:4px">Sign in & Join</button>
    <div id="ji-msg"></div>
  `;
  document.addEventListener('keydown', e => {{ if (e.key === 'Enter') joinSubmit(); }}, {{once: true}});
}}

function renderError(msg) {{
  document.getElementById('root').innerHTML = `
    <div class="error-wrap">
      <div class="error-icon">✕</div>
      <div class="error-title">Invite invalid</div>
      <div class="error-msg">${{msg}}</div>
    </div>`;
}}

function copyLink(btn) {{
  navigator.clipboard.writeText(window.location.href).then(() => {{
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => btn.textContent = orig, 2000);
  }});
}}

async function joinSubmit() {{
  const id  = document.getElementById('ji-id');
  const pw  = document.getElementById('ji-pw');
  const btn = document.getElementById('ji-btn');
  if (!id || !pw || !btn) return;
  if (!id.value.trim() || !pw.value) {{ showJoinMsg('err', 'Enter your beam identity and password.'); return; }}
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  try {{
    const r = await fetch(`${{API_URL}}/join/${{CODE}}`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ beam_identity: id.value.trim(), password: pw.value }})
    }});
    const d = await r.json();
    if (r.ok) {{
      renderJoined(d.identity);
    }} else {{
      btn.disabled = false;
      btn.textContent = 'Sign in & Join';
      showJoinMsg('err', d.error || 'Failed to join.');
    }}
  }} catch {{
    btn.disabled = false;
    btn.textContent = 'Sign in & Join';
    showJoinMsg('err', 'Could not reach the server.');
  }}
}}

function showJoinMsg(cls, text) {{
  const el = document.getElementById('ji-msg');
  if (!el) return;
  el.className = cls;
  el.textContent = text;
}}

function renderJoined(identity) {{
  document.getElementById('root').innerHTML = `
    <h2>You've Joined!</h2>
    <p class="sub">Open the Zeeble app to start chatting.</p>
    <div class="badge" style="background:rgba(16,185,129,0.1);color:#10b981;border-color:rgba(16,185,129,0.2);margin-top:16px">
      <div class="dot" style="background:#10b981;box-shadow:0 0 6px rgba(16,185,129,0.6)"></div>Successfully joined
    </div>
    <div class="info" style="margin-top:20px">
      <div class="info-row"><span class="info-label">Signed in as</span><span class="info-value">${{identity}}</span></div>
    </div>
    <div class="divider"></div>
    <a class="btn btn-primary" href="zeeble://join?code=${{CODE}}">Open in Zeeble</a>
  `;
}}

load();
</script>
</body>
</html>"#,
        code_html = html_escape(&code),
        api_url_html = html_escape(api_url),
    );

    Html(html).into_response()
}

/// POST /join/:code — authenticate + redeem from the web join page
pub async fn join_redeem(
    Extension(state): Extension<Arc<AppState>>,
    Path(code): Path<String>,
    ConnectInfo(sock_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Securely extract client IP for rate limiting
    let ip = extract_client_ip(&headers, &sock_addr.ip(), &state.trusted_proxies);

    // ── Rate limit check ──────────────────────────────────────────────────────
    if let Err(e) = check_login_rate_limit(&state.rate_limits, &ip) {
        return e.into_response();
    }

    // ── TLS enforcement guard ─────────────────────────────────────────────────
    if state.require_tls {
        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok());
        if proto != Some("https") {
            warn!("join_redeem rejected: REQUIRE_TLS=true but no x-forwarded-proto: https");
            return (
                StatusCode::UPGRADE_REQUIRED,
                Json(json!({ "error": "This server requires HTTPS. Configure a TLS-terminating reverse proxy." })),
            )
                .into_response();
        }
    }

    let beam_identity = payload
        .get("beam_identity")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if beam_identity.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Beam identity and password are required" })),
        )
            .into_response();
    }

    let identity = match auth_server_login(&beam_identity, &password, &state).await {
        Ok(id) => id,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({ "error": e }))).into_response()
        }
    };

    if !state.settings.read().await.allow_new_members {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "This server is not accepting new members at this time." })),
        )
            .into_response();
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Confine the MutexGuard to this block so it is dropped before any `.await`.
    // MutexGuard<Connection> is !Send; keeping it across an await makes the future
    // non-Send and breaks the axum Handler<_, _> trait bound.
    let rows_affected = {
        let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
        db.execute(
            "UPDATE invites SET use_count = use_count + 1 \
             WHERE code = ?1 AND (expires_at IS NULL OR expires_at > ?2) \
             AND (max_uses IS NULL OR use_count < max_uses)",
            rusqlite::params![code, now],
        )
    }; // MutexGuard dropped here — no await has occurred yet

    match rows_affected {
        Ok(1) => {
            info!("{identity} redeemed invite {code} via web join page");
            // Register new member in users table so they appear immediately in the member list.
            // Second lock is in its own block, also dropped before the await below.
            {
                let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
                let _ = db.execute(
                    "INSERT OR IGNORE INTO users (beam_identity, status) VALUES (?1, 'offline')",
                    rusqlite::params![identity],
                );
            }
            state.broadcast_member_update().await;
            Json(json!({ "ok": true, "identity": identity })).into_response()
        }
        Ok(0) => {
            // Acquire a fresh lock for diagnostic queries — no await in this arm.
            let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
            let exists: bool = db
                .query_row(
                    "SELECT 1 FROM invites WHERE code = ?1",
                    rusqlite::params![code],
                    |_| Ok(true),
                )
                .unwrap_or(false);

            if !exists {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Invite not found" })),
                )
                    .into_response();
            }

            let row = db.query_row(
                "SELECT expires_at, max_uses, use_count FROM invites WHERE code = ?1",
                rusqlite::params![code],
                |row| {
                    Ok((
                        row.get::<_, Option<i64>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            );

            match row {
                Ok((expires_at, max_uses, use_count)) => {
                    if let Some(exp) = expires_at
                        && now >= exp
                    {
                        return (
                            StatusCode::GONE,
                            Json(json!({ "error": "Invite expired" })),
                        )
                            .into_response();
                    }
                    if let Some(max) = max_uses
                        && use_count >= max
                    {
                        return (
                            StatusCode::GONE,
                            Json(json!({ "error": "Invite at max uses" })),
                        )
                            .into_response();
                    }
                    (
                        StatusCode::GONE,
                        Json(json!({ "error": "Invite cannot be redeemed" })),
                    )
                        .into_response()
                }
                Err(_) => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "Invite not found" })),
                )
                    .into_response(),
            }
        }
        Err(e) => {
            error!("join_redeem: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to redeem invite" })),
            )
                .into_response()
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escapes_ampersand() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn html_escapes_lt_gt() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    }

    #[test]
    fn html_escapes_quotes() {
        assert_eq!(html_escape(r#"x"y"#), "x&quot;y");
    }

    #[test]
    fn html_escapes_combined() {
        let input = r#"<script>alert("x")</script>"#;
        let output = html_escape(input);
        // All original special chars are escaped
        assert!(output.contains("&lt;"));
        assert!(output.contains("&gt;"));
        assert!(output.contains("&quot;"));
        // Original unsafe HTML chars are gone
        assert!(!output.contains("<script>"));
        assert!(!output.contains("</script>"));
        // The escaped version should be present
        assert!(output.contains("&lt;script&gt;"));
    }

    #[test]
    fn html_escapes_noop_on_plain() {
        assert_eq!(html_escape("hello world"), "hello world");
    }
}
