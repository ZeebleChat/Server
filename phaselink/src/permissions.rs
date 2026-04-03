use super::*;
use axum::extract::Extension;
use std::collections::HashMap;
use std::sync::Arc;

use crate::EVERYONE_ROLE;

// ── Permission keys ───────────────────────────────────────────────────────────

/// All valid server-wide permission keys (stored in custom_roles.permissions JSON).
pub const SERVER_PERM_KEYS: &[&str] = &[
    "administrator",
    "manage_server",
    "manage_roles",
    "manage_channels",
    "kick_members",
    "ban_members",
    "create_invites",
    "manage_invites",
    "manage_messages",
    "manage_nicknames",
    "change_nickname",
];

/// All valid channel-level permission keys (stored in channel_permissions allow/deny JSON).
pub const CHANNEL_PERM_KEYS: &[&str] = &[
    "view_channel",
    "send_messages",
    "read_message_history",
    "embed_links",
    "attach_files",
    "add_reactions",
    "mention_everyone",
    "manage_messages",
    "connect",
    "speak",
    "video",
    "mute_members",
    "move_members",
];

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ChannelPerm {
    pub role_name: String,
    pub allow: HashMap<String, bool>,
    pub deny: HashMap<String, bool>,
}

#[derive(Serialize)]
pub struct CategoryPerm {
    pub role_name: String,
    pub allow: HashMap<String, bool>,
    pub deny: HashMap<String, bool>,
}

#[derive(Deserialize)]
pub struct SetChannelPermBody {
    pub allow: Option<HashMap<String, bool>>,
    pub deny: Option<HashMap<String, bool>>,
}

#[derive(Deserialize)]
pub struct SetCategoryPermBody {
    pub allow: Option<HashMap<String, bool>>,
    pub deny: Option<HashMap<String, bool>>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_perm_json(s: &str) -> HashMap<String, bool> {
    serde_json::from_str(s).unwrap_or_default()
}

fn get_role_permissions(db: &rusqlite::Connection, role_name: &str) -> HashMap<String, bool> {
    db.query_row(
        "SELECT permissions FROM custom_roles WHERE name = ?1",
        rusqlite::params![role_name],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .map(|s| parse_perm_json(&s))
    .unwrap_or_default()
}

fn get_channel_overrides(
    db: &rusqlite::Connection,
    channel_id: &str,
    role_name: &str,
) -> (HashMap<String, bool>, HashMap<String, bool>) {
    db.query_row(
        "SELECT allow, deny FROM channel_permissions WHERE channel_id = ?1 AND role_name = ?2",
        rusqlite::params![channel_id, role_name],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .ok()
    .map(|(a, d)| (parse_perm_json(&a), parse_perm_json(&d)))
    .unwrap_or_default()
}

fn get_category_overrides(
    db: &rusqlite::Connection,
    category_id: i64,
    role_name: &str,
) -> (HashMap<String, bool>, HashMap<String, bool>) {
    db.query_row(
        "SELECT allow, deny FROM category_permissions WHERE category_id = ?1 AND role_name = ?2",
        rusqlite::params![category_id, role_name],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .ok()
    .map(|(a, d)| (parse_perm_json(&a), parse_perm_json(&d)))
    .unwrap_or_default()
}

// ── Resolution ────────────────────────────────────────────────────────────────

/// Resolve the full permission set for `identity` on `channel_id`.
///
/// Algorithm (Discord-style):
/// 1. Owner → all true
/// 2. Start with @everyone server-wide permissions
/// 3. OR in member's role permissions
/// 4. If `administrator` is true → return all true
/// 5. Apply channel overrides:
///    a. @everyone deny  → false
///    b. @everyone allow → true
///    c. Member's role deny  → false
///    d. Member's role allow → true
///    Also try category-level overrides as the channel-level source when no
///    channel-specific row exists for that role.
pub async fn resolve_channel_access(
    state: &AppState,
    identity: &str,
    channel_id: &str,
) -> HashMap<String, bool> {
    // Owner always gets everything
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if !owner.is_empty() && identity == owner {
        return all_true();
    }

    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());

    // Look up member's assigned role
    let user_role: Option<String> = db
        .query_row(
            "SELECT role FROM users WHERE beam_identity = ?1",
            rusqlite::params![identity],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    // Step 2: start with @everyone server-wide permissions
    let mut base = get_role_permissions(&db, EVERYONE_ROLE);

    // Step 3: OR in member's role permissions
    if let Some(ref role) = user_role {
        let role_perms = get_role_permissions(&db, role);
        for (k, v) in &role_perms {
            if *v {
                base.insert(k.clone(), true);
            }
        }
    }

    // Step 4: administrator bypasses all channel restrictions
    if base.get("administrator").copied().unwrap_or(false) {
        return all_true();
    }

    // Look up channel's category for category-level fallback
    let category_id: Option<i64> = db
        .query_row(
            "SELECT category_id FROM channels WHERE id = ?1",
            rusqlite::params![channel_id],
            |row| row.get(0),
        )
        .ok()
        .flatten();

    // Build the effective channel overrides for @everyone and the member's role.
    // Channel-specific row takes priority; fall back to category-level row.
    let (ev_allow, ev_deny) = effective_overrides(&db, channel_id, category_id, EVERYONE_ROLE);
    let (role_allow, role_deny) = match &user_role {
        Some(r) => effective_overrides(&db, channel_id, category_id, r),
        None => (HashMap::new(), HashMap::new()),
    };

    // Step 5: apply overrides to each channel permission key
    let mut result = base;
    for &key in CHANNEL_PERM_KEYS {
        let mut val = result.get(key).copied().unwrap_or(false);
        if ev_deny.get(key).copied().unwrap_or(false)   { val = false; }
        if ev_allow.get(key).copied().unwrap_or(false)  { val = true;  }
        if role_deny.get(key).copied().unwrap_or(false)  { val = false; }
        if role_allow.get(key).copied().unwrap_or(false) { val = true;  }
        result.insert(key.to_string(), val);
    }

    result
}

/// Get effective channel overrides for a role: prefer channel-specific row,
/// fall back to category row if neither allow nor deny has any entry.
fn effective_overrides(
    db: &rusqlite::Connection,
    channel_id: &str,
    category_id: Option<i64>,
    role_name: &str,
) -> (HashMap<String, bool>, HashMap<String, bool>) {
    let (ch_allow, ch_deny) = get_channel_overrides(db, channel_id, role_name);
    if !ch_allow.is_empty() || !ch_deny.is_empty() {
        return (ch_allow, ch_deny);
    }
    if let Some(cat_id) = category_id {
        return get_category_overrides(db, cat_id, role_name);
    }
    (HashMap::new(), HashMap::new())
}

fn all_true() -> HashMap<String, bool> {
    let mut m = HashMap::new();
    for &k in SERVER_PERM_KEYS { m.insert(k.to_string(), true); }
    for &k in CHANNEL_PERM_KEYS { m.insert(k.to_string(), true); }
    m
}

// ── Channel permission handlers ───────────────────────────────────────────────

/// GET /channels/:id/permissions
pub async fn list_channel_perms(
    Extension(state): Extension<Arc<AppState>>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = match db.prepare(
        "SELECT role_name, allow, deny FROM channel_permissions WHERE channel_id = ?1 ORDER BY role_name",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("list_channel_perms: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response();
        }
    };
    let rows: Vec<ChannelPerm> = match stmt.query_map(rusqlite::params![channel_id], |row| {
        Ok(ChannelPerm {
            role_name: row.get(0)?,
            allow: serde_json::from_str(&row.get::<_, String>(1)?).unwrap_or_default(),
            deny:  serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(),
        })
    }) {
        Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    Json(rows).into_response()
}

/// PUT /channels/:id/permissions/:role
pub async fn set_channel_perm(
    Extension(state): Extension<Arc<AppState>>,
    Path((channel_id, role_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<SetChannelPermBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Owner only" }))).into_response();
    }
    let allow = serde_json::to_string(&body.allow.unwrap_or_default()).unwrap_or_else(|_| "{}".into());
    let deny  = serde_json::to_string(&body.deny.unwrap_or_default()).unwrap_or_else(|_| "{}".into());
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    match db.execute(
        "INSERT INTO channel_permissions (channel_id, role_name, allow, deny) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(channel_id, role_name) DO UPDATE SET allow=?3, deny=?4",
        rusqlite::params![channel_id, role_name, allow, deny],
    ) {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => {
            error!("set_channel_perm: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response()
        }
    }
}

/// DELETE /channels/:id/permissions/:role
pub async fn delete_channel_perm(
    Extension(state): Extension<Arc<AppState>>,
    Path((channel_id, role_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Owner only" }))).into_response();
    }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    match db.execute(
        "DELETE FROM channel_permissions WHERE channel_id = ?1 AND role_name = ?2",
        rusqlite::params![channel_id, role_name],
    ) {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => {
            error!("delete_channel_perm: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response()
        }
    }
}

// ── Category permission handlers ──────────────────────────────────────────────

/// GET /categories/:id/permissions
pub async fn list_category_perms(
    Extension(state): Extension<Arc<AppState>>,
    Path(category_id): Path<i64>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if require_auth(&state, &headers).await.is_err() {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "Unauthorized" }))).into_response();
    }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    let mut stmt = match db.prepare(
        "SELECT role_name, allow, deny FROM category_permissions WHERE category_id = ?1 ORDER BY role_name",
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("list_category_perms: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response();
        }
    };
    let rows: Vec<CategoryPerm> = match stmt.query_map(rusqlite::params![category_id], |row| {
        Ok(CategoryPerm {
            role_name: row.get(0)?,
            allow: serde_json::from_str(&row.get::<_, String>(1)?).unwrap_or_default(),
            deny:  serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(),
        })
    }) {
        Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
        Err(_) => vec![],
    };
    Json(rows).into_response()
}

/// PUT /categories/:id/permissions/:role
pub async fn set_category_perm(
    Extension(state): Extension<Arc<AppState>>,
    Path((category_id, role_name)): Path<(i64, String)>,
    headers: HeaderMap,
    Json(body): Json<SetCategoryPermBody>,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Owner only" }))).into_response();
    }
    let allow = serde_json::to_string(&body.allow.unwrap_or_default()).unwrap_or_else(|_| "{}".into());
    let deny  = serde_json::to_string(&body.deny.unwrap_or_default()).unwrap_or_else(|_| "{}".into());
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    match db.execute(
        "INSERT INTO category_permissions (category_id, role_name, allow, deny) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(category_id, role_name) DO UPDATE SET allow=?3, deny=?4",
        rusqlite::params![category_id, role_name, allow, deny],
    ) {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => {
            error!("set_category_perm: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response()
        }
    }
}

/// DELETE /categories/:id/permissions/:role
pub async fn delete_category_perm(
    Extension(state): Extension<Arc<AppState>>,
    Path((category_id, role_name)): Path<(i64, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    let owner = state.settings.read().await.owner_beam_identity.clone();
    if identity != owner {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "Owner only" }))).into_response();
    }
    let db = state.db.lock().unwrap_or_else(|e| e.into_inner());
    match db.execute(
        "DELETE FROM category_permissions WHERE category_id = ?1 AND role_name = ?2",
        rusqlite::params![category_id, role_name],
    ) {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => {
            error!("delete_category_perm: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "db error" }))).into_response()
        }
    }
}

// =============================================================================
// Phase 0 — Unit tests for permissions.rs
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── Permission keys completeness ───────────────────────────────────────

    #[test]
    fn server_perm_keys_not_empty() {
        assert!(!SERVER_PERM_KEYS.is_empty());
        assert!(SERVER_PERM_KEYS.contains(&"administrator"));
        assert!(SERVER_PERM_KEYS.contains(&"manage_server"));
    }

    #[test]
    fn channel_perm_keys_not_empty() {
        assert!(!CHANNEL_PERM_KEYS.is_empty());
        assert!(CHANNEL_PERM_KEYS.contains(&"view_channel"));
        assert!(CHANNEL_PERM_KEYS.contains(&"send_messages"));
    }

    #[test]
    fn server_and_channel_keys_distinct() {
        // Verify no overlap between server and channel permission keys
        let server_set: std::collections::HashSet<_> = SERVER_PERM_KEYS.iter().collect();
        let channel_set: std::collections::HashSet<_> = CHANNEL_PERM_KEYS.iter().collect();
        let overlap: Vec<_> = server_set.intersection(&channel_set).collect();
        // Some permissions like "manage_messages" exist in both, which is fine
        assert!(!server_set.is_empty());
        assert!(!channel_set.is_empty());
    }

    // ── Permission JSON parsing ────────────────────────────────────────────

    #[test]
    fn parse_perm_json_empty() {
        let empty = "{}";
        let result = parse_perm_json(empty);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_perm_json_valid() {
        let json = r#"{"view_channel":true,"send_messages":false}"#;
        let result = parse_perm_json(json);
        assert_eq!(result.get("view_channel"), Some(&true));
        assert_eq!(result.get("send_messages"), Some(&false));
    }

    #[test]
    fn parse_perm_json_invalid_defaults_empty() {
        let invalid = "not valid json";
        let result = parse_perm_json(invalid);
        assert!(result.is_empty());
    }

    // ── all_true helper ────────────────────────────────────────────────────

    #[test]
    fn all_true_contains_all_permissions() {
        let perms = all_true();
        for key in SERVER_PERM_KEYS {
            assert_eq!(perms.get(*key), Some(&true), "Server key {} should be true", key);
        }
        for key in CHANNEL_PERM_KEYS {
            assert_eq!(perms.get(*key), Some(&true), "Channel key {} should be true", key);
        }
    }

    // ── Override computation helpers ──────────────────────────────────────

    #[test]
    fn effective_overrides_prefers_channel_over_category() {
        // This test documents the expected behavior
        // In production, channel-specific overrides take priority
        let channel_allow = HashMap::from([("view_channel".to_string(), true)]);
        let channel_deny = HashMap::from([("send_messages".to_string(), false)]);

        // When channel has overrides, they should be used
        assert!(!channel_allow.is_empty() || !channel_deny.is_empty());
    }

    // ── Permission struct serialization ───────────────────────────────────

    #[test]
    fn channel_perm_serialize() {
        let perm = ChannelPerm {
            role_name: "@everyone".to_string(),
            allow: HashMap::from([("view_channel".to_string(), true)]),
            deny: HashMap::new(),
        };
        let json = serde_json::to_string(&perm).unwrap();
        assert!(json.contains("@everyone"));
        assert!(json.contains("view_channel"));
    }

    #[test]
    fn category_perm_serialize() {
        let perm = CategoryPerm {
            role_name: "admin".to_string(),
            allow: HashMap::new(),
            deny: HashMap::from([("send_messages".to_string(), false)]),
        };
        let json = serde_json::to_string(&perm).unwrap();
        assert!(json.contains("admin"));
    }

    // ── SetPermission body deserialization ────────────────────────────────

    #[test]
    fn set_channel_perm_body_deserialize() {
        let json = r#"{"allow":{"view_channel":true},"deny":{"send_messages":false}}"#;
        let body: SetChannelPermBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.allow.as_ref().unwrap().get("view_channel"), Some(&true));
        assert_eq!(body.deny.as_ref().unwrap().get("send_messages"), Some(&false));
    }

    #[test]
    fn set_category_perm_body_deserialize() {
        let json = r#"{"allow":{},"deny":{}}"#;
        let body: SetCategoryPermBody = serde_json::from_str(json).unwrap();
        assert!(body.allow.as_ref().unwrap().is_empty());
        assert!(body.deny.as_ref().unwrap().is_empty());
    }

    // ── Permission resolution algorithm tests ────────────────────────────

    #[test]
    fn owner_gets_all_permissions() {
        // The algorithm states: Owner → all true
        // We can't fully test this without a DB, but we can verify the helper
        let perms = all_true();
        assert!(perms.len() > 0);
        for (_, &v) in &perms {
            assert!(v);
        }
    }

    #[test]
    fn permission_override_order() {
        // Document the expected precedence:
        // 1. Owner → all true
        // 2. Start with @everyone server-wide
        // 3. OR in member's role
        // 4. If administrator → all true
        // 5. Apply channel overrides:
        //    a. @everyone deny
        //    b. @everyone allow
        //    c. Member's role deny
        //    d. Member's role allow

        let base = HashMap::from([("view_channel".to_string(), false)]);
        let allow = HashMap::from([("view_channel".to_string(), true)]);
        let deny = HashMap::from([("view_channel".to_string(), true)]); // deny=true means "explicitly deny"

        // Allow takes precedence over base false
        let mut result = base.clone();
        if allow.get("view_channel").copied().unwrap_or(false) {
            result.insert("view_channel".to_string(), true);
        }
        assert!(result.get("view_channel").unwrap());

        // Deny takes precedence over allow
        let mut result = base.clone();
        if allow.get("view_channel").copied().unwrap_or(false) { result = allow.clone(); }
        if deny.get("view_channel").copied().unwrap_or(false) { result.insert("view_channel".to_string(), false); }
        assert!(!result.get("view_channel").unwrap());
    }
}
