//! IP-based and user-based rate limiting with sliding-window buckets.
//!
//! Provides rate limiting for sensitive endpoints:
//! - /login (via auth server proxy): 5 attempts/minute per IP
//! - /register (via auth server proxy): 3 attempts/minute per IP  
//! - /v1/upload: 10 uploads/minute per user
//! - /v1/invites/* (create): 10 creates/minute per user

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use crate::client_ip;

/// A single bucket in the sliding-window rate limiter.
/// Tracks request timestamps for precise window-based counting.
#[derive(Debug)]
struct RateBucket {
    /// Ring buffer of request timestamps within the window
    requests: Vec<Instant>,
    /// Window duration in seconds
    window_secs: u64,
    /// Maximum requests allowed per window
    max_requests: u32,
}

impl RateBucket {
    fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            requests: Vec::with_capacity(max_requests as usize),
            window_secs,
            max_requests,
        }
    }

    /// Check if the request is allowed and record it if so.
    /// Returns (allowed, remaining_count, retry_after_secs).
    fn check_and_record(&mut self, now: Instant) -> (bool, u32, u64) {
        let window = Duration::from_secs(self.window_secs);
        let cutoff = now - window;

        // Remove expired entries (outside the sliding window)
        self.requests.retain(|&t| t > cutoff);

        // Check if we're under the limit
        if self.requests.len() >= self.max_requests as usize {
            // Rate limit exceeded - calculate retry after
            if let Some(oldest) = self.requests.first() {
                let retry_after = (window - (now - *oldest)).as_secs().max(1);
                return (false, 0, retry_after);
            }
            return (false, 0, self.window_secs);
        }

        // Record this request
        self.requests.push(now);
        let remaining = self.max_requests - self.requests.len() as u32;
        (true, remaining, 0)
    }

    /// Get current count without recording.
    #[allow(dead_code)]
    fn count(&self, now: Instant) -> usize {
        let window = Duration::from_secs(self.window_secs);
        let cutoff = now - window;
        self.requests.iter().filter(|&&t| t > cutoff).count()
    }

    /// Check if there are any requests after the given cutoff time.
    fn has_recent_requests(&self, cutoff: Instant) -> bool {
        self.requests.iter().any(|&t| t > cutoff)
    }
}

/// In-memory rate limit store using sliding-window buckets.
pub struct RateLimitStore {
    /// IP-based buckets for login/register attempts
    ip_buckets: Mutex<HashMap<String, RateBucket>>,
    /// User-based buckets for upload limiting (key: "upload:{user_id}")
    upload_buckets: Mutex<HashMap<String, RateBucket>>,
    /// User-based buckets for invite creation (key: "invite:{user_id}")
    invite_buckets: Mutex<HashMap<String, RateBucket>>,
}

impl RateLimitStore {
    pub fn new() -> Self {
        Self {
            ip_buckets: Mutex::new(HashMap::new()),
            upload_buckets: Mutex::new(HashMap::new()),
            invite_buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Clean up expired buckets to prevent memory growth.
    /// Should be called periodically (e.g., every minute).
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Clean up IP buckets (2x longest window)
        {
            let mut guard = self.ip_buckets.lock().unwrap();
            let cutoff = now - Duration::from_secs(LOGIN_WINDOW_SECS * 2);
            guard.retain(|_, bucket| bucket.has_recent_requests(cutoff));
        }

        // Clean up upload buckets
        {
            let mut guard = self.upload_buckets.lock().unwrap();
            let cutoff = now - Duration::from_secs(UPLOAD_WINDOW_SECS * 2);
            guard.retain(|_, bucket| bucket.has_recent_requests(cutoff));
        }

        // Clean up invite buckets
        {
            let mut guard = self.invite_buckets.lock().unwrap();
            let cutoff = now - Duration::from_secs(INVITE_WINDOW_SECS * 2);
            guard.retain(|_, bucket| bucket.has_recent_requests(cutoff));
        }
    }
}

// ── Rate limit constants ─────────────────────────────────────────────────────

/// Login: 5 attempts per minute per IP
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
pub const LOGIN_WINDOW_SECS: u64 = 60;

/// Register: 3 attempts per minute per IP (reserved for future use)
pub const _REGISTER_MAX_ATTEMPTS: u32 = 3;
pub const _REGISTER_WINDOW_SECS: u64 = 60;

/// Upload: 10 uploads per minute per user
pub const UPLOAD_MAX_PER_MINUTE: u32 = 10;
pub const UPLOAD_WINDOW_SECS: u64 = 60;

/// Invite creation: 10 creates per minute per user
pub const INVITE_MAX_PER_MINUTE: u32 = 10;
pub const INVITE_WINDOW_SECS: u64 = 60;

// ── Rate limiting functions ──────────────────────────────────────────────────

/// Check IP-based rate limit for login attempts.
/// Returns Err(response) if rate limited.
pub fn check_login_rate_limit(
    store: &RateLimitStore,
    ip: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    check_ip_limit(
        &store.ip_buckets,
        ip,
        "login",
        LOGIN_MAX_ATTEMPTS,
        LOGIN_WINDOW_SECS,
    )
}

/// Check IP-based rate limit for register attempts.
/// Returns Err(response) if rate limited.
#[allow(dead_code)]
pub fn check_register_rate_limit(
    store: &RateLimitStore,
    ip: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    check_ip_limit(
        &store.ip_buckets,
        ip,
        "register",
        _REGISTER_MAX_ATTEMPTS,
        _REGISTER_WINDOW_SECS,
    )
}

/// Check user-based rate limit for uploads.
/// Returns Err(response) if rate limited.
pub fn check_upload_rate_limit(
    store: &RateLimitStore,
    user_id: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    check_user_limit(
        &store.upload_buckets,
        user_id,
        "upload",
        UPLOAD_MAX_PER_MINUTE,
        UPLOAD_WINDOW_SECS,
    )
}

/// Check user-based rate limit for invite creation.
/// Returns Err(response) if rate limited.
pub fn check_invite_rate_limit(
    store: &RateLimitStore,
    user_id: &str,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    check_user_limit(
        &store.invite_buckets,
        user_id,
        "invite",
        INVITE_MAX_PER_MINUTE,
        INVITE_WINDOW_SECS,
    )
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn check_ip_limit(
    buckets: &Mutex<HashMap<String, RateBucket>>,
    ip: &str,
    endpoint: &str,
    max_requests: u32,
    window_secs: u64,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let mut guard = buckets.lock().unwrap();
    let bucket = guard
        .entry(ip.to_string())
        .or_insert_with(|| RateBucket::new(max_requests, window_secs));

    let now = Instant::now();
    let (allowed, _remaining, retry_after) = bucket.check_and_record(now);

    if !allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({
                "error": format!("Rate limit exceeded: {} requests per {} seconds for {}",
                    max_requests, window_secs, endpoint),
                "retry_after": retry_after,
            })),
        ));
    }

    Ok(())
}

fn check_user_limit(
    buckets: &Mutex<HashMap<String, RateBucket>>,
    user_id: &str,
    action: &str,
    max_requests: u32,
    window_secs: u64,
) -> Result<(), (StatusCode, axum::Json<serde_json::Value>)> {
    let mut guard = buckets.lock().unwrap();
    let bucket = guard
        .entry(user_id.to_string())
        .or_insert_with(|| RateBucket::new(max_requests, window_secs));

    let now = Instant::now();
    let (allowed, _remaining, retry_after) = bucket.check_and_record(now);

    if !allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({
                "error": format!("Rate limit exceeded: {} {} per {} seconds",
                    max_requests, action, window_secs),
                "retry_after": retry_after,
            })),
        ));
    }

    Ok(())
}

/// Extract client IP for rate limiting from headers and socket address.
/// Convenience wrapper around the main::client_ip function.
pub fn extract_client_ip(
    headers: &HeaderMap,
    socket_ip: &IpAddr,
    trusted_proxies: &[String],
) -> String {
    client_ip(headers, socket_ip, trusted_proxies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_bucket_allows_under_limit() {
        let mut bucket = RateBucket::new(5, 60);
        let now = Instant::now();

        for _ in 0..5 {
            let (allowed, _, _) = bucket.check_and_record(now);
            assert!(allowed);
        }
    }

    #[test]
    fn rate_bucket_blocks_over_limit() {
        let mut bucket = RateBucket::new(2, 60);
        let now = Instant::now();

        // First 2 should succeed
        let (allowed1, _, _) = bucket.check_and_record(now);
        assert!(allowed1);
        let (allowed2, _, _) = bucket.check_and_record(now);
        assert!(allowed2);

        // Third should fail
        let (allowed3, _, _) = bucket.check_and_record(now);
        assert!(!allowed3);
    }

    #[test]
    fn rate_bucket_sliding_window() {
        let mut bucket = RateBucket::new(2, 1); // 2 per 1 second
        let now = Instant::now();

        // First 2 succeed
        assert!(bucket.check_and_record(now).0);
        assert!(bucket.check_and_record(now).0);

        // Third fails
        assert!(!bucket.check_and_record(now).0);

        // Wait for window to slide
        std::thread::sleep(Duration::from_millis(1100));
        let later = Instant::now();

        // Old entries expired, new request succeeds
        assert!(bucket.check_and_record(later).0);
    }

    #[test]
    fn store_creates_different_buckets() {
        let store = RateLimitStore::new();
        let now = Instant::now();

        // Check login for IP
        {
            let mut guard = store.ip_buckets.lock().unwrap();
            let bucket = guard
                .entry("192.168.1.1".to_string())
                .or_insert_with(|| RateBucket::new(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECS));
            assert!(bucket.check_and_record(now).0);
        }

        // Check upload for user
        {
            let mut guard = store.upload_buckets.lock().unwrap();
            let bucket = guard
                .entry("user123".to_string())
                .or_insert_with(|| RateBucket::new(UPLOAD_MAX_PER_MINUTE, UPLOAD_WINDOW_SECS));
            assert!(bucket.check_and_record(now).0);
        }
    }

    #[test]
    fn constants_match_requirements() {
        assert_eq!(LOGIN_MAX_ATTEMPTS, 5);
        assert_eq!(LOGIN_WINDOW_SECS, 60);
        assert_eq!(_REGISTER_MAX_ATTEMPTS, 3);
        assert_eq!(_REGISTER_WINDOW_SECS, 60);
        assert_eq!(UPLOAD_MAX_PER_MINUTE, 10);
        assert_eq!(UPLOAD_WINDOW_SECS, 60);
        assert_eq!(INVITE_MAX_PER_MINUTE, 10);
        assert_eq!(INVITE_WINDOW_SECS, 60);
    }
}
