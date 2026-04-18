use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::config::AppState;

// ─── Bridge Secret Auth ───────────────────────────────────────────────────────

/// Middleware to validate X-Bridge-Secret header
pub async fn bridge_secret_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Skip auth for health endpoint
    let path = request.uri().path();
    if path == "/health" {
        return Ok(next.run(request).await);
    }

    // If no secret is configured, skip auth entirely
    if state.config.bridge_secret.is_empty() {
        return Ok(next.run(request).await);
    }

    let headers = request.headers();
    let secret = headers
        .get("X-Bridge-Secret")
        .and_then(|v| v.to_str().ok());

    match secret {
        Some(s) if s == state.config.bridge_secret.as_str() => {
            Ok(next.run(request).await)
        }
        _ => {
            let error_response = axum::Json(serde_json::json!({
                "error": "Invalid or missing bridge secret"
            }));
            Err((StatusCode::UNAUTHORIZED, error_response).into_response())
        }
    }
}

// ─── CORS ─────────────────────────────────────────────────────────────────────

use axum::http::HeaderValue;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub fn build_cors_layer(allowed_origins: &[String], zpulse_url: &str) -> CorsLayer {
    let mut origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    // Also allow zpulse internal URL
    if let Ok(header) = zpulse_url.parse::<HeaderValue>() {
        origins.push(header);
    }

    // Parse zpulse_url to add its origin (extract scheme + host + port)
    if let Ok(url) = url::Url::parse(zpulse_url) {
        let origin = url.origin().ascii_serialization();
        if !origin.is_empty() && origin != "null" {
            if let Ok(header) = origin.parse::<HeaderValue>() {
                if !origins.contains(&header) {
                    origins.push(header);
                }
            }
        }
    }

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::DELETE])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::HeaderName::from_static("x-bridge-secret"),
        ])
}
