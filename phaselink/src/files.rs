use super::*;
use axum::extract::{ConnectInfo, Extension};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::rate_limit::check_upload_rate_limit;

#[derive(Serialize, utoipa::ToSchema)]
pub struct AttachmentUploadResponse {
    pub attachment_id: i64,
    pub filename: String,
    pub mime_type: String,
    pub file_size: i64,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct UploadResult {
    pub ok: bool,
    pub attachments: Vec<AttachmentUploadResponse>,
}

const ALLOWED_MIME_TYPES: &[&str] = &[
    // Images
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/svg+xml",
    // Videos
    "video/mp4",
    "video/webm",
    // Audio
    "audio/mpeg",
    "audio/ogg",
    "audio/wav",
    // Documents
    "application/pdf",
    "text/plain",
    "text/markdown",
    // Archives
    "application/zip",
    "application/x-zip-compressed",
];

fn sanitize_filename(filename: &str) -> String {
    let sanitized = filename.replace("..", "").replace(['/', '\\'], "_");
    if sanitized.len() > 255 {
        if let Some(ext_pos) = sanitized.rfind('.') {
            let ext = &sanitized[ext_pos..];
            let max_name_len = 255 - ext.len();
            if max_name_len > 0 {
                format!("{}{}", &sanitized[..max_name_len], ext)
            } else {
                sanitized[..255].to_string()
            }
        } else {
            sanitized[..255].to_string()
        }
    } else {
        sanitized
    }
}

/// Store an uploaded file to disk if `attachments_dir` is configured, returning
/// the file path. If the directory is not set, returns `None` (BLOB mode).
fn store_to_disk(attachments_dir: &str, attachment_id: i64, data: &[u8]) -> Result<String, std::io::Error> {
    std::fs::create_dir_all(attachments_dir)?;
    let path = format!("{}/{}", attachments_dir, attachment_id);
    let mut file = std::fs::File::create(&path)?;
    file.write_all(data)?;
    Ok(path)
}

/// POST /upload — upload one or more files and get attachment IDs
pub async fn upload_file(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    ConnectInfo(_sock_addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let identity = match require_auth(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    // ── Rate limit check ──────────────────────────────────────────────
    if let Err(e) = check_upload_rate_limit(&state.rate_limits, &identity) {
        return e.into_response();
    }

    let max_upload_bytes = state.settings.read().await.max_upload_bytes as i64;
    let attachments_dir = state.attachments_dir.clone();
    let mut attachments_data = Vec::new();
    let mut total_size = 0;

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let filename: String = match field.file_name() {
            Some(name) => sanitize_filename(name).to_string(),
            None => continue,
        };

        let mime_type: String = match field.content_type() {
            Some(mime) => mime.to_string(),
            None => continue,
        };

        if !ALLOWED_MIME_TYPES.contains(&mime_type.as_str()) {
            continue;
        }

        let mut bytes = Vec::new();
        while let Ok(Some(chunk)) = field.chunk().await {
            let chunk_len = chunk.len() as i64;
            total_size += chunk_len;
            if total_size > max_upload_bytes {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(json!({
                        "error": format!("File too large. Maximum size is {}.", humanize_bytes(max_upload_bytes as u64))
                    })),
                )
                    .into_response();
            }
            bytes.extend_from_slice(&chunk);
        }

        attachments_data.push((filename, mime_type, bytes));
    }

    if attachments_data.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "No valid files uploaded" })),
        )
            .into_response();
    }

    if total_size > max_upload_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": format!("Total file size exceeds {} limit.", humanize_bytes(max_upload_bytes as u64)) })),
        )
            .into_response();
    }

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    let mut response_attachments = Vec::new();

    for (filename, mime_type, data) in attachments_data {
      let file_size = data.len() as i64;

      // First insert the attachment record to get the real ID
      // For disk storage mode, initially set file_path to NULL
      let data_param: Option<&[u8]> = if attachments_dir.is_some() { None } else { Some(&data) };
      let file_path_null: Option<&str> = None;

      let attachment_id = match db.execute(
        "INSERT INTO attachments (filename, mime_type, file_size, file_data, file_path, uploaded_by)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![filename, mime_type, file_size, data_param, file_path_null, &identity],
      ) {
        Ok(_) => db.last_insert_rowid(),
        Err(e) => {
          error!("insert attachment: {e}");
          return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to store file" })),
          ).into_response();
        }
      };

      // Disk storage mode: write file to disk using the real ID
      if let Some(ref dir) = attachments_dir {
        match store_to_disk(dir, attachment_id, &data) {
          Ok(path) => {
            // Update the attachment record with the file path
            if let Err(e) = db.execute(
              "UPDATE attachments SET file_path = ?1 WHERE id = ?2",
              rusqlite::params![path, attachment_id],
            ) {
              // If update fails, delete the orphaned attachment row
              error!("failed to update attachment with file_path: {e}");
              let _ = db.execute(
                "DELETE FROM attachments WHERE id = ?1",
                rusqlite::params![attachment_id],
              );
              return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to store file" })),
              ).into_response();
            }
          }
          Err(e) => {
            // Disk write failed: roll back by deleting the orphaned attachment row
            error!("failed to write attachment to disk: {e}");
            let _ = db.execute(
              "DELETE FROM attachments WHERE id = ?1",
              rusqlite::params![attachment_id],
            );
            return (
              StatusCode::INTERNAL_SERVER_ERROR,
              Json(json!({ "error": "Failed to store file" })),
            ).into_response();
          }
        }
      }

      response_attachments.push(AttachmentUploadResponse {
        attachment_id,
        filename: filename.clone(),
        mime_type: mime_type.clone(),
        file_size,
      });
    }

    let count = response_attachments.len();
    let total_kb = total_size / 1024;
    info!("{identity} uploaded {count} file(s) ({total_kb} KB total)");
    Json(UploadResult {
        ok: true,
        attachments: response_attachments,
    })
    .into_response()
}

/// GET /attachments/:id — retrieve a file by attachment ID
pub async fn get_attachment(
    Extension(state): Extension<Arc<AppState>>,
    Path(attachment_id): Path<i64>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let auth_result = if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                validate_jwt(token, &*state).await
            } else {
                None
            }
        } else {
            None
        }
    } else if let Some(token) = params.get("token") {
        validate_jwt(token, &*state).await
    } else {
        None
    };

    let _identity = match auth_result {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or expired token" })),
            )
                .into_response();
        }
    };

    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "DB unavailable" })),
            )
                .into_response();
        }
    };

    // Try disk path first, fall back to BLOB
    let (filename, mime_type, file_size, file_path, file_data) = match db
        .prepare("SELECT filename, mime_type, file_size, file_path, file_data FROM attachments WHERE id = ?1")
    {
        Ok(mut stmt) => {
            match stmt.query_row(rusqlite::params![attachment_id], |row| {
                let filename: String = row.get(0)?;
                let mime_type: String = row.get(1)?;
                let file_size: i64 = row.get(2)?;
                let file_path: Option<String> = row.get(3)?;
                let file_data: Option<Vec<u8>> = row.get(4)?;
                Ok((filename, mime_type, file_size, file_path, file_data))
            }) {
                Ok(att) => att,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "Attachment not found" })),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("query attachment: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Database error" })),
                    )
                        .into_response();
                }
            }
        }
        Err(e) => {
            error!("prepare statement: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database error" })),
            )
                .into_response();
        }
    };

    let data = match (file_path, file_data) {
        (Some(path), _) => {
            match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("failed to read attachment from disk ({path}): {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "File storage error" })),
                    ).into_response();
                }
            }
        }
        (None, Some(bytes)) => bytes,
        (None, None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Attachment data missing" })),
            ).into_response();
        }
    };

    debug!("attachment {attachment_id} served: {filename} ({file_size} bytes)");
    (
        [
            (axum::http::header::CONTENT_TYPE, mime_type),
            (axum::http::header::CONTENT_DISPOSITION, format!("inline; filename=\"{}\"", filename)),
            (axum::http::header::CONTENT_LENGTH, file_size.to_string()),
        ],
        data,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_filename_removes_traversal() {
        // ".." is replaced with "", then path separators become "_"
        // "../../etc/passwd" -> "//etc/passwd" -> "__etc_passwd"
        assert_eq!(sanitize_filename("../../etc/passwd"), "__etc_passwd");
        // "..\..\secret" -> "\\secret" -> "__secret"
        assert_eq!(sanitize_filename("..\\..\\secret"), "__secret");
    }

    #[test]
    fn sanitize_filename_replaces_separators() {
        assert_eq!(sanitize_filename("hello/world.txt"), "hello_world.txt");
        assert_eq!(sanitize_filename("foo\\bar.txt"), "foo_bar.txt");
    }

    #[test]
    fn sanitize_filename_preserves_extension_when_truncating() {
        let name = format!("a{}", "b".repeat(300));
        let result = sanitize_filename(&name);
        assert!(result.len() <= 255);
    }

    #[test]
    fn sanitize_filename_within_limit_unchanged() {
        let name = "normal_file.txt";
        assert_eq!(sanitize_filename(name), "normal_file.txt");
    }

    #[test]
    fn sanitize_filename_removes_double_dots() {
        // ".." is replaced with "", so "..." becomes "." and "file..name" becomes "filename"
        assert_eq!(sanitize_filename("...hidden"), ".hidden");
        assert_eq!(sanitize_filename("file..name"), "filename");
    }

    #[test]
    fn sanitize_filename_truncation_no_extension() {
        let long = "a".repeat(300);
        let result = sanitize_filename(&long);
        assert!(result.len() <= 255);
        assert!(result.chars().all(|c| c == 'a'));
    }

    #[test]
    fn allowed_mime_types_contains_common_extensions() {
        assert!(ALLOWED_MIME_TYPES.contains(&"image/png"));
        assert!(ALLOWED_MIME_TYPES.contains(&"image/jpeg"));
        assert!(ALLOWED_MIME_TYPES.contains(&"video/mp4"));
        assert!(ALLOWED_MIME_TYPES.contains(&"audio/mpeg"));
        assert!(ALLOWED_MIME_TYPES.contains(&"application/pdf"));
    }

    #[test]
    fn disallowed_mime_types_not_in_list() {
        assert!(!ALLOWED_MIME_TYPES.contains(&"application/x-executable"));
        assert!(!ALLOWED_MIME_TYPES.contains(&"application/javascript"));
    }
}
