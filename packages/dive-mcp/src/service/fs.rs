#[cfg(not(feature = "local_ipc"))]
use std::time::Duration;

use crate::service::DiveDefaultService;
#[cfg(feature = "local_ipc")]
use rmcp::model::ElicitationAction;
#[cfg(not(feature = "local_ipc"))]
use rmcp::model::{CreateElicitationRequestParam, ElicitationAction};
use rmcp::{
    ErrorData as McpError, Peer,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ElicitationSchema, EnumSchema, PrimitiveSchema},
    service::RoleServer,
    tool, tool_router,
};

use base64::{Engine as _, engine::general_purpose};
use serde::Deserialize;
use tokio::fs;
use tokio::io::AsyncReadExt;

#[cfg(not(feature = "local_ipc"))]
const ELICITATION_TIMEOUT: u64 = 600;

#[derive(Deserialize, schemars::JsonSchema)]
struct ReadFileParams {
    /// The path to the file to read
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct WriteFileParams {
    /// The path to the file to write
    path: String,
    /// The content to write to the file
    content: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ListDirectoryParams {
    /// The path to the directory to list
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct CreateDirectoryParams {
    /// The path to the directory to create
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DeleteFileParams {
    /// The path to the file to delete
    path: String,
}

#[allow(dead_code)]
#[derive(Deserialize, schemars::JsonSchema)]
struct AllowDirParams {
    /// The path to the directory to allow
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct DenyDirParams {
    /// The path to the directory to deny (remove from allowed list)
    path: String,
}

/// Check if a file is binary by reading the first 8KB and looking for null bytes
async fn is_binary_file(path: &str) -> Result<bool, std::io::Error> {
    let mut file = fs::File::open(path).await?;
    let mut buffer = vec![0u8; 8192];
    let bytes_read = file.read(&mut buffer).await?;

    // Check for null bytes in the first chunk
    Ok(buffer[..bytes_read].contains(&0))
}

/// Permission choice enum values
const PERMISSION_ALWAYS: &str = "always";
const PERMISSION_YES: &str = "yes";
const PERMISSION_NO: &str = "no";

/// Create the permission elicitation schema
fn create_permission_schema() -> ElicitationSchema {
    let mut properties = std::collections::BTreeMap::new();
    properties.insert(
        "choice".to_string(),
        PrimitiveSchema::Enum(
            EnumSchema::new(vec![
                PERMISSION_ALWAYS.to_string(),
                PERMISSION_YES.to_string(),
                PERMISSION_NO.to_string(),
            ])
            .enum_names(vec![
                "Always (remember this choice)".to_string(),
                "Yes (allow this time)".to_string(),
                "No (deny access)".to_string(),
            ])
            .description("Select your permission choice"),
        ),
    );

    ElicitationSchema::new(properties).with_required(vec!["choice".to_string()])
}

#[tool_router(router = tool_router_fs, vis = "pub")]
impl DiveDefaultService {
    /// Resolve `.` and `..` components without touching the filesystem.
    ///
    /// Needed for targets `canonicalize` cannot resolve (a file or directory
    /// that does not exist yet): an unresolved `..` would otherwise survive
    /// into the allow-list comparison and step outside the approved directory.
    fn lexical_normalize(path: &std::path::Path) -> std::path::PathBuf {
        use std::path::Component;

        let mut normalized = std::path::PathBuf::new();
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::ParentDir => {
                    normalized.pop();
                }
                other => normalized.push(other),
            }
        }
        normalized
    }

    /// Normalize path to absolute path
    fn normalize_path(path: &str) -> String {
        match std::fs::canonicalize(path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => {
                let path_buf = std::path::PathBuf::from(path);
                if let Some(parent) = path_buf.parent() {
                    match std::fs::canonicalize(parent) {
                        Ok(p) => p
                            .join(path_buf.file_name().unwrap_or_default())
                            .to_string_lossy()
                            .to_string(),
                        Err(_) => Self::lexical_normalize(&path_buf)
                            .to_string_lossy()
                            .to_string(),
                    }
                } else {
                    Self::lexical_normalize(&path_buf)
                        .to_string_lossy()
                        .to_string()
                }
            }
        }
    }

    /// Get the parent directory of a path
    fn get_parent_dir(path: &str) -> Option<String> {
        let path_buf = std::path::PathBuf::from(path);
        path_buf
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Check if a path is within allowed directories (without elicitation)
    ///
    /// Matching is component-wise, so approving `/home/user/docs` must not also
    /// authorize the name-prefixed sibling `/home/user/docs_backup`.
    fn is_path_allowed(abs_path: &str, allowed_dirs: &[String]) -> bool {
        use std::path::{Component, Path};

        let path = Path::new(abs_path);

        // Only fully resolved absolute paths can be matched against the
        // allow-list; anything else is sent back for a fresh prompt.
        if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            return false;
        }

        allowed_dirs.iter().any(|allowed_dir| {
            let allowed = Path::new(allowed_dir);
            // `Path::starts_with` accepts an empty prefix, so an empty or
            // relative entry in fs.json would otherwise match every path.
            allowed.is_absolute() && path.starts_with(allowed)
        })
    }

    /// Check path permission with elicitation support (using MCP peer elicitation)
    #[cfg(not(feature = "local_ipc"))]
    async fn check_path_permission_with_elicitation(
        &self,
        path: &str,
        operation: &str,
        peer: &Peer<RoleServer>,
    ) -> Result<(), McpError> {
        let abs_path = Self::normalize_path(path);

        // Check if already allowed
        {
            let allowed_dirs = self.allowed_dirs.read().await;
            if Self::is_path_allowed(&abs_path, &allowed_dirs) {
                return Ok(());
            }
        }

        // Check if client supports elicitation
        if !peer.supports_elicitation() {
            return Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!(
                    "Access denied: {} is not within allowed directories. Client does not support elicitation for permission request.",
                    abs_path
                ),
                None,
            ));
        }

        // Request permission via elicitation
        let message = format!(
            "Permission required for {} operation on:\n{}\n\nAllow access?",
            operation, abs_path
        );

        let result = peer
            .create_elicitation_with_timeout(
                CreateElicitationRequestParam {
                    message,
                    requested_schema: create_permission_schema(),
                },
                Some(Duration::from_secs(ELICITATION_TIMEOUT)),
            )
            .await
            .map_err(|e| {
                McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to request permission: {}", e),
                    None,
                )
            })?;

        match result.action {
            ElicitationAction::Accept => {
                if let Some(content) = result.content {
                    let choice = content
                        .get("choice")
                        .and_then(|v| v.as_str())
                        .unwrap_or(PERMISSION_NO);

                    match choice {
                        PERMISSION_ALWAYS => {
                            // Add parent directory to allowed list
                            let dir_to_allow =
                                Self::get_parent_dir(&abs_path).unwrap_or_else(|| abs_path.clone());

                            let mut allowed_dirs = self.allowed_dirs.write().await;
                            if !allowed_dirs.contains(&dir_to_allow) {
                                allowed_dirs.push(dir_to_allow);
                            }
                            drop(allowed_dirs);

                            // Save to config
                            let _ = self.save_allowed_dirs().await;
                            Ok(())
                        }
                        PERMISSION_YES => Ok(()),
                        _ => Err(McpError::new(
                            rmcp::model::ErrorCode::INVALID_REQUEST,
                            format!("Access denied by user: {}", abs_path),
                            None,
                        )),
                    }
                } else {
                    Err(McpError::new(
                        rmcp::model::ErrorCode::INVALID_REQUEST,
                        "No permission choice provided".to_string(),
                        None,
                    ))
                }
            }
            ElicitationAction::Decline | ElicitationAction::Cancel => Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!("Access denied: {}", abs_path),
                None,
            )),
        }
    }

    /// Check path permission with elicitation support (using local IPC / libdive)
    #[cfg(feature = "local_ipc")]
    async fn check_path_permission_with_elicitation(
        &self,
        path: &str,
        operation: &str,
        _peer: &Peer<RoleServer>,
    ) -> Result<(), McpError> {
        let abs_path = Self::normalize_path(path);

        // Check if already allowed
        {
            let allowed_dirs = self.allowed_dirs.read().await;
            if Self::is_path_allowed(&abs_path, &allowed_dirs) {
                return Ok(());
            }
        }

        // Request permission via local IPC (libdive)
        let message = format!(
            "Permission required for {} operation on:\n{}\n\nAllow access?",
            operation, abs_path
        );

        let result = crate::local_ipc::request_elicitation(message, create_permission_schema())
            .await
            .map_err(|e| {
                McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to request permission via local IPC: {}", e),
                    None,
                )
            })?;

        match result.action {
            ElicitationAction::Accept => {
                if let Some(content) = result.content {
                    let choice = content
                        .get("choice")
                        .and_then(|v| v.as_str())
                        .unwrap_or(PERMISSION_NO);

                    match choice {
                        PERMISSION_ALWAYS => {
                            // Add parent directory to allowed list
                            let dir_to_allow =
                                Self::get_parent_dir(&abs_path).unwrap_or_else(|| abs_path.clone());

                            let mut allowed_dirs = self.allowed_dirs.write().await;
                            if !allowed_dirs.contains(&dir_to_allow) {
                                allowed_dirs.push(dir_to_allow);
                            }
                            drop(allowed_dirs);

                            // Save to config
                            let _ = self.save_allowed_dirs().await;
                            Ok(())
                        }
                        PERMISSION_YES => Ok(()),
                        _ => Err(McpError::new(
                            rmcp::model::ErrorCode::INVALID_REQUEST,
                            format!("Access denied by user: {}", abs_path),
                            None,
                        )),
                    }
                } else {
                    Err(McpError::new(
                        rmcp::model::ErrorCode::INVALID_REQUEST,
                        "No permission choice provided".to_string(),
                        None,
                    ))
                }
            }
            ElicitationAction::Decline | ElicitationAction::Cancel => Err(McpError::new(
                rmcp::model::ErrorCode::INVALID_REQUEST,
                format!("Access denied: {}", abs_path),
                None,
            )),
        }
    }

    #[tool(description = "Read file content from the specified path")]
    async fn read_file(
        &self,
        peer: Peer<RoleServer>,
        Parameters(params): Parameters<ReadFileParams>,
    ) -> Result<CallToolResult, McpError> {
        // Check permission with elicitation
        self.check_path_permission_with_elicitation(&params.path, "read", &peer)
            .await?;

        // Check if file is binary
        let is_binary = match is_binary_file(&params.path).await {
            Ok(is_bin) => is_bin,
            Err(e) => {
                return Err(McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to check file type: {}", e),
                    None,
                ));
            }
        };

        if is_binary {
            // Read binary file and encode as base64
            match fs::read(&params.path).await {
                Ok(bytes) => {
                    let base64_content = general_purpose::STANDARD.encode(&bytes);
                    Ok(CallToolResult::success(vec![Content::text(format!(
                        "[Binary file encoded as base64]\n{}",
                        base64_content
                    ))]))
                }
                Err(e) => Err(McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to read binary file: {}", e),
                    None,
                )),
            }
        } else {
            // Read text file normally
            match fs::read_to_string(&params.path).await {
                Ok(content) => Ok(CallToolResult::success(vec![Content::text(content)])),
                Err(e) => Err(McpError::new(
                    rmcp::model::ErrorCode::INTERNAL_ERROR,
                    format!("Failed to read file: {}", e),
                    None,
                )),
            }
        }
    }

    #[tool(description = "Write content to a file at the specified path")]
    async fn write_file(
        &self,
        peer: Peer<RoleServer>,
        Parameters(params): Parameters<WriteFileParams>,
    ) -> Result<CallToolResult, McpError> {
        // Check permission with elicitation
        self.check_path_permission_with_elicitation(&params.path, "write", &peer)
            .await?;

        match fs::write(&params.path, &params.content).await {
            Ok(_) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Successfully wrote to {}",
                params.path
            ))])),
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to write file: {}", e),
                None,
            )),
        }
    }

    #[tool(description = "List all files and directories in the specified path")]
    async fn list_directory(
        &self,
        peer: Peer<RoleServer>,
        Parameters(params): Parameters<ListDirectoryParams>,
    ) -> Result<CallToolResult, McpError> {
        // Check permission with elicitation
        self.check_path_permission_with_elicitation(&params.path, "list", &peer)
            .await?;

        match fs::read_dir(&params.path).await {
            Ok(mut entries) => {
                let mut items = Vec::new();
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Ok(file_name) = entry.file_name().into_string() {
                        let file_type = if entry.path().is_dir() {
                            "directory"
                        } else {
                            "file"
                        };
                        items.push(format!("{} ({})", file_name, file_type));
                    }
                }
                Ok(CallToolResult::success(vec![Content::text(
                    items.join("\n"),
                )]))
            }
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to list directory: {}", e),
                None,
            )),
        }
    }

    #[tool(description = "Create a new directory at the specified path")]
    async fn create_directory(
        &self,
        peer: Peer<RoleServer>,
        Parameters(params): Parameters<CreateDirectoryParams>,
    ) -> Result<CallToolResult, McpError> {
        // Check permission with elicitation
        self.check_path_permission_with_elicitation(&params.path, "create directory", &peer)
            .await?;

        match fs::create_dir_all(&params.path).await {
            Ok(_) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Successfully created directory: {}",
                params.path
            ))])),
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to create directory: {}", e),
                None,
            )),
        }
    }

    #[tool(description = "Delete a file at the specified path")]
    async fn delete_file(
        &self,
        peer: Peer<RoleServer>,
        Parameters(params): Parameters<DeleteFileParams>,
    ) -> Result<CallToolResult, McpError> {
        // Check permission with elicitation
        self.check_path_permission_with_elicitation(&params.path, "delete", &peer)
            .await?;

        match fs::remove_file(&params.path).await {
            Ok(_) => Ok(CallToolResult::success(vec![Content::text(format!(
                "Successfully deleted file: {}",
                params.path
            ))])),
            Err(e) => Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to delete file: {}", e),
                None,
            )),
        }
    }

    // #[tool(description = "Add a directory to the allowed directories list")]
    // async fn allow_dir(
    //     &self,
    //     Parameters(params): Parameters<AllowDirParams>,
    // ) -> Result<CallToolResult, McpError> {
    //     // Normalize the path to absolute path
    //     let path = match std::fs::canonicalize(&params.path) {
    //         Ok(p) => p.to_string_lossy().to_string(),
    //         Err(e) => {
    //             return Err(McpError::new(
    //                 rmcp::model::ErrorCode::INVALID_PARAMS,
    //                 format!("Invalid path: {}", e),
    //                 None,
    //             ));
    //         }
    //     };
    //
    //     let mut allowed_dirs = self.allowed_dirs.write().await;
    //     if !allowed_dirs.contains(&path) {
    //         allowed_dirs.push(path.clone());
    //     }
    //     drop(allowed_dirs);
    //
    //     if let Err(e) = self.save_allowed_dirs().await {
    //         return Err(McpError::new(
    //             rmcp::model::ErrorCode::INTERNAL_ERROR,
    //             format!("Failed to save allowed directories: {}", e),
    //             None,
    //         ));
    //     }
    //
    //     Ok(CallToolResult::success(vec![Content::text(format!(
    //         "Successfully added {} to allowed directories",
    //         path
    //     ))]))
    // }

    #[tool(description = "Remove a directory from the allowed directories list")]
    async fn deny_dir(
        &self,
        Parameters(params): Parameters<DenyDirParams>,
    ) -> Result<CallToolResult, McpError> {
        // Normalize the path to absolute path
        let path = match std::fs::canonicalize(&params.path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(e) => {
                return Err(McpError::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    format!("Invalid path: {}", e),
                    None,
                ));
            }
        };

        let mut allowed_dirs = self.allowed_dirs.write().await;
        allowed_dirs.retain(|d| d != &path);
        drop(allowed_dirs);

        if let Err(e) = self.save_allowed_dirs().await {
            return Err(McpError::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                format!("Failed to save allowed directories: {}", e),
                None,
            ));
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Successfully removed {} from allowed directories",
            path
        ))]))
    }

    // #[tool(description = "List all allowed directories")]
    // async fn list_allow_dir(&self) -> Result<CallToolResult, McpError> {
    //     let allowed_dirs = self.allowed_dirs.read().await;
    //
    //     if allowed_dirs.is_empty() {
    //         Ok(CallToolResult::success(vec![Content::text(
    //             "No allowed directories configured".to_string(),
    //         )]))
    //     } else {
    //         Ok(CallToolResult::success(vec![Content::text(
    //             allowed_dirs.join("\n"),
    //         )]))
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::DiveDefaultService as Fs;

    fn allowed(path: &str) -> Vec<String> {
        vec![path.to_string()]
    }

    #[test]
    fn allows_the_approved_dir_and_its_descendants() {
        let dirs = allowed("/home/user/docs");

        assert!(Fs::is_path_allowed("/home/user/docs", &dirs));
        assert!(Fs::is_path_allowed("/home/user/docs/notes.txt", &dirs));
        assert!(Fs::is_path_allowed("/home/user/docs/sub/deep/notes.txt", &dirs));
    }

    #[test]
    fn rejects_name_prefixed_siblings() {
        let dirs = allowed("/home/user/docs");

        assert!(!Fs::is_path_allowed("/home/user/docs_backup/secret.key", &dirs));
        assert!(!Fs::is_path_allowed("/home/user/docs.old/secret.key", &dirs));
        assert!(!Fs::is_path_allowed("/home/user/docsecret", &dirs));
        assert!(!Fs::is_path_allowed("/home/user/documents/id_rsa", &dirs));
    }

    #[test]
    fn rejects_unrelated_and_parent_paths() {
        let dirs = allowed("/home/user/docs");

        assert!(!Fs::is_path_allowed("/etc/passwd", &dirs));
        assert!(!Fs::is_path_allowed("/home/user", &dirs));
        assert!(!Fs::is_path_allowed("/", &dirs));
    }

    #[test]
    fn rejects_traversal_out_of_the_approved_dir() {
        let dirs = allowed("/home/user/docs");

        assert!(!Fs::is_path_allowed("/home/user/docs/../../../etc/passwd", &dirs));
        assert!(!Fs::is_path_allowed("/home/user/docs/../ssh/id_rsa", &dirs));
    }

    #[test]
    fn rejects_relative_paths() {
        let dirs = allowed("/home/user/docs");

        assert!(!Fs::is_path_allowed("docs/notes.txt", &dirs));
        assert!(!Fs::is_path_allowed("", &dirs));
    }

    #[test]
    fn ignores_unusable_allow_list_entries() {
        // A hand-edited or corrupt fs.json must not turn into allow-everything.
        assert!(!Fs::is_path_allowed("/etc/passwd", &allowed("")));
        assert!(!Fs::is_path_allowed("/etc/passwd", &allowed("docs")));
        assert!(!Fs::is_path_allowed("/etc/passwd", &[]));
    }

    #[test]
    fn matches_any_entry_in_a_multi_dir_allow_list() {
        let dirs = vec![
            "/home/user/docs".to_string(),
            "/srv/shared".to_string(),
        ];

        assert!(Fs::is_path_allowed("/srv/shared/report.pdf", &dirs));
        assert!(!Fs::is_path_allowed("/srv/shared_private/report.pdf", &dirs));
    }

    #[test]
    fn lexical_normalize_resolves_dot_components() {
        let normalize = |p: &str| {
            Fs::lexical_normalize(std::path::Path::new(p))
                .to_string_lossy()
                .to_string()
        };

        assert_eq!(normalize("/home/user/docs/./notes.txt"), "/home/user/docs/notes.txt");
        assert_eq!(normalize("/home/user/docs/../../etc/passwd"), "/home/etc/passwd");
        assert_eq!(normalize("/home/user/docs/.."), "/home/user");
        // Never climbs above the root.
        assert_eq!(normalize("/../../etc"), "/etc");
    }

    #[test]
    fn normalized_traversal_cannot_reach_a_sibling_dir() {
        // `create_dir_all` accepts targets whose parents do not exist yet, so
        // such paths reach the gate via the lexical fallback rather than
        // `canonicalize`. They must still be confined.
        let dirs = allowed("/home/user/docs");
        let escaped = Fs::normalize_path("/home/user/docs/../docs_backup/new/dir");

        assert!(!Fs::is_path_allowed(&escaped, &dirs));
    }
}
