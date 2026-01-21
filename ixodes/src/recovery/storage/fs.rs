use crate::recovery::task::{RecoveryArtifact, RecoveryError};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::warn;

pub async fn copy_dir_limited(
    src: &Path,
    dst: &Path,
    label: &str,
    artifacts: &mut Vec<RecoveryArtifact>,
    max_depth: usize,
    file_limit: usize,
) -> Result<(), RecoveryError> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf(), 0usize)];

    while let Some((current_src, current_dst, depth)) = stack.pop() {
        if reached_limit(artifacts.len(), file_limit) {
            break;
        }

        if max_depth > 0 && depth >= max_depth {
            continue;
        }

        fs::create_dir_all(&current_dst).await?;

        let mut entries = match fs::read_dir(&current_src).await {
            Ok(dir) => dir,
            Err(err) => {
                warn!(path=?current_src, error=?err, "failed to read directory");
                continue;
            }
        };

        while let Some(entry) = entries.next_entry().await? {
            if reached_limit(artifacts.len(), file_limit) {
                break;
            }

            let path = entry.path();
            let file_name = entry.file_name();
            let target = current_dst.join(&file_name);

            let metadata = match entry.metadata().await {
                Ok(metadata) => metadata,
                Err(err) => {
                    warn!(path=?path, error=?err, "failed to read metadata");
                    continue;
                }
            };

            if metadata.is_dir() {
                stack.push((path, target, depth + 1));
            } else if metadata.is_file() {
                if let Err(err) = fs::copy(&path, &target).await {
                    warn!(src=?path, dst=?target, error=?err, "failed to copy file");
                    continue;
                }
                let copied_meta = fs::metadata(&target).await?;
                artifacts.push(RecoveryArtifact {
                    label: label.to_string(),
                    path: target,
                    size_bytes: copied_meta.len(),
                    modified: copied_meta.modified().ok(),
                });
            }
        }
    }

    Ok(())
}

pub async fn copy_file(
    label: &str,
    src: &Path,
    dst_root: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    if !src.exists() {
        return Ok(());
    }

    fs::create_dir_all(dst_root).await?;
    let file_name = src
        .file_name()
        .ok_or_else(|| RecoveryError::Custom("invalid source filename".into()))?;
    
    let destination = dst_root.join(file_name);
    fs::copy(src, &destination).await?;
    
    let meta = fs::metadata(&destination).await?;
    artifacts.push(RecoveryArtifact {
        label: label.to_string(),
        path: destination,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    });
    
    Ok(())
}

pub async fn copy_named_dir(
    label: &str,
    src: &Path,
    dst: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    match fs::metadata(src).await {
        Ok(meta) if meta.is_dir() => {
            copy_dir_limited(src, dst, label, artifacts, usize::MAX, 0).await?;
        }
        _ => {}
    }
    Ok(())
}

fn reached_limit(current: usize, limit: usize) -> bool {
    limit > 0 && current >= limit
}

pub fn sanitize_label(label: &str) -> String {
    let filtered: String = label
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            _ => ch,
        })
        .collect();

    filtered.trim_matches('.').trim().to_string()
}
