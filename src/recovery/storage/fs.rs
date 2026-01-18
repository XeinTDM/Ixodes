use crate::recovery::task::{RecoveryArtifact, RecoveryError};
use std::path::Path;
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
            Err(err) => return Err(err.into()),
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
                fs::copy(&path, &target).await?;
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
