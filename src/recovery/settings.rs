use crate::recovery::task::RecoveryCategory;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use once_cell::sync::Lazy;
use std::{collections::HashSet, env, str::FromStr};
use tracing::{info, warn};

static GLOBAL_RECOVERY_CONTROL: Lazy<RecoveryControl> = Lazy::new(RecoveryControl::from_env);

#[derive(Debug)]
pub struct RecoveryControl {
    allow_sensitive_tasks: bool,
    allow_external_api: bool,
    allowed_categories: Option<HashSet<RecoveryCategory>>,
    artifact_key: Option<Vec<u8>>,
}

impl RecoveryControl {
    pub fn global() -> &'static Self {
        &GLOBAL_RECOVERY_CONTROL
    }

    pub fn allow_sensitive_tasks(&self) -> bool {
        self.allow_sensitive_tasks
    }

    pub fn allow_external_api(&self) -> bool {
        self.allow_external_api
    }

    pub fn allows_category(&self, category: RecoveryCategory) -> bool {
        self.allowed_categories
            .as_ref()
            .map(|set| set.contains(&category))
            .unwrap_or(true)
    }

    pub fn artifact_key(&self) -> Option<&[u8]> {
        self.artifact_key.as_deref()
    }

    fn from_env() -> Self {
        let allow_sensitive = parse_flag("IXODES_ALLOW_SENSITIVE");
        let allow_external = parse_flag("IXODES_ALLOW_EXTERNAL_API");
        let allowed_categories = env::var("IXODES_ENABLED_CATEGORIES")
            .ok()
            .and_then(|value| parse_categories(&value));

        if let Some(categories) = allowed_categories.as_ref() {
            info!(
                "restricting recovery to {} categories",
                categories
                    .iter()
                    .map(|category| category.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        let artifact_key = env::var("IXODES_ARTIFACT_KEY").ok().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return None;
            }
            match STANDARD.decode(trimmed) {
                Ok(bytes) => {
                    if bytes.len() != 32 {
                        warn!(
                            "artifact encryption key must be 32 bytes (base64); got {} bytes",
                            bytes.len()
                        );
                        None
                    } else {
                        Some(bytes)
                    }
                }
                Err(err) => {
                    warn!(
                        error = ?err,
                        "failed to decode artifact encryption key"
                    );
                    None
                }
            }
        });

        if artifact_key.is_some() {
            info!("artifact encryption enabled");
        }

        RecoveryControl {
            allow_sensitive_tasks: allow_sensitive,
            allow_external_api: allow_external,
            allowed_categories,
            artifact_key,
        }
    }
}

fn parse_flag(key: &str) -> bool {
    env::var(key)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn parse_categories(value: &str) -> Option<HashSet<RecoveryCategory>> {
    let mut set = HashSet::new();
    for segment in value.split(',') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        match RecoveryCategory::from_str(trimmed) {
            Ok(category) => {
                set.insert(category);
            }
            Err(err) => {
                warn!("skipping invalid category filter {trimmed}: {err}");
            }
        }
    }
    if set.is_empty() { None } else { Some(set) }
}
