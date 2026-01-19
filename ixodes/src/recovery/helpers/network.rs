use crate::recovery::task::RecoveryError;
use serde::Deserialize;
use serde_json::Value;
use tokio::process::Command;

pub struct NetworkTrafficStat {
    pub name: String,
    pub received_bytes: Option<u64>,
    pub transmitted_bytes: Option<u64>,
}

pub async fn gather_network_traffic() -> Result<Vec<NetworkTrafficStat>, RecoveryError> {
    let script = r#"Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Depth 1"#;
    let value = capture_powershell_json(script).await?;
    Ok(parse_network_stats(value))
}

async fn capture_powershell_json(script: &str) -> Result<Value, RecoveryError> {
    let output = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(script)
        .output()
        .await?;

    if !output.status.success() {
        return Err(RecoveryError::Custom(format!(
            "PowerShell command failed with code {:?}",
            output.status.code()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(Value::Null);
    }

    serde_json::from_str(stdout.trim())
        .map_err(|err| RecoveryError::Custom(format!("PowerShell JSON parse failed: {err}")))
}

fn parse_network_stats(value: Value) -> Vec<NetworkTrafficStat> {
    let mut adapters = Vec::new();
    match value {
        Value::Array(items) => {
            for item in items {
                if let Ok(raw) = serde_json::from_value::<RawNetAdapterStat>(item) {
                    adapters.push(raw.into());
                }
            }
        }
        Value::Object(_) => {
            if let Ok(raw) = serde_json::from_value::<RawNetAdapterStat>(value) {
                adapters.push(raw.into());
            }
        }
        _ => {}
    }
    adapters
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawNetAdapterStat {
    name: String,
    received_bytes: Option<u64>,
    sent_bytes: Option<u64>,
}

impl From<RawNetAdapterStat> for NetworkTrafficStat {
    fn from(raw: RawNetAdapterStat) -> Self {
        Self {
            name: raw.name,
            received_bytes: raw.received_bytes,
            transmitted_bytes: raw.sent_bytes,
        }
    }
}
