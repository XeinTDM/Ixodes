use std::ffi::c_void;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::core::{PCSTR, PCWSTR};

#[repr(C)]
struct SyscallStub {
    ssn: u32,
    address: *const c_void,
}

pub struct SyscallManager {
    pub nt_protect_virtual_memory_ssn: u32,
    #[allow(dead_code)]
    pub nt_write_virtual_memory_ssn: u32,
    pub syscall_gadget: *const c_void,
}

impl SyscallManager {
    pub fn new() -> Result<Self, String> {
        let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(std::iter::once(0)).collect();
        let h_ntdll = unsafe { GetModuleHandleW(PCWSTR(ntdll_name.as_ptr())) }.map_err(|e| e.to_string())?;
        
        let syscall_gadget = find_syscall_gadget(h_ntdll.0 as *const u8)?;
        
        let nt_protect = resolve_syscall(h_ntdll.0 as *const u8, "NtProtectVirtualMemory")?;
        let nt_write = resolve_syscall(h_ntdll.0 as *const u8, "NtWriteVirtualMemory")?;

        Ok(Self {
            nt_protect_virtual_memory_ssn: nt_protect.ssn,
            nt_write_virtual_memory_ssn: nt_write.ssn,
            syscall_gadget,
        })
    }
}

use crate::recovery::helpers::pe::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};

fn find_syscall_gadget(ntdll_base: *const u8) -> Result<*const c_void, String> {
    unsafe {
        let dos_header = &*(ntdll_base as *const IMAGE_DOS_HEADER);
        let nt_headers = &*(ntdll_base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let size_of_image = nt_headers.optional_header.size_of_image as usize;

        for i in 0..(size_of_image - 2) {
            let ptr = ntdll_base.add(i);
            if *ptr == 0x0F && *ptr.add(1) == 0x05 && *ptr.add(2) == 0xC3 {
                return Ok(ptr as *const c_void);
            }
        }
    }
    Err("Failed to find syscall gadget".to_string())
}

fn resolve_syscall(ntdll_base: *const u8, function_name: &str) -> Result<SyscallStub, String> {
    let func_name_c = format!("{}\0", function_name);
    let address = unsafe { GetProcAddress(windows::Win32::Foundation::HMODULE(ntdll_base as _), PCSTR(func_name_c.as_ptr())) };
    let addr = address.ok_or_else(|| format!("Failed to find {}", function_name))? as *const u8;
    
    unsafe {
        for i in 0..32 {
            if *addr.add(i) == 0xB8 {
                let ssn = *(addr.add(i + 1) as *const u32);
                return Ok(SyscallStub { ssn, address: addr as _ });
            }
        }
    }
    Err(format!("Failed to extract SSN for {}", function_name))
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn indirect_syscall_5(ssn: u32, gadget: *const c_void, a1: isize, a2: isize, a3: isize, a4: isize, a5: isize) -> i32 {
    let mut status: i32;
    unsafe {
        std::arch::asm!(
            "sub rsp, 0x28",
            "mov [rsp + 0x20], {arg5}",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x28",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            arg5 = in(reg) a5,
            in("rcx") a1,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            out("rax") status,
        );
    }
    status
}