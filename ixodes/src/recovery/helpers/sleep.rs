use std::ffi::c_void;
use tracing::debug;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::Threading::{
    CreateWaitableTimerW, SetWaitableTimer, WaitForSingleObject,
};

#[repr(C)]
struct Ustring {
    length: u32,
    maximum_length: u32,
    buffer: *mut c_void,
}

type SystemFunction032 = unsafe extern "system" fn(data: *mut Ustring, key: *mut Ustring) -> i32;

pub fn stealth_sleep(millis: u32) {
    if millis == 0 {
        return;
    }

    unsafe {
        let advapi32_name: Vec<u16> = "advapi32.dll".encode_utf16().chain(std::iter::once(0)).collect();
        let h_advapi32 = GetModuleHandleW(PCWSTR(advapi32_name.as_ptr())).unwrap_or_default();
        let func_032_name = PCSTR("SystemFunction032\0".as_ptr());
        let p_system_function_032 = GetProcAddress(h_advapi32, func_032_name);

        let Some(sys_func_032_ptr) = p_system_function_032 else {
            debug!("SystemFunction032 not found, falling back to normal sleep");
            std::thread::sleep(std::time::Duration::from_millis(millis as u64));
            return;
        };

        let _sys_func_032: SystemFunction032 = std::mem::transmute(sys_func_032_ptr);

        let mut key_data = [0u8; 16];
        for i in 0..16 {
            key_data[i] = (i * 42) as u8;
        }
        let _key = Ustring {
            length: 16,
            maximum_length: 16,
            buffer: key_data.as_mut_ptr() as *mut c_void,
        };

        debug!("entering stealthy sleep for {}ms", millis);
        
        let timer = CreateWaitableTimerW(None, true, None).unwrap_or(HANDLE(0));
        if timer.is_invalid() {
            std::thread::sleep(std::time::Duration::from_millis(millis as u64));
            return;
        }

        let due_time = -( (millis as i64) * 10000 );
        if SetWaitableTimer(timer, &due_time, 0, None, None, false).is_ok() {
            WaitForSingleObject(timer, 0xFFFFFFFF);
        }

        let _ = windows::Win32::Foundation::CloseHandle(timer);
        debug!("exiting stealthy sleep");
    }
}
