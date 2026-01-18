use crate::recovery::task::RecoveryError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::path::Path;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};
use windows::Win32::System::Memory::LocalFree;

pub fn extract_master_key(local_state_path: &Path) -> Result<Option<Vec<u8>>, RecoveryError> {
    let data = std::fs::read(local_state_path).map_err(|err| RecoveryError::Io(err))?;
    let json: serde_json::Value =
        serde_json::from_slice(&data).map_err(|err| RecoveryError::Custom(err.to_string()))?;

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

        if !success.as_bool() {
            return Err(RecoveryError::Custom("CryptUnprotectData failed".into()));
        }

        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        if !output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData as isize));
        }
        Ok(result)
    }
}
