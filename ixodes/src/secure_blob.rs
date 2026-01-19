use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use const_random::const_random;
use std::str;
use thiserror::Error;
use zeroize::Zeroizing;

const AES_KEY: [u8; 32] = [
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
];

const AES_NONCE: [u8; 12] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];
const BLOB_AAD: &[u8] = b"ixodes blob v1";
const BLOB_MARKER: u128 = const_random!(u128);

#[derive(Debug)]
pub struct SecretBlob {
    inner: Zeroizing<String>,
}

#[derive(Debug, Error)]
pub enum SecureBlobError {
    #[error("invalid AES key length for secure blob")]
    InvalidKeyLength,
    #[error("secure blob decryption failed")]
    Decryption,
    #[error("secure blob is not valid UTF-8: {0}")]
    Utf8(str::Utf8Error),
}

impl SecretBlob {
    pub fn decrypt() -> Result<Self, SecureBlobError> {
        let cipher = {
            let key = Zeroizing::new(AES_KEY);
            let cipher =
                Aes256Gcm::new_from_slice(&*key).map_err(|_| SecureBlobError::InvalidKeyLength)?;
            cipher
        };

        let nonce = Nonce::from_slice(&AES_NONCE);
        let ciphertext = include_bytes!("assets/secret.blob");
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: BLOB_AAD,
                },
            )
            .map_err(|_| SecureBlobError::Decryption)?;

        let text =
            String::from_utf8(plaintext).map_err(|err| SecureBlobError::Utf8(err.utf8_error()))?;
        Ok(Self {
            inner: Zeroizing::new(text),
        })
    }

    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn marker(&self) -> u128 {
        BLOB_MARKER
    }

    pub fn preview(&self, limit: usize) -> &str {
        if limit == 0 {
            return "";
        }

        let text = self.as_str();
        match text.char_indices().nth(limit) {
            Some((idx, _)) => &text[..idx],
            None => text,
        }
    }
}
