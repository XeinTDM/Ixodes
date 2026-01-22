pub fn deobf(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    use crate::build_config::OBFUSCATION_KEY as KEY;

    let mut b = bytes.to_vec();
    for i in 0..b.len() {
        let key_byte = KEY[i % KEY.len()];
        b[i] ^= key_byte;
        b[i] = b[i].rotate_right((i % 8) as u32);
        b[i] = b[i].wrapping_sub((i.wrapping_mul(7)) as u8);
    }

    String::from_utf8_lossy(&b).to_string()
}

pub fn deobf_w(bytes: &[u8]) -> Vec<u16> {
    let s = deobf(bytes);
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[macro_export]
macro_rules! obf {
    ($s:expr) => {{
        let bytes = $s.as_bytes();
        let key = &$crate::build_config::OBFUSCATION_KEY;
        let mut b = bytes.to_vec();
        for i in 0..b.len() {
            b[i] = b[i].wrapping_add((i.wrapping_mul(7)) as u8);
            b[i] = b[i].rotate_left((i % 8) as u32);
            b[i] ^= key[i % key.len()];
        }
        b
    }};
}

#[macro_export]
macro_rules! stack_str {
    ($($c:expr),*) => {{
        let mut s = String::with_capacity(32);
        $( s.push($c); )*
        s
    }};
}
