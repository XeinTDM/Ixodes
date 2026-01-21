#[macro_export]
macro_rules! obf {
    ($s:expr) => {{
        const KEY: u8 = 0xBD;
        let mut b = $s.as_bytes().to_vec();
        for i in 0..b.len() {
            b[i] ^= KEY;
        }
        b
    }};
}

pub fn deobf(bytes: &[u8]) -> String {
    const KEY: u8 = 0xBD;
    let mut b = bytes.to_vec();
    for i in 0..b.len() {
        b[i] ^= KEY;
    }
    String::from_utf8_lossy(&b).to_string()
}

pub fn deobf_w(bytes: &[u8]) -> Vec<u16> {
    const KEY: u8 = 0xBD;
    let mut b = bytes.to_vec();
    for i in 0..b.len() {
        b[i] ^= KEY;
    }
    let s = String::from_utf8_lossy(&b);
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
