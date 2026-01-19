use winreg::RegValue;

pub fn format_reg_value(value: &RegValue) -> String {
    let text = String::from_utf8_lossy(&value.bytes)
        .trim_end_matches('\0')
        .to_string();

    if text.is_empty() {
        format!("hex:{}", bytes_to_hex(&value.bytes))
    } else {
        text
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join("")
}
