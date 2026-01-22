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

    let mut rng = OsRng;
    let seed = rng.next_u64();

    let mut task_salt = [0u8; 8];
    rng.fill_bytes(&mut task_salt);

    let mut shuffle_block = [0u8; 16];
    rng.fill_bytes(&mut shuffle_block);

    const VARIANTS: [&str; 4] = ["alpha", "beta", "gamma", "delta"];
    let variant = VARIANTS[(rng.next_u32() as usize) % VARIANTS.len()];
    println!("cargo:rustc-cfg=build_variant={variant:?}");

    for candidate in VARIANTS.iter() {
        println!(
            "cargo:rustc-check-cfg=cfg(build_variant, values({candidate:?}))",
            candidate = candidate
        );
    }

    let out_dir = env::var("OUT_DIR")?;
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
