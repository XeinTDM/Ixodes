use rand::RngCore;
use rand::rngs::OsRng;
use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = OsRng;
    let seed = rng.next_u64();

    let mut task_salt = [0u8; 8];
    rng.fill_bytes(&mut task_salt);

    let mut shuffle_block = [0u8; 16];
    rng.fill_bytes(&mut shuffle_block);

    let mut summary_order = [0u8, 1, 2, 3];
    shuffle(&mut summary_order, &mut rng);

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
        "pub const SUMMARY_FIELD_ORDER: [u8; 4] = [{}];",
        hex_list(&summary_order)
    )?;
    writeln!(
        file,
        "pub const BULK_RANDOM_BLOCK: [u8; 16] = [{}];",
        hex_list(&shuffle_block)
    )?;

    Ok(())
}

fn shuffle(buf: &mut [u8], rng: &mut OsRng) {
    for i in (1..buf.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        buf.swap(i, j);
    }
}

fn hex_list(values: &[u8]) -> String {
    let mut pieces = Vec::with_capacity(values.len());
    for byte in values {
        pieces.push(format!("0x{byte:02x}"));
    }
    pieces.join(", ")
}
