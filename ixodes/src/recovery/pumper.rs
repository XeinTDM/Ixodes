use crate::recovery::settings::RecoveryControl;
use rand::Rng;
use std::env;
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use tracing::{info, warn};

pub fn pump_file() {
    let target_size_mb = RecoveryControl::global().pump_size_mb();
    if target_size_mb == 0 {
        return;
    }

    let target_size_bytes = (target_size_mb as u64) * 1024 * 1024;

    if let Err(err) = pump_file_impl(target_size_bytes) {
        warn!(error = %err, "failed to pump file size");
    }
}

fn pump_file_impl(target_size: u64) -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let mut file = OpenOptions::new().read(true).write(true).open(&current_exe)?;

    let current_size = file.metadata()?.len();

    if current_size >= target_size {
        return Ok(());
    }

    let needed = target_size - current_size;
    file.seek(SeekFrom::End(0))?;

    let mut rng = rand::thread_rng();
    let chunk_size = 1024 * 512;
    let mut remaining = needed;

    while remaining > 0 {
        let to_write = std::cmp::min(remaining, chunk_size as u64) as usize;
        let mut buffer = vec![0u8; to_write];

        let mode = rng.gen_range(0..4);
        match mode {
            0 => {
                rng.fill(&mut buffer[..]);
            }
            1 => {
                let pattern = [0x41, 0x42, 0x43, 0x44, 0x00]; // ABCD.
                for i in 0..to_write {
                    buffer[i] = pattern[i % pattern.len()];
                }
            }
            2 => {
                for i in (0..to_write).step_by(16) {
                    if rng.gen_bool(0.1) {
                        buffer[i] = rng.r#gen();
                    }
                }
            }
            _ => {
                for i in 0..to_write {
                    buffer[i] = rng.gen_range(32..126);
                }
            }
        }

        file.write_all(&buffer)?;
        remaining -= to_write as u64;
    }

    info!(target_mb = target_size / 1024 / 1024, "file pumped realistically");
    Ok(())
}