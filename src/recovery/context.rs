use directories::BaseDirs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct RecoveryContext {
    pub home_dir: PathBuf,
    pub local_data_dir: PathBuf,
    pub roaming_data_dir: PathBuf,
    pub output_dir: PathBuf,
    pub concurrency_limit: usize,
}

impl RecoveryContext {
    pub fn discover() -> Result<Self, RecoveryInitError> {
        let dirs = BaseDirs::new().ok_or(RecoveryInitError::BaseDirsUnavailable)?;
        let home_dir = dirs.home_dir().to_path_buf();
        let local_data_dir = dirs.data_local_dir().to_path_buf();
        let roaming_data_dir = dirs.data_dir().to_path_buf();
        let output_dir = dirs.cache_dir().join("ixodes").join("recovery");
        if output_dir.as_os_str().is_empty() {
            return Err(RecoveryInitError::InvalidOutputPath);
        }

        let concurrency_limit = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(1);

        Ok(Self {
            home_dir,
            local_data_dir,
            roaming_data_dir,
            output_dir,
            concurrency_limit,
        })
    }
}

#[derive(Debug, Error)]
pub enum RecoveryInitError {
    #[error("could not resolve OS-specific base directories")]
    BaseDirsUnavailable,
    #[error("computed output directory path is empty")]
    InvalidOutputPath,
}
