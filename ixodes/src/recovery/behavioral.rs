use crate::recovery::{
    context::RecoveryContext,
    output::write_json_artifact,
    task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask},
};
use async_trait::async_trait;
use libloading::Library;
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use serde::Serialize;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{Duration as TokioDuration, sleep};
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_PROTECTION_FLAGS,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE, PAGE_WRITECOPY, VirtualQuery,
};

const TIMING_ITERATIONS: usize = 6;
const TIMING_SLEEP_DURATION_MS: u64 = 10;
const TIMING_MAX_RATIO: f64 = 1.75;
const TIMING_MAX_DEVIATION_MS: f64 = 30.0;

const SYSCALL_STUB_LEN: usize = 11;
const SYSCALL_PREFIX: [u8; 3] = [0x4C, 0x8B, 0xD1];
const SYSCALL_OPCODE: u8 = 0xB8;
const SYSCALL_SUFFIX: [u8; 3] = [0x0F, 0x05, 0xC3];
const CHECKSUM_PATTERN: [u8; 7] = [0x4C, 0x8B, 0xD1, 0xB8, 0x0F, 0x05, 0xC3];
const SPREAD_DELAY_MIN_MS: u64 = 20;
const SPREAD_DELAY_MAX_MS: u64 = 60;

struct HotPathInspector {
    library: Library,
}

impl HotPathInspector {
    fn new() -> Result<Self, String> {
        unsafe { Library::new("ntdll.dll") }
            .map(|library| Self { library })
            .map_err(|err| err.to_string())
    }

    fn resolve_symbol(&self, function_name: &str) -> Result<*const u8, String> {
        let symbol_name = format!("{function_name}\0");
        unsafe { self.library.get::<*const u8>(symbol_name.as_bytes()) }
            .map(|symbol| *symbol)
            .map_err(|err| err.to_string())
    }

    fn analyze_syscall(&self, info: &HotPathChecksum) -> SyscallFunctionCheck {
        let mut check = SyscallFunctionCheck {
            function: info.function.to_string(),
            observed_bytes: None,
            matches_expected_stub: false,
            checksum_expected: info.expected_hash(),
            checksum_observed: None,
            checksum_matches: None,
            cross_checksum_expected: info.cross_expected,
            cross_checksum_observed: None,
            cross_checksum_matches: None,
            reason: None,
            error: None,
        };

        match self.resolve_symbol(info.function) {
            Ok(ptr) => unsafe {
                let bytes = std::slice::from_raw_parts(ptr, SYSCALL_STUB_LEN);
                let collected = bytes.to_vec();
                check.observed_bytes = Some(hex_bytes(&collected));
                check.matches_expected_stub = matches_syscall_stub(&collected);
                if let Some(selected) = selected_syscall_bytes(&collected) {
                    let observed_hash = polynomial_hash(&selected, info.base);
                    check.checksum_observed = Some(observed_hash);
                    let matches = observed_hash == check.checksum_expected;
                    check.checksum_matches = Some(matches);
                    if !matches && check.reason.is_none() {
                        check.reason = Some(
                            "inline syscall checksum diverges from the expected hot-path pattern"
                                .to_string(),
                        );
                    }
                    let cross_observed = polynomial_hash(&selected, info.cross_base);
                    check.cross_checksum_observed = Some(cross_observed);
                    let cross_matches = cross_observed == info.cross_expected;
                    check.cross_checksum_matches = Some(cross_matches);
                    if !cross_matches && check.reason.is_none() {
                        check.reason = Some(
                            "cross-validation checksum diverges from the secondary pattern"
                                .to_string(),
                        );
                    }
                }

                if !check.matches_expected_stub && check.reason.is_none() {
                    check.reason = Some(
                        "entry bytes diverge from the expected inline syscall pattern".to_string(),
                    );
                }
            },
            Err(err) => {
                check.error = Some(err.clone());
                check.reason = Some("failed to resolve syscall entry".to_string());
            }
        }

        check
    }

    fn inspect_page_protection(&self, function_name: &str) -> PageProtectionObservation {
        let mut observation = PageProtectionObservation {
            function: function_name.to_string(),
            protection: None,
            suspicious: false,
            reason: None,
        };

        match self.resolve_symbol(function_name) {
            Ok(ptr) => unsafe {
                let address = ptr as *const c_void;
                let mut info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
                let length = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
                if VirtualQuery(Some(address), info.as_mut_ptr(), length) == 0 {
                    observation.reason = Some(format!(
                        "VirtualQuery failed: {}",
                        std::io::Error::last_os_error()
                    ));
                } else {
                    let info = info.assume_init();
                    observation.protection = Some(format_page_protection_label(info.Protect));
                    observation.suspicious = is_page_protection_suspicious(info.Protect);
                    if observation.suspicious && observation.reason.is_none() {
                        observation.reason = Some(
                            "observed protection diverges from the expected read-execute state"
                                .to_string(),
                        );
                    }
                }
            },
            Err(err) => {
                observation.reason = Some(err);
            }
        }

        observation
    }
}

#[derive(Clone, Copy)]
struct HotPathChecksum {
    function: &'static str,
    base: u64,
    cross_base: u64,
    cross_expected: u64,
}

impl HotPathChecksum {
    fn expected_hash(&self) -> u64 {
        polynomial_hash(&CHECKSUM_PATTERN, self.base)
    }
}

const HOT_PATH_CHECKSUMS: [HotPathChecksum; 3] = [
    HotPathChecksum {
        function: "NtQuerySystemInformation",
        base: 257,
        cross_base: 267,
        cross_expected: 28088091275950780,
    },
    HotPathChecksum {
        function: "NtOpenProcess",
        base: 263,
        cross_base: 273,
        cross_expected: 32089670685948526,
    },
    HotPathChecksum {
        function: "NtReadVirtualMemory",
        base: 269,
        cross_base: 279,
        cross_expected: 36555449606258128,
    },
];

const PAGE_PROTECTION_BASE_MASK: u32 = 0xFF;
const PAGE_PROTECTION_EXPECTED_BASES: [u32; 2] = [PAGE_EXECUTE.0, PAGE_EXECUTE_READ.0];

const SINGLE_STEP_ITERATIONS: usize = 64;
const SINGLE_STEP_THRESHOLD_CYCLES: u64 = 2_400;
const SINGLE_STEP_INNER_LOOP: usize = 16;

pub fn behavioral_tasks(_ctx: &RecoveryContext) -> Vec<Arc<dyn RecoveryTask>> {
    vec![
        Arc::new(TimingDistortionTask),
        Arc::new(SyscallAnomaliesTask),
        Arc::new(PageProtectionTask),
        Arc::new(SingleStepDetectionTask),
        Arc::new(SpreadValidationTask),
        Arc::new(EnvironmentalDiscoveryTask),
        Arc::new(DebuggerDetectionTask),
    ]
}

pub async fn check_behavioral() -> bool {
    let mut suspicious = false;

    let debugger = collect_debugger_summary();
    if debugger.suspicious {
        suspicious = true;
    }

    // VM/Sandbox
    let env = collect_environmental_summary();
    if env.suspicious {
        suspicious = true;
    }

    let timing = collect_timing_summary().await;
    if timing.suspicious {
        suspicious = true;
    }

    let syscall = inspect_syscall_anomalies();
    if syscall.anomalies_detected {
        suspicious = true;
    }

    let pages = inspect_page_protections();
    if pages.anomalies_detected {
        suspicious = true;
    }

    let step = collect_single_step_summary();
    if step.suspicious {
        suspicious = true;
    }

    !suspicious
}

struct DebuggerDetectionTask;

#[async_trait]
impl RecoveryTask for DebuggerDetectionTask {
    fn label(&self) -> String {
        "Behavioral: Debugger Detection".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = collect_debugger_summary();
        if summary.suspicious {
            return Err(RecoveryError::KillSwitchTriggered);
        }
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "behavioral-debugger-detection.json",
            &summary,
        )
        .await?;
        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct DebuggerSummary {
    suspicious: bool,
    checks: Vec<EnvironmentalCheck>,
}

fn collect_debugger_summary() -> DebuggerSummary {
    let mut checks = Vec::new();
    let mut suspicious = false;

    // Check PEB BeingDebugged flag
    let peb_debugged = is_peb_debugger_present();
    if peb_debugged {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "PEB BeingDebugged".to_string(),
        detected: peb_debugged,
        details: None,
    });

    // Check for NtGlobalFlag
    let nt_global_flag = is_nt_global_flag_set();
    if nt_global_flag {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "NtGlobalFlag Debugger".to_string(),
        detected: nt_global_flag,
        details: None,
    });

    DebuggerSummary { suspicious, checks }
}

fn is_peb_debugger_present() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let peb_debugged: u32;
        std::arch::asm!(
            "mov {tmp}, gs:[0x60]",
            "movzx {out:e}, byte ptr [{tmp} + 2]",
            tmp = out(reg) _,
            out = out(reg) peb_debugged,
        );
        (peb_debugged & 0xFF) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

fn is_nt_global_flag_set() -> bool {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let nt_global_flag: u32;
        std::arch::asm!(
            "mov {tmp}, gs:[0x60]",
            "mov {out:e}, dword ptr [{tmp} + 0xBC]",
            tmp = out(reg) _,
            out = out(reg) nt_global_flag,
        );
        // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
        (nt_global_flag & 0x70) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

struct EnvironmentalDiscoveryTask;

#[async_trait]
impl RecoveryTask for EnvironmentalDiscoveryTask {
    fn label(&self) -> String {
        "Behavioral: Environmental Discovery".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = collect_environmental_summary();
        if summary.suspicious {
            return Err(RecoveryError::KillSwitchTriggered);
        }
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "behavioral-environmental-discovery.json",
            &summary,
        )
        .await?;
        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct EnvironmentalSummary {
    suspicious: bool,
    checks: Vec<EnvironmentalCheck>,
}

#[derive(Serialize)]
struct EnvironmentalCheck {
    name: String,
    detected: bool,
    details: Option<String>,
}

fn collect_environmental_summary() -> EnvironmentalSummary {
    let mut checks = Vec::new();
    let mut suspicious = false;

    use crate::recovery::helpers::anti_vm;

    // Check for common VM files
    let vm_files = [
        "C:\\windows\\System32\\Drivers\\Vmmouse.sys",
        "C:\\windows\\System32\\Drivers\\vboxguest.sys",
        "C:\\windows\\System32\\Drivers\\vmhgfs.sys",
    ];

    for file in vm_files {
        let detected = std::path::Path::new(file).exists();
        if detected {
            suspicious = true;
        }
        checks.push(EnvironmentalCheck {
            name: format!("File Presence: {}", file),
            detected,
            details: None,
        });
    }

    // Check for RAM size (Sandboxes often have < 4GB)
    if let Ok(mem) = get_total_ram_gb() {
        let low_ram = mem < 4;
        if low_ram {
            suspicious = true;
        }
        checks.push(EnvironmentalCheck {
            name: "Low RAM Check".to_string(),
            detected: low_ram,
            details: Some(format!("{} GB", mem)),
        });
    }

    // CPUID Hypervisor Check
    let cpuid_vm = anti_vm::check_cpuid_hypervisor();
    if cpuid_vm {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "CPUID Hypervisor Bit".to_string(),
        detected: cpuid_vm,
        details: None,
    });

    // CPU Cores Check
    let low_cores = anti_vm::check_cpu_cores();
    if low_cores {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "Low CPU Cores (< 2)".to_string(),
        detected: low_cores,
        details: None,
    });

    // Screen Resolution Check
    let bad_res = anti_vm::check_screen_resolution();
    if bad_res {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "Suspicious Screen Resolution".to_string(),
        detected: bad_res,
        details: None,
    });

    // Process Enumeration (VM Tools)
    let vm_procs = anti_vm::check_processes();
    if vm_procs {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "VM Tools Processes".to_string(),
        detected: vm_procs,
        details: None,
    });

    // Username/Hostname Blocklist
    let bad_user = anti_vm::check_usernames();
    if bad_user {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "Blacklisted User/Host".to_string(),
        detected: bad_user,
        details: None,
    });

    // Disk Size Check
    let small_disk = anti_vm::check_disk_size();
    if small_disk {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "Small Disk (< 60GB)".to_string(),
        detected: small_disk,
        details: None,
    });

    // MAC Address OUI Check
    let bad_mac = anti_vm::check_mac_address();
    if bad_mac {
        suspicious = true;
    }
    checks.push(EnvironmentalCheck {
        name: "Virtual MAC OUI".to_string(),
        detected: bad_mac,
        details: None,
    });

    EnvironmentalSummary { suspicious, checks }
}

fn get_total_ram_gb() -> Result<u64, String> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    unsafe {
        let mut mem_status = MEMORYSTATUSEX::default();
        mem_status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if GlobalMemoryStatusEx(&mut mem_status).is_ok() {
            Ok(mem_status.ullTotalPhys / (1024 * 1024 * 1024))
        } else {
            Err("failed to get memory status".to_string())
        }
    }
}

struct TimingDistortionTask;

#[async_trait]
impl RecoveryTask for TimingDistortionTask {
    fn label(&self) -> String {
        "Behavioral: Timing Distortion".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = collect_timing_summary().await;
        if summary.suspicious {
            return Err(RecoveryError::KillSwitchTriggered);
        }
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "behavioral-timing-distortion.json",
            &summary,
        )
        .await?;
        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct TimingDistortionSummary {
    iterations: usize,
    expected_delay_ms: f64,
    max_ratio_threshold: f64,
    max_deviation_threshold_ms: f64,
    highest_ratio: f64,
    highest_deviation_ms: f64,
    suspicious: bool,
    observations: Vec<TimingObservation>,
}

#[derive(Serialize)]
struct TimingObservation {
    iteration: usize,
    elapsed_ms: f64,
    deviation_ms: f64,
    ratio: f64,
}

async fn collect_timing_summary() -> TimingDistortionSummary {
    let sleep_duration = TokioDuration::from_millis(TIMING_SLEEP_DURATION_MS);
    let expected_ms = TIMING_SLEEP_DURATION_MS as f64;
    let mut observations = Vec::with_capacity(TIMING_ITERATIONS);
    let mut highest_ratio = 0.0f64;
    let mut highest_deviation = 0.0f64;
    let mut suspicious = false;

    for index in 0..TIMING_ITERATIONS {
        let start = Instant::now();
        sleep(sleep_duration).await;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let ratio = if expected_ms > 0.0 {
            elapsed_ms / expected_ms
        } else {
            1.0
        };
        let deviation = elapsed_ms - expected_ms;

        highest_ratio = highest_ratio.max(ratio);
        highest_deviation = highest_deviation.max(deviation.abs());
        if ratio > TIMING_MAX_RATIO || deviation.abs() > TIMING_MAX_DEVIATION_MS {
            suspicious = true;
        }

        observations.push(TimingObservation {
            iteration: index + 1,
            elapsed_ms,
            deviation_ms: deviation,
            ratio,
        });
    }

    TimingDistortionSummary {
        iterations: TIMING_ITERATIONS,
        expected_delay_ms: expected_ms,
        max_ratio_threshold: TIMING_MAX_RATIO,
        max_deviation_threshold_ms: TIMING_MAX_DEVIATION_MS,
        highest_ratio,
        highest_deviation_ms: highest_deviation,
        suspicious,
        observations,
    }
}

struct SyscallAnomaliesTask;

#[async_trait]
impl RecoveryTask for SyscallAnomaliesTask {
    fn label(&self) -> String {
        "Behavioral: Syscall Anomalies".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = inspect_syscall_anomalies();
        if summary.anomalies_detected {
            return Err(RecoveryError::KillSwitchTriggered);
        }
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "behavioral-syscall-anomalies.json",
            &summary,
        )
        .await?;
        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct SyscallAnomalySummary {
    library_error: Option<String>,
    anomalies_detected: bool,
    functions: Vec<SyscallFunctionCheck>,
}

#[derive(Serialize)]
struct SyscallFunctionCheck {
    function: String,
    observed_bytes: Option<String>,
    matches_expected_stub: bool,
    checksum_expected: u64,
    checksum_observed: Option<u64>,
    checksum_matches: Option<bool>,
    cross_checksum_expected: u64,
    cross_checksum_observed: Option<u64>,
    cross_checksum_matches: Option<bool>,
    reason: Option<String>,
    error: Option<String>,
}

fn inspect_syscall_anomalies() -> SyscallAnomalySummary {
    match HotPathInspector::new() {
        Ok(inspector) => {
            let functions = HOT_PATH_CHECKSUMS
                .iter()
                .map(|candidate| inspector.analyze_syscall(candidate))
                .collect::<Vec<_>>();
            let anomalies_detected = functions.iter().any(|check| has_syscall_anomaly(check));
            SyscallAnomalySummary {
                library_error: None,
                anomalies_detected,
                functions,
            }
        }
        Err(err) => SyscallAnomalySummary {
            library_error: Some(err),
            anomalies_detected: false,
            functions: Vec::new(),
        },
    }
}

fn matches_syscall_stub(bytes: &[u8]) -> bool {
    if bytes.len() < SYSCALL_STUB_LEN {
        return false;
    }

    bytes.starts_with(&SYSCALL_PREFIX)
        && bytes[3] == SYSCALL_OPCODE
        && bytes[8..11] == SYSCALL_SUFFIX
}

fn selected_syscall_bytes(bytes: &[u8]) -> Option<[u8; 7]> {
    if bytes.len() < SYSCALL_STUB_LEN {
        return None;
    }

    let mut pattern = [0u8; 7];
    pattern[..4].copy_from_slice(&bytes[..4]);
    pattern[4..].copy_from_slice(&bytes[8..SYSCALL_STUB_LEN]);
    Some(pattern)
}

fn polynomial_hash(bytes: &[u8], base: u64) -> u64 {
    let mut hash = 0u64;
    for &value in bytes {
        hash = hash
            .wrapping_mul(base)
            .wrapping_add(u64::from(value).wrapping_add(1));
    }
    hash
}

fn has_syscall_anomaly(check: &SyscallFunctionCheck) -> bool {
    (check.observed_bytes.is_some() && !check.matches_expected_stub)
        || matches!(check.checksum_matches, Some(false))
        || matches!(check.cross_checksum_matches, Some(false))
}

struct SpreadValidationTask;

#[async_trait]
impl RecoveryTask for SpreadValidationTask {
    fn label(&self) -> String {
        "Behavioral: Spread Validation Checks".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = collect_spread_validation_summary().await;
        if summary.suspicious {
            return Err(RecoveryError::KillSwitchTriggered);
        }
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "behavioral-spread-validation.json",
            &summary,
        )
        .await?;
        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct SpreadValidationSummary {
    checks: Vec<SpreadCheckSummary>,
    total_checks: usize,
    suspicious: bool,
    library_error: Option<String>,
}

#[derive(Serialize)]
struct SpreadCheckSummary {
    function: String,
    delay_ms: u64,
    observed_bytes: Option<String>,
    stub_matches: bool,
    checksum_expected: u64,
    checksum_observed: Option<u64>,
    checksum_matches: Option<bool>,
    cross_checksum_expected: u64,
    cross_checksum_observed: Option<u64>,
    cross_checksum_matches: Option<bool>,
    reason: Option<String>,
}

impl SpreadCheckSummary {
    fn from_syscall(check: &SyscallFunctionCheck, delay_ms: u64) -> Self {
        Self {
            function: check.function.clone(),
            delay_ms,
            observed_bytes: check.observed_bytes.clone(),
            stub_matches: check.matches_expected_stub,
            checksum_expected: check.checksum_expected,
            checksum_observed: check.checksum_observed,
            checksum_matches: check.checksum_matches,
            cross_checksum_expected: check.cross_checksum_expected,
            cross_checksum_observed: check.cross_checksum_observed,
            cross_checksum_matches: check.cross_checksum_matches,
            reason: check.reason.clone(),
        }
    }
}

async fn collect_spread_validation_summary() -> SpreadValidationSummary {
    match HotPathInspector::new() {
        Ok(inspector) => run_spread_checks(inspector).await,
        Err(err) => SpreadValidationSummary {
            checks: Vec::new(),
            total_checks: 0,
            suspicious: true,
            library_error: Some(err),
        },
    }
}

async fn run_spread_checks(inspector: HotPathInspector) -> SpreadValidationSummary {
    let mut rng = StdRng::from_entropy();
    let mut candidates = HOT_PATH_CHECKSUMS.to_vec();
    candidates.shuffle(&mut rng);
    let mut checks = Vec::with_capacity(candidates.len());
    let mut suspicious = false;

    for info in candidates {
        let delay = rng.gen_range(SPREAD_DELAY_MIN_MS..=SPREAD_DELAY_MAX_MS);
        sleep(TokioDuration::from_millis(delay)).await;
        let check = inspector.analyze_syscall(&info);
        suspicious |= has_syscall_anomaly(&check);
        let _function_name = check.function.clone();
        checks.push(SpreadCheckSummary::from_syscall(&check, delay));
    }

    let total_checks = checks.len();
    SpreadValidationSummary {
        checks,
        total_checks,
        suspicious,
        library_error: None,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|value| format!("{:02X}", value))
        .collect::<Vec<_>>()
        .join(" ")
}

struct PageProtectionTask;

#[async_trait]
impl RecoveryTask for PageProtectionTask {
    fn label(&self) -> String {
        "Behavioral: Page Protections".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = inspect_page_protections();
        if summary.anomalies_detected {
            return Err(RecoveryError::KillSwitchTriggered);
        }
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "behavioral-page-protection.json",
            &summary,
        )
        .await?;
        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct PageProtectionSummary {
    library_error: Option<String>,
    expected_protections: Vec<String>,
    anomalies_detected: bool,
    functions: Vec<PageProtectionObservation>,
}

#[derive(Serialize)]
struct PageProtectionObservation {
    function: String,
    protection: Option<String>,
    suspicious: bool,
    reason: Option<String>,
}

fn inspect_page_protections() -> PageProtectionSummary {
    let expected = PAGE_PROTECTION_EXPECTED_BASES
        .iter()
        .map(|value| page_protection_base_label(*value))
        .collect();
    match HotPathInspector::new() {
        Ok(inspector) => {
            let functions = HOT_PATH_CHECKSUMS
                .iter()
                .map(|info| inspector.inspect_page_protection(info.function))
                .collect::<Vec<_>>();
            let anomalies_detected = functions.iter().any(|check| check.suspicious);
            PageProtectionSummary {
                library_error: None,
                expected_protections: expected,
                anomalies_detected,
                functions,
            }
        }
        Err(err) => PageProtectionSummary {
            library_error: Some(err),
            expected_protections: expected,
            anomalies_detected: false,
            functions: Vec::new(),
        },
    }
}

fn format_page_protection_label(protection: PAGE_PROTECTION_FLAGS) -> String {
    let mut pieces = Vec::new();
    let base = protection.0 & PAGE_PROTECTION_BASE_MASK;
    pieces.push(page_protection_base_label(base));
    if (protection.0 & PAGE_GUARD.0) != 0 {
        pieces.push("PAGE_GUARD".to_string());
    }
    if (protection.0 & PAGE_NOCACHE.0) != 0 {
        pieces.push("PAGE_NOCACHE".to_string());
    }
    if (protection.0 & PAGE_WRITECOMBINE.0) != 0 {
        pieces.push("PAGE_WRITECOMBINE".to_string());
    }
    pieces.join(" | ")
}

fn page_protection_base_label(base: u32) -> String {
    match base {
        value if value == PAGE_NOACCESS.0 => "PAGE_NOACCESS".to_string(),
        value if value == PAGE_READONLY.0 => "PAGE_READONLY".to_string(),
        value if value == PAGE_READWRITE.0 => "PAGE_READWRITE".to_string(),
        value if value == PAGE_WRITECOPY.0 => "PAGE_WRITECOPY".to_string(),
        value if value == PAGE_EXECUTE.0 => "PAGE_EXECUTE".to_string(),
        value if value == PAGE_EXECUTE_READ.0 => "PAGE_EXECUTE_READ".to_string(),
        value if value == PAGE_EXECUTE_READWRITE.0 => "PAGE_EXECUTE_READWRITE".to_string(),
        value if value == PAGE_EXECUTE_WRITECOPY.0 => "PAGE_EXECUTE_WRITECOPY".to_string(),
        other => format!("PAGE_UNKNOWN(0x{other:02X})"),
    }
}

fn is_page_protection_suspicious(protection: PAGE_PROTECTION_FLAGS) -> bool {
    let base = protection.0 & PAGE_PROTECTION_BASE_MASK;
    if (protection.0 & PAGE_GUARD.0) != 0 || (protection.0 & PAGE_NOACCESS.0) != 0 {
        return true;
    }
    !PAGE_PROTECTION_EXPECTED_BASES.contains(&base)
}

struct SingleStepDetectionTask;

#[async_trait]
impl RecoveryTask for SingleStepDetectionTask {
    fn label(&self) -> String {
        "Behavioral: Single-Step Timing".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let summary = collect_single_step_summary();
        if summary.suspicious {
            return Err(RecoveryError::KillSwitchTriggered);
        }
        let artifact = write_json_artifact(
            ctx,
            self.category(),
            &self.label(),
            "behavioral-single-step-detection.json",
            &summary,
        )
        .await?;
        Ok(vec![artifact])
    }
}

#[derive(Serialize)]
struct SingleStepSummary {
    supported: bool,
    iterations: usize,
    threshold_cycles: u64,
    highest_cycles: Option<u64>,
    average_cycles: Option<f64>,
    suspicious: bool,
    observations: Vec<SingleStepObservation>,
}

#[derive(Serialize)]
struct SingleStepObservation {
    iteration: usize,
    cycles: Option<u64>,
    suspicious: bool,
}

fn collect_single_step_summary() -> SingleStepSummary {
    let mut observations = Vec::with_capacity(SINGLE_STEP_ITERATIONS);
    let mut highest_cycles = 0u64;
    let mut total_cycles = 0u128;
    let mut recorded = 0usize;
    let mut anomalies = false;

    for index in 0..SINGLE_STEP_ITERATIONS {
        let cycles = sample_instruction_cycles();
        if let Some(value) = cycles {
            recorded += 1;
            total_cycles += value as u128;
            highest_cycles = highest_cycles.max(value);
            if value > SINGLE_STEP_THRESHOLD_CYCLES {
                anomalies = true;
            }
        }
        observations.push(SingleStepObservation {
            iteration: index + 1,
            cycles,
            suspicious: cycles
                .map(|value| value > SINGLE_STEP_THRESHOLD_CYCLES)
                .unwrap_or(false),
        });
    }

    let highest_cycles = if recorded > 0 {
        Some(highest_cycles)
    } else {
        None
    };
    let average_cycles = if recorded > 0 {
        Some((total_cycles as f64) / (recorded as f64))
    } else {
        None
    };

    SingleStepSummary {
        supported: recorded > 0,
        iterations: SINGLE_STEP_ITERATIONS,
        threshold_cycles: SINGLE_STEP_THRESHOLD_CYCLES,
        highest_cycles,
        average_cycles,
        suspicious: anomalies,
        observations,
    }
}

#[cfg(target_arch = "x86_64")]
fn sample_instruction_cycles() -> Option<u64> {
    use core::arch::x86_64::{_mm_lfence, _mm_pause, _rdtsc};
    unsafe {
        let mut scratch = 0u64;
        _mm_lfence();
        let start = _rdtsc();
        for _ in 0..SINGLE_STEP_INNER_LOOP {
            scratch = scratch.wrapping_add(1);
            _mm_pause();
        }
        _mm_lfence();
        let end = _rdtsc();
        let _ = ptr::read_volatile(&scratch);
        Some(end - start)
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn sample_instruction_cycles() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_expected_syscall_stub() {
        let valid = [
            0x4C, 0x8B, 0xD1, 0xB8, 0xAA, 0xBB, 0xCC, 0xDD, 0x0F, 0x05, 0xC3,
        ];
        assert!(matches_syscall_stub(&valid));
    }

    #[test]
    fn rejects_hooked_syscall_stub() {
        let hooked = [
            0xE9, 0x00, 0x00, 0x00, 0xA1, 0xB2, 0xC3, 0xD4, 0x0F, 0x05, 0xC3,
        ];
        assert!(!matches_syscall_stub(&hooked));
    }

    #[test]
    fn hex_bytes_outputs_uppercase_pairs() {
        let sample = [0x0F, 0xA0, 0x01];
        assert_eq!(hex_bytes(&sample), "0F A0 01");
    }

    #[test]
    fn page_protection_label_includes_expected_bits() {
        let label = format_page_protection_label(PAGE_EXECUTE_READ);
        assert!(label.contains("PAGE_EXECUTE_READ"));
    }

    #[test]
    fn suspicious_protection_detects_writable_pages() {
        assert!(is_page_protection_suspicious(PAGE_EXECUTE_READWRITE));
    }

    #[test]
    fn expected_protection_is_not_marked_suspicious() {
        assert!(!is_page_protection_suspicious(PAGE_EXECUTE_READ));
    }

    #[test]
    fn spread_summary_copies_syscall_fields() {
        let check = SyscallFunctionCheck {
            function: "NtTest".to_string(),
            observed_bytes: Some("AA BB".to_string()),
            matches_expected_stub: true,
            checksum_expected: 0x1A2B,
            checksum_observed: Some(0x1A2B),
            checksum_matches: Some(true),
            cross_checksum_expected: 0x3C4D,
            cross_checksum_observed: Some(0x3C4D),
            cross_checksum_matches: Some(true),
            reason: Some("reason".to_string()),
            error: None,
        };
        let summary = SpreadCheckSummary::from_syscall(&check, 37);
        assert_eq!(summary.function, "NtTest");
        assert_eq!(summary.delay_ms, 37);
        assert!(summary.stub_matches);
        assert_eq!(summary.observed_bytes, Some("AA BB".to_string()));
        assert_eq!(summary.checksum_expected, 0x1A2B);
        assert_eq!(summary.checksum_observed, Some(0x1A2B));
        assert_eq!(summary.reason.as_deref(), Some("reason"));
    }
}
