//! Crash triage tool for the Zebra security audit.
//!
//! This tool:
//! 1. Scans a crash directory for fuzzer-produced crash inputs.
//! 2. Deduplicates crashes by content hash.
//! 3. Replays each crash against the target harness binary.
//! 4. Classifies the crash type (OOM, stack overflow, assertion, sanitiser).
//! 5. Assigns an exploitability rating.
//! 6. Generates a structured JSON report.
//!
//! Usage:
//!   crash-triage --crash-dir ./crashes --harness ./target/debug/fuzz_p2p_version \
//!                --output ./reports/triage.json

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "crash-triage",
    about = "Automated crash triage for Zebra security audit",
    version = "0.1.0"
)]
struct Cli {
    /// Directory containing crash inputs from the fuzzer.
    #[arg(long, default_value = "./crashes")]
    crash_dir: PathBuf,

    /// Path to the harness binary to replay crashes against.
    #[arg(long)]
    harness: PathBuf,

    /// Output JSON report path.
    #[arg(long, default_value = "./reports/triage.json")]
    output: PathBuf,

    /// Timeout per crash replay in seconds.
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Maximum number of crashes to process.
    #[arg(long, default_value = "10000")]
    max_crashes: usize,
}

// ── Data structures ───────────────────────────────────────────────────────────

/// Exploitability classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Exploitability {
    /// Remote code execution — attacker controls instruction pointer.
    Rce,
    /// Denial of service — crash or hang without code execution.
    Dos,
    /// Information leak — out-of-bounds read.
    InfoLeak,
    /// Logic/consensus bug — node reaches inconsistent state.
    Logic,
    /// Unknown — requires further manual analysis.
    Unknown,
}

/// Crash type classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CrashType {
    /// AddressSanitizer: heap buffer overflow.
    HeapBufferOverflow,
    /// AddressSanitizer: stack buffer overflow.
    StackBufferOverflow,
    /// AddressSanitizer: use-after-free.
    UseAfterFree,
    /// AddressSanitizer: heap use-after-free.
    HeapUseAfterFree,
    /// MemorySanitizer: use of uninitialised value.
    UninitMemory,
    /// UndefinedBehaviourSanitizer: integer overflow.
    IntegerOverflow,
    /// UndefinedBehaviourSanitizer: null pointer dereference.
    NullDeref,
    /// UndefinedBehaviourSanitizer: misaligned access.
    MisalignedAccess,
    /// ThreadSanitizer: data race.
    DataRace,
    /// Out-of-memory (allocation failure).
    OutOfMemory,
    /// Stack overflow (infinite recursion).
    StackOverflow,
    /// Assertion failure (debug_assert! or assert!).
    AssertionFailure,
    /// Controlled panic (expected for invalid input).
    ControlledPanic,
    /// Timeout (potential infinite loop).
    Timeout,
    /// Unknown crash type.
    Unknown,
}

/// A single triaged crash finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CrashFinding {
    /// Unique identifier (SHA-256 of crash input).
    id: String,
    /// Path to the crash input file.
    input_path: String,
    /// Size of the crash input in bytes.
    input_size: usize,
    /// Crash type classification.
    crash_type: CrashType,
    /// Exploitability rating.
    exploitability: Exploitability,
    /// Exit code of the harness process.
    exit_code: Option<i32>,
    /// Signal that killed the process (if any).
    signal: Option<i32>,
    /// First 500 bytes of stderr output (sanitiser report).
    stderr_excerpt: String,
    /// Whether the crash is reproducible.
    reproducible: bool,
    /// Time to reproduce in milliseconds.
    reproduction_time_ms: u64,
    /// Suggested CVSS 3.1 base score.
    cvss_score: f32,
    /// Remediation notes.
    remediation: String,
}

/// The complete triage report.
#[derive(Debug, Serialize, Deserialize)]
struct TriageReport {
    /// Harness binary path.
    harness: String,
    /// Total crashes processed.
    total_crashes: usize,
    /// Unique crashes (after deduplication).
    unique_crashes: usize,
    /// Crashes by exploitability.
    by_exploitability: HashMap<String, usize>,
    /// Crashes by type.
    by_type: HashMap<String, usize>,
    /// All findings.
    findings: Vec<CrashFinding>,
}

// ── Core logic ────────────────────────────────────────────────────────────────

/// Compute SHA-256 hash of a byte slice, returning a hex string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Classify a crash based on stderr output and exit code.
fn classify_crash(stderr: &str, exit_code: Option<i32>, timed_out: bool) -> (CrashType, Exploitability) {
    if timed_out {
        return (CrashType::Timeout, Exploitability::Dos);
    }

    // ASAN patterns.
    if stderr.contains("heap-buffer-overflow") {
        return (CrashType::HeapBufferOverflow, Exploitability::Rce);
    }
    if stderr.contains("stack-buffer-overflow") {
        return (CrashType::StackBufferOverflow, Exploitability::Rce);
    }
    if stderr.contains("heap-use-after-free") {
        return (CrashType::HeapUseAfterFree, Exploitability::Rce);
    }
    if stderr.contains("use-after-free") {
        return (CrashType::UseAfterFree, Exploitability::Rce);
    }

    // MSAN patterns.
    if stderr.contains("MemorySanitizer") || stderr.contains("use-of-uninitialized-value") {
        return (CrashType::UninitMemory, Exploitability::InfoLeak);
    }

    // UBSAN patterns.
    if stderr.contains("integer overflow") || stderr.contains("signed integer overflow") {
        return (CrashType::IntegerOverflow, Exploitability::Dos);
    }
    if stderr.contains("null pointer") || stderr.contains("null-pointer-dereference") {
        return (CrashType::NullDeref, Exploitability::Dos);
    }
    if stderr.contains("misaligned") {
        return (CrashType::MisalignedAccess, Exploitability::Dos);
    }

    // TSAN patterns.
    if stderr.contains("ThreadSanitizer") || stderr.contains("DATA RACE") {
        return (CrashType::DataRace, Exploitability::Logic);
    }

    // OOM.
    if stderr.contains("out of memory") || stderr.contains("cannot allocate") {
        return (CrashType::OutOfMemory, Exploitability::Dos);
    }

    // Stack overflow.
    if stderr.contains("stack overflow") || stderr.contains("SIGSEGV") && stderr.contains("stack") {
        return (CrashType::StackOverflow, Exploitability::Dos);
    }

    // Assertion failure.
    if stderr.contains("assertion failed") || stderr.contains("assertion `") {
        return (CrashType::AssertionFailure, Exploitability::Dos);
    }

    // Controlled panic.
    if stderr.contains("thread 'main' panicked") || stderr.contains("panicked at") {
        return (CrashType::ControlledPanic, Exploitability::Dos);
    }

    // Signal-based classification.
    match exit_code {
        Some(code) if code < 0 => {
            let sig = -code;
            match sig {
                11 => (CrashType::NullDeref, Exploitability::Dos), // SIGSEGV
                6  => (CrashType::AssertionFailure, Exploitability::Dos), // SIGABRT
                8  => (CrashType::IntegerOverflow, Exploitability::Dos), // SIGFPE
                _  => (CrashType::Unknown, Exploitability::Unknown),
            }
        }
        _ => (CrashType::Unknown, Exploitability::Unknown),
    }
}

/// Compute a CVSS 3.1 base score estimate.
fn estimate_cvss(crash_type: &CrashType, exploitability: &Exploitability) -> f32 {
    match exploitability {
        Exploitability::Rce => match crash_type {
            CrashType::HeapBufferOverflow | CrashType::HeapUseAfterFree => 9.8,
            CrashType::StackBufferOverflow => 9.0,
            CrashType::UseAfterFree => 8.8,
            _ => 8.0,
        },
        Exploitability::InfoLeak => 7.5,
        Exploitability::Dos => match crash_type {
            CrashType::OutOfMemory | CrashType::StackOverflow => 7.5,
            CrashType::Timeout => 6.5,
            _ => 5.9,
        },
        Exploitability::Logic => 6.5,
        Exploitability::Unknown => 4.0,
    }
}

/// Generate remediation guidance.
fn remediation_guidance(crash_type: &CrashType) -> String {
    match crash_type {
        CrashType::HeapBufferOverflow | CrashType::StackBufferOverflow => {
            "Add bounds checking before indexing. Use safe Rust slice operations. \
             Consider replacing unsafe pointer arithmetic with safe alternatives."
                .to_string()
        }
        CrashType::UseAfterFree | CrashType::HeapUseAfterFree => {
            "Audit ownership and lifetime annotations. Ensure no Arc/Rc cycles. \
             Review all unsafe blocks that store raw pointers."
                .to_string()
        }
        CrashType::UninitMemory => {
            "Initialise all memory before use. Replace MaybeUninit with safe alternatives \
             where possible. Add MSAN CI checks."
                .to_string()
        }
        CrashType::IntegerOverflow => {
            "Use checked arithmetic (checked_add, checked_mul) for all attacker-controlled \
             values. Enable overflow-checks = true in Cargo.toml profiles."
                .to_string()
        }
        CrashType::NullDeref => {
            "Replace raw pointer dereferences with safe Option-based patterns. \
             Add null checks before all FFI calls."
                .to_string()
        }
        CrashType::OutOfMemory => {
            "Add allocation size limits before Vec::reserve and Vec::with_capacity calls. \
             Validate compact-size fields against MAX_PAYLOAD_SIZE before allocating."
                .to_string()
        }
        CrashType::DataRace => {
            "Add appropriate synchronisation (Mutex, RwLock, or atomic operations). \
             Review all shared mutable state accessed from multiple threads."
                .to_string()
        }
        CrashType::Timeout => {
            "Add timeout guards to all parsing loops. Ensure no unbounded iteration \
             over attacker-controlled data."
                .to_string()
        }
        CrashType::AssertionFailure => {
            "Replace debug_assert! with proper error handling in production code paths. \
             Ensure assertions are not reachable from network input."
                .to_string()
        }
        _ => "Perform manual root cause analysis. Review the sanitiser report and \
              stack trace to identify the vulnerable code path."
            .to_string(),
    }
}

/// Replay a crash input against the harness binary.
fn replay_crash(
    harness: &Path,
    input: &[u8],
    timeout: Duration,
) -> (Option<i32>, String, bool, u64) {
    let start = Instant::now();

    // Write input to a temp file.
    let tmp = tempfile_path();
    if fs::write(&tmp, input).is_err() {
        return (None, String::new(), false, 0);
    }

    let result = Command::new(harness)
        .arg(&tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();

    let elapsed_ms = start.elapsed().as_millis() as u64;

    let _ = fs::remove_file(&tmp);

    match result {
        Ok(mut child) => {
            let timed_out = match child.wait_timeout(timeout) {
                Ok(Some(_)) => false,
                _ => {
                    let _ = child.kill();
                    true
                }
            };
            let exit_code = child.wait().ok().and_then(|s| s.code());
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr {
                let _ = e.read_to_string(&mut stderr);
            }
            let stderr_excerpt = stderr.chars().take(500).collect();
            (exit_code, stderr_excerpt, !timed_out, elapsed_ms)
        }
        Err(e) => {
            warn!("Failed to spawn harness: {}", e);
            (None, String::new(), false, elapsed_ms)
        }
    }
}

/// Generate a temporary file path.
fn tempfile_path() -> PathBuf {
    let id: u64 = rand::random();
    std::env::temp_dir().join(format!("zebra-crash-{:016x}.bin", id))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let cli = Cli::parse();

    info!("Starting crash triage");
    info!("Crash dir: {}", cli.crash_dir.display());
    info!("Harness:   {}", cli.harness.display());
    info!("Output:    {}", cli.output.display());

    // Collect crash files.
    let mut crash_files: Vec<PathBuf> = walkdir::WalkDir::new(&cli.crash_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    crash_files.sort();
    crash_files.truncate(cli.max_crashes);

    info!("Found {} crash files", crash_files.len());

    let mut seen_hashes: HashMap<String, bool> = HashMap::new();
    let mut findings: Vec<CrashFinding> = Vec::new();
    let timeout = Duration::from_secs(cli.timeout);

    for path in &crash_files {
        let input = match fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to read {}: {}", path.display(), e);
                continue;
            }
        };

        let hash = sha256_hex(&input);

        // Deduplicate.
        if seen_hashes.contains_key(&hash) {
            continue;
        }
        seen_hashes.insert(hash.clone(), true);

        info!("Triaging {} ({})", path.display(), hash);

        let (exit_code, stderr_excerpt, reproducible, elapsed_ms) =
            replay_crash(&cli.harness, &input, timeout);

        let timed_out = elapsed_ms >= cli.timeout * 1000;
        let (crash_type, exploitability) =
            classify_crash(&stderr_excerpt, exit_code, timed_out);

        let cvss_score = estimate_cvss(&crash_type, &exploitability);
        let remediation = remediation_guidance(&crash_type);

        let finding = CrashFinding {
            id: hash,
            input_path: path.display().to_string(),
            input_size: input.len(),
            crash_type,
            exploitability,
            exit_code,
            signal: None,
            stderr_excerpt,
            reproducible,
            reproduction_time_ms: elapsed_ms,
            cvss_score,
            remediation,
        };

        findings.push(finding);
    }

    // Sort by exploitability (most severe first).
    findings.sort_by(|a, b| a.exploitability.cmp(&b.exploitability));

    // Build summary statistics.
    let mut by_exploitability: HashMap<String, usize> = HashMap::new();
    let mut by_type: HashMap<String, usize> = HashMap::new();

    for f in &findings {
        *by_exploitability
            .entry(format!("{:?}", f.exploitability))
            .or_insert(0) += 1;
        *by_type
            .entry(format!("{:?}", f.crash_type))
            .or_insert(0) += 1;
    }

    let report = TriageReport {
        harness: cli.harness.display().to_string(),
        total_crashes: crash_files.len(),
        unique_crashes: findings.len(),
        by_exploitability,
        by_type,
        findings,
    };

    // Write report.
    if let Some(parent) = cli.output.parent() {
        fs::create_dir_all(parent).context("Failed to create output directory")?;
    }
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&cli.output, &json).context("Failed to write report")?;

    info!(
        "Triage complete: {} unique crashes, report written to {}",
        report.unique_crashes,
        cli.output.display()
    );

    // Print summary to stdout.
    println!("\n=== CRASH TRIAGE SUMMARY ===");
    println!("Total crashes processed: {}", report.total_crashes);
    println!("Unique crashes:          {}", report.unique_crashes);
    println!("\nBy exploitability:");
    let mut exp_sorted: Vec<_> = report.by_exploitability.iter().collect();
    exp_sorted.sort_by_key(|(k, _)| k.clone());
    for (k, v) in &exp_sorted {
        println!("  {:20} {}", k, v);
    }
    println!("\nBy crash type:");
    let mut type_sorted: Vec<_> = report.by_type.iter().collect();
    type_sorted.sort_by_key(|(k, _)| k.clone());
    for (k, v) in &type_sorted {
        println!("  {:30} {}", k, v);
    }

    Ok(())
}

// ── Trait extension for process timeout ──────────────────────────────────────

trait WaitTimeout {
    fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>>;
}

impl WaitTimeout for std::process::Child {
    fn wait_timeout(&mut self, timeout: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
        let start = Instant::now();
        loop {
            match self.try_wait()? {
                Some(status) => return Ok(Some(status)),
                None => {
                    if start.elapsed() >= timeout {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

// Bring rand into scope.
mod rand {
    pub fn random<T: rand_core::RngCore>() -> u64 {
        use rand_core::RngCore;
        let mut rng = rand_core::OsRng;
        rng.next_u64()
    }
}
