//! Unsafe block enumerator for the Zebra security audit.
//!
//! Scans the entire workspace for `unsafe` blocks and classifies each by
//! risk level based on proximity to network-facing code paths.
//!
//! Output: JSON report with all unsafe blocks, their locations, and risk ratings.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "unsafe-enumerator", about = "Enumerate and classify unsafe blocks")]
struct Cli {
    /// Workspace root to scan.
    #[arg(long, default_value = "..")]
    workspace: PathBuf,

    /// Output JSON report path.
    #[arg(long, default_value = "./reports/unsafe_blocks.json")]
    output: PathBuf,
}

/// Risk level of an unsafe block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RiskLevel {
    /// Directly reachable from network input.
    High,
    /// Reachable via local RPC or file inputs.
    Medium,
    /// Only accessible through trusted internal pathways.
    Low,
}

/// A single unsafe block finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsafeBlock {
    /// File path (relative to workspace root).
    file: String,
    /// Line number.
    line: usize,
    /// Column number.
    column: usize,
    /// The line content containing `unsafe`.
    content: String,
    /// Surrounding context (3 lines before and after).
    context: Vec<String>,
    /// Risk level classification.
    risk: RiskLevel,
    /// Reason for the risk classification.
    risk_reason: String,
    /// Crate name.
    crate_name: String,
}

/// High-risk crates (directly handle network input).
const HIGH_RISK_CRATES: &[&str] = &[
    "zebra-network",
    "zebra-chain",
    "zebra-script",
    "zebra-rpc",
];

/// Medium-risk crates (handle local input or internal state).
const MEDIUM_RISK_CRATES: &[&str] = &[
    "zebra-state",
    "zebra-consensus",
    "zebrad",
];

/// Keywords that indicate high-risk unsafe usage.
const HIGH_RISK_KEYWORDS: &[&str] = &[
    "from_raw_parts",
    "transmute",
    "ptr::read",
    "ptr::write",
    "ptr::copy",
    "slice::from_raw_parts",
    "mem::forget",
    "mem::uninitialized",
    "MaybeUninit",
    "raw pointer",
    "as *mut",
    "as *const",
    "deref_mut",
];

fn classify_risk(crate_name: &str, content: &str, context: &[String]) -> (RiskLevel, String) {
    let all_text = format!("{} {}", content, context.join(" "));

    // Check crate-level risk.
    let crate_risk = if HIGH_RISK_CRATES.contains(&crate_name) {
        2
    } else if MEDIUM_RISK_CRATES.contains(&crate_name) {
        1
    } else {
        0
    };

    // Check for high-risk keywords.
    let has_high_risk_keyword = HIGH_RISK_KEYWORDS
        .iter()
        .any(|kw| all_text.contains(kw));

    match (crate_risk, has_high_risk_keyword) {
        (2, true) => (
            RiskLevel::High,
            format!(
                "High-risk crate '{}' with dangerous unsafe pattern ({})",
                crate_name,
                HIGH_RISK_KEYWORDS
                    .iter()
                    .find(|kw| all_text.contains(*kw))
                    .unwrap_or(&"unknown")
            ),
        ),
        (2, false) => (
            RiskLevel::High,
            format!("High-risk crate '{}' — all unsafe blocks are high priority", crate_name),
        ),
        (1, true) => (
            RiskLevel::High,
            format!(
                "Medium-risk crate '{}' with dangerous unsafe pattern",
                crate_name
            ),
        ),
        (1, false) => (
            RiskLevel::Medium,
            format!("Medium-risk crate '{}' — reachable via local input", crate_name),
        ),
        (_, true) => (
            RiskLevel::Medium,
            "Low-risk crate but contains dangerous unsafe pattern".to_string(),
        ),
        _ => (
            RiskLevel::Low,
            "Low-risk crate with standard unsafe usage".to_string(),
        ),
    }
}

fn extract_crate_name(file_path: &Path, workspace: &Path) -> String {
    // Extract crate name from path: workspace/crate-name/src/...
    if let Ok(rel) = file_path.strip_prefix(workspace) {
        if let Some(first) = rel.components().next() {
            return first.as_os_str().to_string_lossy().to_string();
        }
    }
    "unknown".to_string()
}

fn scan_file(file_path: &Path, workspace: &Path) -> Vec<UnsafeBlock> {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let lines: Vec<&str> = content.lines().collect();
    let crate_name = extract_crate_name(file_path, workspace);
    let mut blocks = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if line.contains("unsafe") {
            // Collect context (3 lines before and after).
            let start = i.saturating_sub(3);
            let end = (i + 4).min(lines.len());
            let context: Vec<String> = lines[start..end]
                .iter()
                .map(|l| l.to_string())
                .collect();

            let (risk, risk_reason) = classify_risk(&crate_name, line, &context);

            let rel_path = file_path
                .strip_prefix(workspace)
                .unwrap_or(file_path)
                .display()
                .to_string();

            blocks.push(UnsafeBlock {
                file: rel_path,
                line: i + 1,
                column: line.find("unsafe").unwrap_or(0) + 1,
                content: line.trim().to_string(),
                context,
                risk,
                risk_reason,
                crate_name: crate_name.clone(),
            });
        }
    }

    blocks
}

#[derive(Debug, Serialize, Deserialize)]
struct UnsafeReport {
    total_unsafe_blocks: usize,
    by_risk: HashMap<String, usize>,
    by_crate: HashMap<String, usize>,
    blocks: Vec<UnsafeBlock>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cli = Cli::parse();

    info!("Scanning workspace: {}", cli.workspace.display());

    let mut all_blocks: Vec<UnsafeBlock> = Vec::new();

    for entry in walkdir::WalkDir::new(&cli.workspace)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "rs")
                && !e
                    .path()
                    .components()
                    .any(|c| c.as_os_str() == "target" || c.as_os_str() == ".git")
        })
    {
        let blocks = scan_file(entry.path(), &cli.workspace);
        all_blocks.extend(blocks);
    }

    // Sort by risk (High first), then by file.
    all_blocks.sort_by(|a, b| {
        let risk_ord = |r: &RiskLevel| match r {
            RiskLevel::High => 0,
            RiskLevel::Medium => 1,
            RiskLevel::Low => 2,
        };
        risk_ord(&a.risk)
            .cmp(&risk_ord(&b.risk))
            .then(a.file.cmp(&b.file))
            .then(a.line.cmp(&b.line))
    });

    let mut by_risk: HashMap<String, usize> = HashMap::new();
    let mut by_crate: HashMap<String, usize> = HashMap::new();

    for block in &all_blocks {
        *by_risk
            .entry(format!("{:?}", block.risk))
            .or_insert(0) += 1;
        *by_crate.entry(block.crate_name.clone()).or_insert(0) += 1;
    }

    let report = UnsafeReport {
        total_unsafe_blocks: all_blocks.len(),
        by_risk: by_risk.clone(),
        by_crate: by_crate.clone(),
        blocks: all_blocks,
    };

    if let Some(parent) = cli.output.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&cli.output, &json)?;

    println!("\n=== UNSAFE BLOCK ENUMERATION REPORT ===");
    println!("Total unsafe blocks: {}", report.total_unsafe_blocks);
    println!("\nBy risk level:");
    let mut risk_sorted: Vec<_> = by_risk.iter().collect();
    risk_sorted.sort_by_key(|(k, _)| k.clone());
    for (k, v) in &risk_sorted {
        println!("  {:10} {}", k, v);
    }
    println!("\nBy crate:");
    let mut crate_sorted: Vec<_> = by_crate.iter().collect();
    crate_sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (k, v) in &crate_sorted {
        println!("  {:30} {}", k, v);
    }
    println!("\nReport written to: {}", cli.output.display());

    Ok(())
}
