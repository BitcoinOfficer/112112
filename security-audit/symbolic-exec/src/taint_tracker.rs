//! Taint tracking analysis tool for the Zebra security audit.
//!
//! This tool performs static taint analysis by:
//! 1. Identifying taint sources (network recv, RPC input, file reads).
//! 2. Tracing data flow through the codebase.
//! 3. Identifying taint sinks (unsafe blocks, FFI calls, allocations).
//! 4. Reporting paths from sources to sinks.
//!
//! This is a static approximation; dynamic taint tracking requires
//! Intel Pin or DynamoRIO instrumentation (see scripts/taint_pin.sh).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "taint-tracker", about = "Static taint flow analysis")]
struct Cli {
    /// Workspace root to analyse.
    #[arg(long, default_value = "..")]
    workspace: PathBuf,

    /// Output JSON report path.
    #[arg(long, default_value = "./reports/taint_analysis.json")]
    output: PathBuf,
}

/// A taint source (where attacker-controlled data enters the system).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaintSource {
    /// File path.
    file: String,
    /// Line number.
    line: usize,
    /// Source type.
    source_type: String,
    /// Code snippet.
    snippet: String,
}

/// A taint sink (where tainted data could cause harm).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaintSink {
    /// File path.
    file: String,
    /// Line number.
    line: usize,
    /// Sink type.
    sink_type: String,
    /// Code snippet.
    snippet: String,
    /// Risk level.
    risk: String,
}

/// A taint flow path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TaintFlow {
    /// Source.
    source: TaintSource,
    /// Sink.
    sink: TaintSink,
    /// Intermediate files in the flow.
    intermediate_files: Vec<String>,
    /// Confidence level (0.0 - 1.0).
    confidence: f32,
}

/// Patterns that indicate taint sources.
const SOURCE_PATTERNS: &[(&str, &str)] = &[
    ("ZcashDeserialize", "network_deserialisation"),
    ("zcash_deserialize", "network_deserialisation"),
    ("from_utf8", "string_parsing"),
    ("hex::decode", "hex_decoding"),
    ("serde_json::from_str", "json_parsing"),
    ("recv(", "socket_recv"),
    ("read(", "io_read"),
    ("read_to_string", "file_read"),
    ("from_str", "string_parsing"),
    ("parse::<", "type_parsing"),
];

/// Patterns that indicate taint sinks.
const SINK_PATTERNS: &[(&str, &str, &str)] = &[
    ("unsafe {", "unsafe_block", "HIGH"),
    ("from_raw_parts", "raw_pointer", "HIGH"),
    ("transmute", "type_transmute", "HIGH"),
    ("Vec::with_capacity", "allocation_size", "MEDIUM"),
    ("Vec::reserve", "allocation_size", "MEDIUM"),
    ("slice::from_raw_parts", "raw_slice", "HIGH"),
    ("ptr::read", "raw_read", "HIGH"),
    ("ptr::write", "raw_write", "HIGH"),
    ("as *mut", "raw_pointer_cast", "HIGH"),
    ("as *const", "raw_pointer_cast", "MEDIUM"),
    ("libzcash_script", "ffi_boundary", "HIGH"),
    ("execve", "dangerous_syscall", "CRITICAL"),
    ("system(", "dangerous_syscall", "CRITICAL"),
    ("Command::new", "process_spawn", "MEDIUM"),
    ("fs::write", "file_write", "MEDIUM"),
    ("fs::remove", "file_delete", "MEDIUM"),
];

fn scan_for_sources(file_path: &Path, workspace: &Path) -> Vec<TaintSource> {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let lines: Vec<&str> = content.lines().collect();
    let rel_path = file_path
        .strip_prefix(workspace)
        .unwrap_or(file_path)
        .display()
        .to_string();

    let mut sources = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        for (pattern, source_type) in SOURCE_PATTERNS {
            if line.contains(pattern) {
                sources.push(TaintSource {
                    file: rel_path.clone(),
                    line: i + 1,
                    source_type: source_type.to_string(),
                    snippet: line.trim().to_string(),
                });
                break;
            }
        }
    }

    sources
}

fn scan_for_sinks(file_path: &Path, workspace: &Path) -> Vec<TaintSink> {
    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let lines: Vec<&str> = content.lines().collect();
    let rel_path = file_path
        .strip_prefix(workspace)
        .unwrap_or(file_path)
        .display()
        .to_string();

    let mut sinks = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        for (pattern, sink_type, risk) in SINK_PATTERNS {
            if line.contains(pattern) {
                sinks.push(TaintSink {
                    file: rel_path.clone(),
                    line: i + 1,
                    sink_type: sink_type.to_string(),
                    snippet: line.trim().to_string(),
                    risk: risk.to_string(),
                });
                break;
            }
        }
    }

    sinks
}

/// Approximate taint flow by checking if source and sink are in the same crate.
fn approximate_flows(
    sources: &[TaintSource],
    sinks: &[TaintSink],
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();

    for source in sources {
        // Extract crate from file path (first path component).
        let source_crate = source
            .file
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();

        for sink in sinks {
            let sink_crate = sink
                .file
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();

            // Same crate = high confidence flow.
            // Adjacent crates (e.g., network → chain) = medium confidence.
            let confidence = if source_crate == sink_crate {
                0.8
            } else if is_adjacent_crate(&source_crate, &sink_crate) {
                0.5
            } else {
                0.2
            };

            // Only report flows with confidence > 0.4.
            if confidence > 0.4 {
                flows.push(TaintFlow {
                    source: source.clone(),
                    sink: sink.clone(),
                    intermediate_files: vec![],
                    confidence,
                });
            }
        }
    }

    // Sort by confidence (highest first).
    flows.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    flows.truncate(1000); // Limit output size.
    flows
}

/// Check if two crates are adjacent in the dependency graph.
fn is_adjacent_crate(from: &str, to: &str) -> bool {
    const ADJACENCY: &[(&str, &str)] = &[
        ("zebra-network", "zebra-chain"),
        ("zebra-rpc", "zebra-chain"),
        ("zebra-rpc", "zebra-state"),
        ("zebra-consensus", "zebra-chain"),
        ("zebra-consensus", "zebra-state"),
        ("zebrad", "zebra-network"),
        ("zebrad", "zebra-rpc"),
        ("zebrad", "zebra-consensus"),
    ];
    ADJACENCY.iter().any(|(f, t)| f == &from && t == &to)
}

#[derive(Debug, Serialize, Deserialize)]
struct TaintReport {
    total_sources: usize,
    total_sinks: usize,
    total_flows: usize,
    high_risk_flows: usize,
    sources: Vec<TaintSource>,
    sinks: Vec<TaintSink>,
    flows: Vec<TaintFlow>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cli = Cli::parse();

    info!("Scanning workspace: {}", cli.workspace.display());

    let mut all_sources: Vec<TaintSource> = Vec::new();
    let mut all_sinks: Vec<TaintSink> = Vec::new();

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
        all_sources.extend(scan_for_sources(entry.path(), &cli.workspace));
        all_sinks.extend(scan_for_sinks(entry.path(), &cli.workspace));
    }

    info!(
        "Found {} taint sources and {} taint sinks",
        all_sources.len(),
        all_sinks.len()
    );

    let flows = approximate_flows(&all_sources, &all_sinks);
    let high_risk_flows = flows
        .iter()
        .filter(|f| f.sink.risk == "HIGH" || f.sink.risk == "CRITICAL")
        .count();

    let report = TaintReport {
        total_sources: all_sources.len(),
        total_sinks: all_sinks.len(),
        total_flows: flows.len(),
        high_risk_flows,
        sources: all_sources,
        sinks: all_sinks,
        flows,
    };

    if let Some(parent) = cli.output.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(&cli.output, &json)?;

    println!("\n=== TAINT ANALYSIS REPORT ===");
    println!("Total taint sources: {}", report.total_sources);
    println!("Total taint sinks:   {}", report.total_sinks);
    println!("Total flows:         {}", report.total_flows);
    println!("High-risk flows:     {}", report.high_risk_flows);
    println!("\nReport written to: {}", cli.output.display());

    Ok(())
}
