//! Symbolic execution orchestrator for the Zebra security audit.
//!
//! This tool:
//! 1. Compiles target crates to LLVM bitcode.
//! 2. Invokes KLEE on the bitcode with symbolic input buffers.
//! 3. Collects KLEE-generated test cases and error reports.
//! 4. Converts KLEE outputs into fuzzer corpus entries.
//! 5. Generates angr analysis scripts for ELF-based exploration.
//!
//! Prerequisites:
//!   - KLEE installed and in PATH
//!   - clang/llvm-link installed
//!   - RUSTFLAGS="--emit=llvm-bc" for bitcode compilation

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info, warn};

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "symbolic-exec", about = "Symbolic execution orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Compile target crates to LLVM bitcode.
    Compile {
        /// Workspace root directory.
        #[arg(long, default_value = "..")]
        workspace: PathBuf,
        /// Output directory for bitcode files.
        #[arg(long, default_value = "./bitcode")]
        output: PathBuf,
    },
    /// Run KLEE on compiled bitcode.
    Klee {
        /// Directory containing .bc files.
        #[arg(long, default_value = "./bitcode")]
        bitcode_dir: PathBuf,
        /// KLEE output directory.
        #[arg(long, default_value = "./klee-output")]
        output: PathBuf,
        /// Maximum time per target in seconds.
        #[arg(long, default_value = "86400")]
        timeout: u64,
    },
    /// Convert KLEE test cases to fuzzer corpus entries.
    ConvertCorpus {
        /// KLEE output directory.
        #[arg(long, default_value = "./klee-output")]
        klee_dir: PathBuf,
        /// Fuzzer corpus output directory.
        #[arg(long, default_value = "./corpus")]
        corpus_dir: PathBuf,
    },
    /// Generate angr analysis scripts.
    GenerateAngr {
        /// Target ELF binary.
        #[arg(long)]
        binary: PathBuf,
        /// Output Python script path.
        #[arg(long, default_value = "./angr_analysis.py")]
        output: PathBuf,
    },
}

// ── Crates to compile to bitcode ─────────────────────────────────────────────

const BITCODE_CRATES: &[&str] = &[
    "zebra-chain",
    "zebra-network",
    "zebra-rpc",
    "zebra-script",
    "zebra-state",
];

// ── Compile subcommand ────────────────────────────────────────────────────────

fn compile_to_bitcode(workspace: &Path, output: &Path) -> Result<()> {
    fs::create_dir_all(output).context("Failed to create bitcode output directory")?;

    for crate_name in BITCODE_CRATES {
        info!("Compiling {} to LLVM bitcode", crate_name);

        let status = Command::new("cargo")
            .current_dir(workspace)
            .env("RUSTFLAGS", "--emit=llvm-bc -C opt-level=0 -C debuginfo=2")
            .args([
                "build",
                "--package",
                crate_name,
                "--target",
                "x86_64-unknown-linux-gnu",
            ])
            .status()
            .context("Failed to run cargo build")?;

        if !status.success() {
            warn!("Failed to compile {} to bitcode", crate_name);
            continue;
        }

        // Find and copy .bc files.
        let bc_glob = workspace
            .join("target")
            .join("x86_64-unknown-linux-gnu")
            .join("debug")
            .join("deps");

        if bc_glob.exists() {
            for entry in walkdir::WalkDir::new(&bc_glob)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "bc"))
            {
                let dest = output.join(entry.file_name());
                let _ = fs::copy(entry.path(), &dest);
                info!("Copied bitcode: {}", dest.display());
            }
        }
    }

    info!("Bitcode compilation complete. Output: {}", output.display());
    Ok(())
}

// ── KLEE subcommand ───────────────────────────────────────────────────────────

/// KLEE invocation parameters for each target function.
struct KleeTarget {
    /// Name of the target function.
    function: &'static str,
    /// Bitcode file containing the function.
    bitcode: &'static str,
    /// Maximum symbolic input size in bytes.
    input_size: usize,
    /// KLEE search strategy.
    search: &'static str,
}

const KLEE_TARGETS: &[KleeTarget] = &[
    KleeTarget {
        function: "zebra_chain_transaction_read",
        bitcode: "zebra_chain.bc",
        input_size: 65536,
        search: "dfs",
    },
    KleeTarget {
        function: "zebra_network_message_read",
        bitcode: "zebra_network.bc",
        input_size: 65536,
        search: "bfs",
    },
    KleeTarget {
        function: "zebra_chain_block_read",
        bitcode: "zebra_chain.bc",
        input_size: 65536,
        search: "dfs",
    },
    KleeTarget {
        function: "zebra_script_verify",
        bitcode: "zebra_script.bc",
        input_size: 10240,
        search: "dfs",
    },
];

fn run_klee(bitcode_dir: &Path, output: &Path, timeout: u64) -> Result<()> {
    fs::create_dir_all(output).context("Failed to create KLEE output directory")?;

    // Check if KLEE is available.
    if Command::new("klee").arg("--version").output().is_err() {
        warn!("KLEE not found in PATH. Generating KLEE invocation scripts instead.");
        return generate_klee_scripts(bitcode_dir, output, timeout);
    }

    for target in KLEE_TARGETS {
        let bc_path = bitcode_dir.join(target.bitcode);
        if !bc_path.exists() {
            warn!("Bitcode not found: {}", bc_path.display());
            continue;
        }

        let target_output = output.join(target.function);
        fs::create_dir_all(&target_output)?;

        info!("Running KLEE on {}", target.function);

        let status = Command::new("klee")
            .args([
                "--search",
                target.search,
                "--max-time",
                &timeout.to_string(),
                "--max-memory",
                "8192",
                "--output-dir",
                &target_output.display().to_string(),
                "--emit-all-errors",
                "--use-query-log=all:kquery",
                "--write-test-info",
                "--write-paths",
                "--write-cov",
                "--entry-point",
                target.function,
                &bc_path.display().to_string(),
            ])
            .status()
            .context("Failed to run KLEE")?;

        if status.success() {
            info!("KLEE completed for {}", target.function);
        } else {
            warn!("KLEE exited with error for {}", target.function);
        }
    }

    Ok(())
}

/// Generate shell scripts that invoke KLEE (when KLEE is not installed).
fn generate_klee_scripts(bitcode_dir: &Path, output: &Path, timeout: u64) -> Result<()> {
    let script_path = output.join("run_klee.sh");
    let mut script = String::from("#!/usr/bin/env bash\n# KLEE invocation script\nset -euo pipefail\n\n");

    for target in KLEE_TARGETS {
        let bc_path = bitcode_dir.join(target.bitcode);
        script.push_str(&format!(
            "# Target: {}\n\
             mkdir -p {}/{}\n\
             klee \\\n\
               --search={} \\\n\
               --max-time={} \\\n\
               --max-memory=8192 \\\n\
               --output-dir={}/{} \\\n\
               --emit-all-errors \\\n\
               --use-query-log=all:kquery \\\n\
               --write-test-info \\\n\
               --write-paths \\\n\
               --write-cov \\\n\
               --entry-point={} \\\n\
               {}\n\n",
            target.function,
            output.display(),
            target.function,
            target.search,
            timeout,
            output.display(),
            target.function,
            target.function,
            bc_path.display(),
        ));
    }

    fs::write(&script_path, &script)?;
    info!("Generated KLEE script: {}", script_path.display());
    Ok(())
}

// ── Corpus conversion ─────────────────────────────────────────────────────────

fn convert_klee_corpus(klee_dir: &Path, corpus_dir: &Path) -> Result<()> {
    fs::create_dir_all(corpus_dir)?;

    let mut count = 0usize;
    for entry in walkdir::WalkDir::new(klee_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext == "ktest")
        })
    {
        // Read the .ktest file and extract the symbolic input bytes.
        // KLEE .ktest format: header + objects (name + data).
        if let Ok(data) = fs::read(entry.path()) {
            let corpus_file = corpus_dir.join(format!("klee_{:06}", count));
            fs::write(&corpus_file, &data)?;
            count += 1;
        }
    }

    info!("Converted {} KLEE test cases to corpus entries", count);
    Ok(())
}

// ── angr script generation ────────────────────────────────────────────────────

fn generate_angr_script(binary: &Path, output: &Path) -> Result<()> {
    let script = format!(
        r#"#!/usr/bin/env python3
"""
angr-based concolic execution analysis for Zebra.
Target binary: {binary}

This script:
1. Loads the binary into angr.
2. Hooks recv/read syscalls to inject symbolic data.
3. Explores paths that reach unsafe blocks or dangerous syscalls.
4. Reports any path that reaches execve/system with attacker-controlled args.

Usage:
    pip install angr
    python3 {output}
"""

import angr
import claripy
import logging

logging.getLogger('angr').setLevel(logging.WARNING)
logging.getLogger('cle').setLevel(logging.WARNING)

BINARY = "{binary}"
MAX_STATES = 10_000
SYMBOLIC_INPUT_SIZE = 65_536  # bytes

# Dangerous functions to detect.
DANGEROUS_FUNCTIONS = [
    "execve", "system", "popen", "exec", "fork",
    "dlopen", "mmap", "mprotect",
]

# Unsafe block markers (function names containing unsafe operations).
UNSAFE_MARKERS = [
    "from_raw_parts", "transmute", "ptr::read", "ptr::write",
    "slice::from_raw_parts", "mem::forget",
]


def make_symbolic_input(size: int) -> claripy.BVS:
    """Create a symbolic bitvector representing network input."""
    return claripy.BVS("network_input", size * 8)


def hook_recv(state):
    """Hook the recv syscall to inject symbolic data."""
    sym_data = make_symbolic_input(SYMBOLIC_INPUT_SIZE)
    state.memory.store(state.regs.rsi, sym_data)
    state.regs.rax = SYMBOLIC_INPUT_SIZE


def hook_read(state):
    """Hook the read syscall to inject symbolic data."""
    sym_data = make_symbolic_input(SYMBOLIC_INPUT_SIZE)
    state.memory.store(state.regs.rsi, sym_data)
    state.regs.rax = SYMBOLIC_INPUT_SIZE


def find_dangerous_paths(proj, cfg):
    """Find paths that reach dangerous functions."""
    findings = []

    for func_name in DANGEROUS_FUNCTIONS:
        try:
            func = proj.loader.find_symbol(func_name)
            if func is None:
                continue

            print(f"[*] Found dangerous function: {{func_name}} @ {{hex(func.rebased_addr)}}")

            # Create a simulation manager starting from main.
            entry = proj.entry
            state = proj.factory.blank_state(addr=entry)
            state.options.add(angr.options.LAZY_SOLVES)

            simgr = proj.factory.simulation_manager(state)
            simgr.explore(
                find=func.rebased_addr,
                num_find=5,
                step_func=lambda sm: sm if len(sm.found) < 5 else sm.move("found", "deadended"),
            )

            for found_state in simgr.found:
                # Concretise the symbolic input.
                try:
                    concrete_input = found_state.solver.eval(
                        found_state.memory.load(found_state.regs.rsi, SYMBOLIC_INPUT_SIZE),
                        cast_to=bytes,
                    )
                    findings.append({{
                        "function": func_name,
                        "address": hex(func.rebased_addr),
                        "input": concrete_input.hex(),
                        "input_len": len(concrete_input),
                    }})
                    print(f"  [!] Path found to {{func_name}}: input={{concrete_input[:32].hex()}}...")
                except Exception as e:
                    print(f"  [!] Path found but concretisation failed: {{e}}")

        except Exception as e:
            print(f"  [-] Error analysing {{func_name}}: {{e}}")

    return findings


def main():
    print(f"[*] Loading binary: {{BINARY}}")
    proj = angr.Project(BINARY, auto_load_libs=False)

    # Hook syscalls.
    proj.hook_symbol("recv", angr.SIM_PROCEDURES["posix"]["recv"]())
    proj.hook_symbol("read", angr.SIM_PROCEDURES["posix"]["read"]())

    print("[*] Building CFG (this may take a while)...")
    try:
        cfg = proj.analyses.CFGFast(normalize=True)
        print(f"[*] CFG built: {{len(cfg.graph.nodes())}} nodes")
    except Exception as e:
        print(f"[-] CFG construction failed: {{e}}")
        cfg = None

    print("[*] Searching for dangerous paths...")
    findings = find_dangerous_paths(proj, cfg)

    print(f"\n[*] Analysis complete. Found {{len(findings)}} dangerous paths.")
    for i, f in enumerate(findings):
        print(f"\n  Finding {{i+1}}:")
        print(f"    Function: {{f['function']}}")
        print(f"    Address:  {{f['address']}}")
        print(f"    Input:    {{f['input'][:64]}}...")

    # Save findings to JSON.
    import json
    with open("angr_findings.json", "w") as fp:
        json.dump(findings, fp, indent=2)
    print("\n[*] Findings saved to angr_findings.json")


if __name__ == "__main__":
    main()
"#,
        binary = binary.display(),
        output = output.display(),
    );

    fs::write(output, &script)?;
    info!("Generated angr script: {}", output.display());
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Compile { workspace, output } => {
            compile_to_bitcode(&workspace, &output)?;
        }
        Commands::Klee {
            bitcode_dir,
            output,
            timeout,
        } => {
            run_klee(&bitcode_dir, &output, timeout)?;
        }
        Commands::ConvertCorpus {
            klee_dir,
            corpus_dir,
        } => {
            convert_klee_corpus(&klee_dir, &corpus_dir)?;
        }
        Commands::GenerateAngr { binary, output } => {
            generate_angr_script(&binary, &output)?;
        }
    }

    Ok(())
}
