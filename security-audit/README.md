# Zebra Security Audit Infrastructure

## Overview

This directory contains a comprehensive, multi-version, multi-sanitizer security audit infrastructure for the Zebra Zcash consensus node implementation. The audit covers versions 4.1.0 through 4.4.1 with the goal of discovering memory corruptions, logic flaws, injection primitives, and any exploitable conditions.

## Directory Structure

```
security-audit/
├── infrastructure/          # Build scripts and compilation configurations
│   ├── build-scripts/      # Scripts to compile all instrumented binaries
│   ├── sanitizers/         # Sanitizer-specific configurations
│   └── versions/           # Version-specific build artifacts
├── fuzzing/                # Fuzzing campaign materials
│   ├── harnesses/          # Fuzzing harness source code (45+ harnesses)
│   ├── corpora/            # Seed corpora for fuzzers
│   ├── crashes/            # Discovered crashes and reproducer inputs
│   └── queue/              # Fuzzer queue directories
├── symbolic-execution/     # KLEE and angr configurations
├── reports/                # Vulnerability reports and findings
├── scripts/                # Automation and orchestration scripts
├── docker/                 # Container definitions for isolation
├── reproducers/            # Minimal reproducers for each finding
└── coverage/               # Code coverage reports
```

## Audit Objectives

1. **Memory Safety**: Discover buffer overflows, use-after-free, heap/stack corruption
2. **Concurrency**: Detect data races, deadlocks, TOCTOU vulnerabilities
3. **Logic Flaws**: Identify consensus bugs, state machine errors
4. **Injection**: Find format string, command injection, path traversal
5. **DoS**: Uncover resource exhaustion, infinite loops, hangs
6. **Information Leakage**: Detect out-of-bounds reads exposing memory

## Instrumented Binary Matrix

For each Zebra version (4.1.0, 4.2.0, 4.3.0, 4.4.1):

| Binary | Sanitizer | Purpose |
|--------|-----------|---------|
| `zebrad-asan` | AddressSanitizer | Memory corruption detection |
| `zebrad-msan` | MemorySanitizer | Uninitialized memory reads |
| `zebrad-ubsan` | UndefinedBehaviorSanitizer | Integer overflow, alignment |
| `zebrad-tsan` | ThreadSanitizer | Data race detection |
| `zebrad-coverage` | Source coverage | Guide fuzzing campaigns |
| `zebrad-debug` | Debug symbols | Crash triage and analysis |
| `zebrad-release` | Optimized | Baseline performance testing |

## Fuzzing Campaign

### Harness Categories (45+ harnesses)

1. **P2P Network Messages** (22 harnesses)
   - version, verack, ping, pong, addr, addrv2, inv, getdata, getblocks, getheaders
   - tx, block, headers, notfound, reject, filterload, filteradd, filterclear
   - mempool, sendheaders, sendcmpct, feefilter

2. **Transaction Deserialization** (5 harnesses)
   - tx_v4, tx_v5, tx_transparent, tx_sapling, tx_orchard

3. **Script and Address Parsing** (3 harnesses)
   - script_pubkey, script_sig, address

4. **RPC Interface** (5 harnesses)
   - rpc_json_request, rpc_sendrawtransaction, rpc_getblocktemplate
   - rpc_submithashrate, rpc_logging

5. **Core Data Structures** (4 harnesses)
   - block_deser, merkle_tree, note_commitment_tree, sighash_computation

6. **Cryptographic Primitives** (3 harnesses)
   - equihash_solution, redjubjub_sig, orchard_proof

### Fuzzing Tools

- **libFuzzer**: Primary fuzzer with structure-aware mutations
- **AFL++**: Persistent mode + QEMU mode for release binaries
- **Honggfuzz**: Hardware-assisted feedback (Intel PT when available)

### Campaign Duration

- Minimum 336 hours (14 days) per harness per version
- Total estimated compute: ~500,000 core-hours
- Continuous 24/7 operation with automated crash collection

## Symbolic Execution

### KLEE Configuration

- Target crates: zebra-chain, zebra-network, zebra-rpc, zebra-script, zebra-state
- Compiled to LLVM bitcode with thin C wrappers
- Search strategy: DFS for deep path exploration
- Maximum time: 24 hours per target function
- Focus: unsafe blocks, arithmetic on attacker-controlled lengths

### angr Configuration

- Direct binary analysis on compiled ELF
- Syscall hooks inject symbolic data (read, recv, recvfrom)
- Exploration bias toward unsafe blocks and system calls
- Detection of paths reaching dangerous functions with tainted arguments

## Dynamic Instrumentation

### Valgrind Memcheck

- Full test suite re-execution with `--track-origins=yes`
- Leak checking with `--leak-check=full`
- Captures subtle uninitialized-value errors

### Taint Tracking

- Custom Intel Pin/DynamoRIO tool
- Track taint from network input (recv syscalls) to memory accesses
- Log when tainted data used as pointer/length/offset
- Identify latent corruption sinks

### Record and Replay (rr)

- Every crash recorded for deterministic replay
- Full reproducibility on any workstation
- Essential for root cause analysis

## Unsafe Block Audit

### Static Analysis

- Enumerate all `unsafe` blocks in workspace
- Risk classification: high/medium/low based on network reachability
- Map to fuzzing harnesses for coverage verification

### Dynamic Verification

- Targeted harness per high-risk unsafe block
- Test with extreme sizes, invalid pointers, uninitialized memory
- ASAN/MSAN verification under worst-case inputs

### FFI Boundary Testing

- Wrap every FFI call (libsodium, blake2b, equihash, zcash_proofs)
- Fuzz with arbitrary buffers
- Build with instrumented C libraries for cross-language detection

## Dependency Audit

### Automated Scanning

- `cargo audit` on each version's Cargo.lock
- Reachability analysis for flagged advisories
- Prioritize reachable vulnerabilities

### Manual Deep-Dive

- hyper/tonic: HTTP header fuzzing, request smuggling
- rocksdb: Database I/O boundary fuzzing
- orchard/halo2/redjubjub: Cryptographic proof/signature fuzzing
- tokio: Extreme connection load and I/O pattern stress testing

## Manual Penetration Testing

1. **Format String Probes**: Test log messages with %n, %s, %x
2. **Directory Traversal**: Test file path RPC methods with ../
3. **Resource Exhaustion**: Flood with inv messages, fill mempool
4. **TOCTOU**: Race file access between check and open
5. **Consensus Splitting**: Craft edge-case blocks to desynchronize nodes

## Crash Triage Workflow

For each sanitizer crash or Valgrind error:

1. **Reproduce**: Store exact fuzzer input, create minimal reproducer
2. **Root Cause**: Use GDB + rr replay to identify corruption
3. **Classify Exploitability**:
   - RCE: Control of instruction pointer or critical data structures
   - DoS: Crash or hang without code execution
   - Information Leak: Out-of-bounds read exposing memory
   - Logic/Consensus Bug: Inconsistent state
4. **Proof-of-Concept**: Develop minimal PoC demonstrating severity
5. **Document**: Unique ID, affected versions, CVSS, reproduction steps

## Deliverables

1. **Comprehensive Audit Report**: All findings with root cause analysis
2. **Vulnerability Database**: Structured JSON/CSV with CVSS scores
3. **Reproducer Package**: All crash inputs, rr traces, PoC scripts
4. **Fuzzing Corpora**: All harnesses, seed corpora, build scripts
5. **Coverage Reports**: Daily snapshots highlighting untested code
6. **Disclosure Advisories**: Pre-written security advisories for critical bugs

## Timeline

| Phase | Duration | Activities |
|-------|----------|------------|
| Environment Setup | Weeks 1-2 | Compile binaries, build harnesses, deploy orchestration |
| Continuous Fuzzing | Weeks 3-10 | 24/7 fuzzing, weekly coverage reviews |
| Symbolic Execution | Week 11 | KLEE and angr deep-path analysis |
| Manual Testing | Weeks 12-13 | Adversarial testing, race condition hunting |
| Triage & PoC | Weeks 14-16 | Reproduce, classify, develop PoCs |
| Reporting | Week 17 | Final report, remediation guidance |

## Usage

### Building Instrumented Binaries

```bash
cd security-audit/infrastructure/build-scripts
./build-all-versions.sh
```

### Running Fuzzing Campaign

```bash
cd security-audit/scripts
./orchestrate-fuzzing.sh
```

### Generating Coverage Reports

```bash
cd security-audit/scripts
./generate-coverage.sh
```

### Triaging Crashes

```bash
cd security-audit/scripts
./triage-crash.sh <crash-file>
```

## Contact

This audit infrastructure was created following security best practices for comprehensive vulnerability discovery in consensus-critical blockchain node software.
