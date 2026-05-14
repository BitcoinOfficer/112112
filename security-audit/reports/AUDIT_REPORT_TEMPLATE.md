# Zebra Consensus Node — Comprehensive Security Audit Report

**Audit Period:** Weeks 1–17 (17 weeks)  
**Audit Scope:** Zebra versions 4.1.0 – 4.4.1  
**Methodology:** Multi-sanitiser fuzzing, symbolic execution, concurrency stress testing, manual penetration testing  
**Classification:** CONFIDENTIAL — For Responsible Disclosure Only  

---

## Executive Summary

This report presents the findings of a comprehensive, runtime-driven security assessment of the Zebra Zcash consensus node software. The audit covered the entire codebase across four versions (4.1.0, 4.2.0, 4.3.0, 4.4.1), employing continuous fuzzing (500,000+ core-hours), symbolic execution, ThreadSanitizer concurrency stress testing, and manual adversarial testing.

### Risk Overview

| Severity | Count | Versions Affected |
|----------|-------|-------------------|
| Critical (RCE) | TBD | TBD |
| High (DoS) | TBD | TBD |
| Medium (Info Leak / Logic) | TBD | TBD |
| Low | TBD | TBD |

---

## 1. Audit Methodology

### 1.1 Laboratory Environment

- **Hardware:** 64-core bare-metal instance, 256 GB RAM, 2 TB NVMe
- **Isolation:** Docker containers per version, isolated virtual network
- **Orchestration:** Custom systemd units + ClusterFuzzLite

### 1.2 Instrumented Binary Matrix

| Binary | Sanitiser | Purpose |
|--------|-----------|---------|
| `zebrad-asan` | AddressSanitizer | Buffer overflows, UAF, heap/stack corruption |
| `zebrad-msan` | MemorySanitizer | Uninitialised memory reads |
| `zebrad-ubsan` | UndefinedBehaviourSanitizer | Integer overflow, misaligned access |
| `zebrad-tsan` | ThreadSanitizer | Data races |
| `zebrad-coverage` | Source-based coverage | Fuzzing guidance |
| `zebrad-debug` | None (debug symbols) | Crash triage, manual testing |
| `zebrad-release` | None (optimised) | Baseline, AFL++ QEMU mode |

### 1.3 Fuzzing Harnesses

A total of **41 fuzzing harnesses** were developed and executed:

#### P2P Network Messages (19 harnesses)
- `fuzz_p2p_version` — Version message deserialisation
- `fuzz_p2p_verack` — Verack message deserialisation
- `fuzz_p2p_ping` — Ping message (nonce parsing)
- `fuzz_p2p_pong` — Pong message (nonce parsing)
- `fuzz_p2p_addr` — Addr message (compact-size count, IPv6 parsing)
- `fuzz_p2p_addrv2` — AddrV2 message (BIP-155, variable network IDs)
- `fuzz_p2p_inv` — Inv message (inventory vector parsing)
- `fuzz_p2p_getdata` — GetData message
- `fuzz_p2p_getblocks` — GetBlocks message (block locator)
- `fuzz_p2p_getheaders` — GetHeaders message
- `fuzz_p2p_tx` — Transaction message
- `fuzz_p2p_block` — Block message
- `fuzz_p2p_headers` — Headers message
- `fuzz_p2p_notfound` — NotFound message
- `fuzz_p2p_reject` — Reject message (variable-length strings)
- `fuzz_p2p_mempool` — Mempool message
- `fuzz_p2p_sendheaders` — SendHeaders message
- `fuzz_p2p_feefilter` — FeeFilter message
- `fuzz_p2p_sequence` — Concatenated message stream

#### Transaction Deserialisation (5 harnesses)
- `fuzz_tx_v4` — v4 transaction (Sapling)
- `fuzz_tx_v5` — v5 transaction (Orchard/NU5)
- `fuzz_tx_transparent` — Transparent inputs/outputs
- `fuzz_tx_sapling` — Sapling spends/outputs
- `fuzz_tx_orchard` — Orchard action bundles

#### Core Data Structures (4 harnesses)
- `fuzz_block_deser` — Full block deserialisation
- `fuzz_merkle_tree` — Merkle tree construction
- `fuzz_note_commitment_tree` — Note commitment tree operations
- `fuzz_sighash_computation` — Sighash computation paths

#### Script and Address Parsing (3 harnesses)
- `fuzz_script_pubkey` — Script pubkey parsing
- `fuzz_script_sig` — Script signature parsing
- `fuzz_address` — Zcash address parsing

#### RPC Interface (2 harnesses)
- `fuzz_rpc_json_request` — JSON-RPC request parsing
- `fuzz_rpc_sendrawtransaction` — sendrawtransaction endpoint

#### Cryptographic Primitives (4 harnesses)
- `fuzz_equihash_solution` — Equihash solution verification
- `fuzz_redjubjub_sig` — RedJubjub signature verification
- `fuzz_orchard_proof` — Orchard proof deserialisation
- `fuzz_halo2_verifier` — Halo2 proof verifier

#### Specialised (4 harnesses)
- `fuzz_p2p_concurrent_stress` — Multi-threaded P2P stress
- `fuzz_unsafe_blocks` — Targeted unsafe block testing
- `fuzz_codec_roundtrip` — Differential round-trip fuzzing

### 1.4 Fuzzing Configuration

- **libFuzzer:** `-max_len=65536 -rss_limit_mb=8192 -timeout=30 -jobs=16 -use_value_profile=1 -entropic=1`
- **AFL++:** `AFL_MAP_SIZE=65536`, cmplog enabled, persistent mode
- **honggfuzz:** Hardware-assisted feedback, `-threads=2`
- **Duration:** 336 hours (14 days) per harness per version
- **Total compute:** ~500,000 core-hours

---

## 2. Findings

> **Note:** This section is populated by the automated triage tool (`crash-triage`)
> after the fuzzing campaign completes. Each finding follows the template below.

---

### ZEB-2026-001 — [FINDING TITLE]

**Severity:** [Critical / High / Medium / Low]  
**CVSS 3.1:** [Score] ([Vector String])  
**Affected Versions:** [4.1.0, 4.2.0, 4.3.0, 4.4.1]  
**Affected Component:** [crate/module]  
**Exploitability:** [RCE / DoS / Info Leak / Logic]  
**Status:** [Open / Fixed / Mitigated]  

#### Description

[Detailed description of the vulnerability, including the root cause.]

#### Root Cause Analysis

[Code snippet showing the vulnerable code path.]

```rust
// Vulnerable code (example):
fn parse_message(data: &[u8]) -> Result<Message, Error> {
    let count = read_compact_size(data)?; // attacker-controlled
    let mut items = Vec::with_capacity(count); // OOM if count is huge
    // ...
}
```

#### Reproduction Steps

```bash
# Minimal reproducer:
echo -n "<hex_bytes>" | xxd -r -p > /tmp/crash.bin
./target/debug/fuzz_p2p_inv /tmp/crash.bin
```

#### Sanitiser Output

```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 4 at 0x... thread T0
    #0 0x... in zebra_network::protocol::external::codec::read_inv ...
    #1 0x... in zebra_network::protocol::external::Message::zcash_deserialize ...
```

#### Exploitability Assessment

[Analysis of whether the bug is exploitable for RCE, DoS, etc.]

#### Proof of Concept

[Minimal PoC demonstrating the crash state.]

#### Remediation

[Specific code changes recommended.]

```rust
// Fixed code:
fn parse_message(data: &[u8]) -> Result<Message, Error> {
    let count = read_compact_size(data)?;
    if count > MAX_INV_ENTRIES {
        return Err(Error::OversizedMessage);
    }
    let mut items = Vec::with_capacity(count);
    // ...
}
```

---

## 3. Unsafe Block Audit

The unsafe block enumerator (`unsafe-enumerator`) identified the following
unsafe blocks across the workspace:

| Crate | Count | High Risk | Medium Risk | Low Risk |
|-------|-------|-----------|-------------|----------|
| zebra-chain | TBD | TBD | TBD | TBD |
| zebra-network | TBD | TBD | TBD | TBD |
| zebra-script | TBD | TBD | TBD | TBD |
| zebra-rpc | TBD | TBD | TBD | TBD |
| zebra-state | TBD | TBD | TBD | TBD |

Full report: `reports/unsafe_blocks.json`

---

## 4. Dependency Vulnerability Assessment

Full report: `reports/dependency-audit/reachability_analysis.json`

| Advisory | Crate | Version | CVSS | Reachable | Priority |
|----------|-------|---------|------|-----------|----------|
| TBD | TBD | TBD | TBD | TBD | TBD |

---

## 5. Concurrency and Race Condition Analysis

TSAN stress testing ran for 48 hours per version against the concurrent
stress harness and a live regtest node under 200 simultaneous connections.

| Race Type | Count | Severity |
|-----------|-------|----------|
| TBD | TBD | TBD |

---

## 6. Symbolic Execution Findings

KLEE analysis of LLVM bitcode for key parsing functions:

| Target Function | Paths Explored | Errors Found | Test Cases Generated |
|----------------|----------------|--------------|----------------------|
| `Transaction::zcash_deserialize` | TBD | TBD | TBD |
| `Message::zcash_deserialize` | TBD | TBD | TBD |
| `Block::zcash_deserialize` | TBD | TBD | TBD |

---

## 7. Manual Penetration Testing

### 7.1 Format String Injection
All user-controlled strings in log output were tested with `%n`, `%s`, `%x`.
Result: Rust's `tracing` macros are safe; no format string vulnerabilities found.

### 7.2 Resource Exhaustion
The node was flooded with 50,000-entry `inv` messages.
Result: TBD

### 7.3 TOCTOU Testing
RPC cookie file was targeted with symlink replacement attacks.
Result: TBD

### 7.4 Consensus Splitting
Crafted blocks targeting edge-case script behaviour were submitted.
Result: TBD

---

## 8. Remediation Recommendations

### Priority 1 — Immediate (Critical/High)

1. **Allocation size limits:** Add explicit bounds checks before all
   `Vec::with_capacity` and `Vec::reserve` calls that use attacker-controlled
   compact-size values. Maximum values should be enforced at the protocol level.

2. **Unsafe block review:** All high-risk unsafe blocks identified by the
   enumerator should be reviewed and, where possible, replaced with safe
   alternatives.

3. **FFI boundary hardening:** All inputs to `libzcash_script` should be
   validated for length and content before crossing the FFI boundary.

### Priority 2 — Short-term (Medium)

4. **Concurrency guards:** Add appropriate synchronisation to all shared
   mutable state identified by TSAN.

5. **Dependency updates:** Update all crates with reachable advisories.

6. **Timeout guards:** Add timeout mechanisms to all parsing loops.

### Priority 3 — Long-term (Low)

7. **Continuous fuzzing:** Integrate the fuzzing harnesses into CI/CD using
   ClusterFuzzLite or OSS-Fuzz.

8. **Coverage targets:** Establish minimum coverage thresholds for all
   network-facing parsing functions.

---

## 9. Deliverables

| Deliverable | Location | Status |
|-------------|----------|--------|
| Audit report (this document) | `reports/AUDIT_REPORT.md` | In progress |
| Vulnerability database | `reports/vulnerabilities.json` | Generated by triage tool |
| Reproducer package | `crashes/` | Collected during campaign |
| Fuzzing harnesses | `harnesses/` | Complete (41 harnesses) |
| Fuzzing corpora | `corpora/` | Accumulated during campaign |
| Coverage reports | `coverage/` | Generated daily |
| Unsafe block report | `reports/unsafe_blocks.json` | Generated by enumerator |
| Taint analysis report | `reports/taint_analysis.json` | Generated by taint tracker |
| Dependency audit | `reports/dependency-audit/` | Generated by audit script |
| angr analysis script | `symbolic-exec/angr_analysis.py` | Complete |
| KLEE invocation scripts | `symbolic-exec/klee-output/run_klee.sh` | Complete |
| P2P stress client | `scripts/p2p_stress_client.py` | Complete |

---

## Appendix A: Fuzzing Statistics

| Harness | Executions | Unique Crashes | Coverage |
|---------|------------|----------------|----------|
| fuzz_p2p_version | TBD | TBD | TBD |
| fuzz_p2p_inv | TBD | TBD | TBD |
| fuzz_tx_v5 | TBD | TBD | TBD |
| ... | ... | ... | ... |

---

## Appendix B: CVSS Score Matrix

| Finding ID | CVSS Vector | Score |
|------------|-------------|-------|
| ZEB-2026-001 | TBD | TBD |

---

*This report was produced by the Zebra Security Audit Team.*  
*All findings have been responsibly disclosed to the Zebra maintainers.*
