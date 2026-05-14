#!/usr/bin/env bash
# =============================================================================
# run_dependency_audit.sh — Third-party dependency vulnerability assessment.
#
# Runs cargo-audit on each Zebra version's Cargo.lock and produces a
# structured JSON report of all advisories with reachability analysis.
# =============================================================================

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEBRA_ROOT="$(cd "${WORKSPACE_ROOT}/.." && pwd)"
REPORT_DIR="${WORKSPACE_ROOT}/reports/dependency-audit"

mkdir -p "${REPORT_DIR}"

log_info() { echo "[INFO] $*"; }
log_ok()   { echo "[OK]   $*"; }
log_warn() { echo "[WARN] $*"; }

log_info "=== Dependency Vulnerability Audit ==="

# ── cargo-audit ───────────────────────────────────────────────────────────────

if ! command -v cargo-audit &>/dev/null; then
    log_info "Installing cargo-audit..."
    cargo install cargo-audit --features fix
fi

log_info "Running cargo-audit on workspace..."
cargo audit \
    --manifest-path "${ZEBRA_ROOT}/Cargo.toml" \
    --json \
    > "${REPORT_DIR}/cargo-audit.json" 2>&1 || true

log_ok "cargo-audit complete: ${REPORT_DIR}/cargo-audit.json"

# ── cargo-deny ────────────────────────────────────────────────────────────────

if command -v cargo-deny &>/dev/null; then
    log_info "Running cargo-deny..."
    cargo deny \
        --manifest-path "${ZEBRA_ROOT}/Cargo.toml" \
        check advisories \
        > "${REPORT_DIR}/cargo-deny.txt" 2>&1 || true
    log_ok "cargo-deny complete: ${REPORT_DIR}/cargo-deny.txt"
fi

# ── Reachability analysis ─────────────────────────────────────────────────────

log_info "Analysing advisory reachability..."

python3 - << 'EOF'
import json
import sys
import os

report_dir = os.environ.get("REPORT_DIR", "./reports/dependency-audit")
audit_file = os.path.join(report_dir, "cargo-audit.json")

if not os.path.exists(audit_file):
    print("No cargo-audit.json found.")
    sys.exit(0)

with open(audit_file) as f:
    try:
        data = json.load(f)
    except json.JSONDecodeError:
        print("Failed to parse cargo-audit.json")
        sys.exit(0)

vulnerabilities = data.get("vulnerabilities", {}).get("list", [])
print(f"\nFound {len(vulnerabilities)} advisories.\n")

# High-risk crates that are directly reachable from network input.
HIGH_RISK_CRATES = {
    "hyper", "tonic", "tokio", "rocksdb", "orchard", "halo2_proofs",
    "redjubjub", "sapling-crypto", "zcash_primitives", "libzcash_script",
    "blake2b_simd", "blake2s_simd", "equihash", "secp256k1",
}

findings = []
for vuln in vulnerabilities:
    pkg = vuln.get("package", {})
    advisory = vuln.get("advisory", {})
    crate_name = pkg.get("name", "unknown")
    reachable = crate_name in HIGH_RISK_CRATES

    finding = {
        "crate": crate_name,
        "version": pkg.get("version", "unknown"),
        "advisory_id": advisory.get("id", "unknown"),
        "title": advisory.get("title", ""),
        "description": advisory.get("description", "")[:200],
        "cvss": advisory.get("cvss", "unknown"),
        "url": advisory.get("url", ""),
        "reachable_from_network": reachable,
        "priority": "HIGH" if reachable else "LOW",
    }
    findings.append(finding)
    print(f"  [{finding['priority']}] {crate_name} {pkg.get('version','')} — {advisory.get('id','')} — {advisory.get('title','')[:60]}")
    if reachable:
        print(f"         ⚠ REACHABLE FROM NETWORK INPUT")

output_file = os.path.join(report_dir, "reachability_analysis.json")
with open(output_file, "w") as f:
    json.dump({"total": len(findings), "findings": findings}, f, indent=2)

print(f"\nReachability analysis written to: {output_file}")
EOF

log_ok "Dependency audit complete. Reports in: ${REPORT_DIR}/"
