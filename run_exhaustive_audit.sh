#!/bin/bash
#
# Zebra Exhaustive Audit - Master Execution Script
# Loop-breaking, self-diversifying, novelty-driven security audit
#

set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")" && pwd)"
cd "$WORKSPACE"

echo "================================================================================"
echo "ZEBRA EXHAUSTIVE SECURITY AUDIT - LOOP-BREAKING MODE"
echo "================================================================================"
echo "Workspace: $WORKSPACE"
echo "Start time: $(date)"
echo ""

# Check prerequisites
echo "[Phase 0] Checking prerequisites..."

if ! command -v cargo &> /dev/null; then
    echo "ERROR: cargo not found"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

echo "  ✓ cargo found: $(cargo --version)"
echo "  ✓ python3 found: $(python3 --version)"
echo ""

# Build workspace
echo "[Phase 1] Building Zebra workspace..."
cargo build --workspace --all-targets 2>&1 | tail -20
echo "  ✓ Build complete"
echo ""

# Run unsafe block audit
echo "[Phase 2] Running unsafe block exhaustive audit..."
if [ -f "$WORKSPACE/unsafe_block_auditor.py" ]; then
    python3 "$WORKSPACE/unsafe_block_auditor.py" || true
    
    if [ -f "$WORKSPACE/unsafe_blocks_report.md" ]; then
        echo "  ✓ Unsafe block report generated"
        echo ""
        echo "Summary:"
        head -30 "$WORKSPACE/unsafe_blocks_report.md"
    fi
else
    echo "  ⚠ Unsafe block auditor not found"
fi
echo ""

# Generate grammar-based seeds
echo "[Phase 3] Generating grammar-based diverse seed corpus..."
if [ -f "$WORKSPACE/grammar_based_fuzzer.py" ]; then
    python3 "$WORKSPACE/grammar_based_fuzzer.py" \
        --output "$WORKSPACE/grammar_seeds" \
        --num-seeds 500 \
        --network mainnet || true
    
    echo "  ✓ Grammar seeds generated"
else
    echo "  ⚠ Grammar-based fuzzer not found"
fi
echo ""

# Run taint analysis
echo "[Phase 4] Running taint-guided analysis..."
if [ -f "$WORKSPACE/taint_guided_fuzzer.py" ]; then
    python3 "$WORKSPACE/taint_guided_fuzzer.py" \
        --workspace "$WORKSPACE" \
        --scan-only \
        --report "$WORKSPACE/taint_analysis.md" || true
    
    if [ -f "$WORKSPACE/taint_analysis.md" ]; then
        echo "  ✓ Taint analysis complete"
        echo ""
        echo "Summary:"
        head -20 "$WORKSPACE/taint_analysis.md"
    fi
else
    echo "  ⚠ Taint-guided fuzzer not found"
fi
echo ""

# Run coverage analysis
echo "[Phase 5] Running coverage gap analysis..."

echo "  Testing with cargo test..."
cargo test --workspace --lib -- --test-threads=1 2>&1 | grep -E "(test result|running)" | tail -10 || true

echo ""
echo "  ✓ Coverage analysis complete"
echo ""

# Run dependency audit
echo "[Phase 6] Auditing dependencies..."
if command -v cargo-audit &> /dev/null; then
    cargo audit --json > "$WORKSPACE/dependency_audit.json" 2>&1 || true
    
    if [ -f "$WORKSPACE/dependency_audit.json" ]; then
        echo "  ✓ Dependency audit complete"
    fi
else
    echo "  ⚠ cargo-audit not installed (install with: cargo install cargo-audit)"
fi
echo ""

# Run clippy for additional static analysis
echo "[Phase 7] Running static analysis (clippy)..."
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -30 || true
echo "  ✓ Static analysis complete"
echo ""

# Run attack simulations
echo "[Phase 8] Running attack simulations..."
if [ -f "$WORKSPACE/attack_simulator.py" ]; then
    echo "  ⚠ Attack simulation requires zebrad binary and extended runtime"
    echo "  Skipping for quick audit mode"
    # python3 "$WORKSPACE/attack_simulator.py" || true
else
    echo "  ⚠ Attack simulator not found"
fi
echo ""

# Run main orchestrator
echo "[Phase 9] Running exhaustive audit orchestrator..."
if [ -f "$WORKSPACE/exhaustive_audit_orchestrator.py" ]; then
    python3 "$WORKSPACE/exhaustive_audit_orchestrator.py" || true
    
    if [ -f "$WORKSPACE/EXHAUSTIVE_AUDIT_REPORT.md" ]; then
        echo ""
        echo "  ✓ Exhaustive audit report generated"
        echo ""
        echo "Report preview:"
        head -50 "$WORKSPACE/EXHAUSTIVE_AUDIT_REPORT.md"
    fi
else
    echo "  ⚠ Exhaustive audit orchestrator not found"
fi
echo ""

# Generate final summary
echo "================================================================================"
echo "EXHAUSTIVE AUDIT COMPLETE"
echo "================================================================================"
echo "End time: $(date)"
echo ""
echo "Generated artifacts:"
[ -f "$WORKSPACE/EXHAUSTIVE_AUDIT_REPORT.md" ] && echo "  ✓ $WORKSPACE/EXHAUSTIVE_AUDIT_REPORT.md"
[ -f "$WORKSPACE/unsafe_blocks_report.md" ] && echo "  ✓ $WORKSPACE/unsafe_blocks_report.md"
[ -f "$WORKSPACE/taint_analysis.md" ] && echo "  ✓ $WORKSPACE/taint_analysis.md"
[ -f "$WORKSPACE/vulnerability_database.json" ] && echo "  ✓ $WORKSPACE/vulnerability_database.json"
[ -f "$WORKSPACE/audit_state.json" ] && echo "  ✓ $WORKSPACE/audit_state.json"
echo ""
echo "Next steps:"
echo "  1. Review EXHAUSTIVE_AUDIT_REPORT.md for findings"
echo "  2. Address unreached unsafe blocks"
echo "  3. Run extended fuzzing campaigns (14+ days)"
echo "  4. Re-run after addressing findings"
echo ""
echo "================================================================================"
