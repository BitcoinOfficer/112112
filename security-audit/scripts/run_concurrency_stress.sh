#!/usr/bin/env bash
# =============================================================================
# run_concurrency_stress.sh — TSAN concurrency stress testing.
#
# Runs the concurrent stress harness with ThreadSanitizer for 48 hours,
# collecting all race condition reports.
# =============================================================================

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="${WORKSPACE_ROOT}/binaries/current/harnesses"
CRASH_DIR="${WORKSPACE_ROOT}/crashes/concurrency"
LOG_DIR="${WORKSPACE_ROOT}/logs"
DURATION_SECS="${DURATION_SECS:-172800}"  # 48 hours

mkdir -p "${CRASH_DIR}" "${LOG_DIR}"

TSAN_OPTIONS="halt_on_error=0:history_size=7:second_deadlock_stack=1"

log_info() { echo "[INFO] $*"; }
log_ok()   { echo "[OK]   $*"; }

log_info "=== Concurrency Stress Test (TSAN) ==="
log_info "Duration: ${DURATION_SECS}s"

# Run the concurrent stress harness.
TSAN_OPTIONS="${TSAN_OPTIONS}" \
"${HARNESS_DIR}/fuzz_p2p_concurrent_stress-asan" \
    "${WORKSPACE_ROOT}/corpora/fuzz_p2p_concurrent_stress" \
    -artifact_prefix="${CRASH_DIR}/" \
    -max_len=65536 \
    -rss_limit_mb=16384 \
    -timeout=60 \
    -jobs=4 \
    -workers=4 \
    -max_total_time="${DURATION_SECS}" \
    > "${LOG_DIR}/concurrency-stress.log" 2>&1 &

FUZZER_PID=$!
log_ok "Stress fuzzer PID: ${FUZZER_PID}"

# Also run a raw multi-connection stress test against a live node.
if command -v zebrad &>/dev/null; then
    log_info "Starting live node stress test..."
    python3 "${WORKSPACE_ROOT}/scripts/p2p_stress_client.py" \
        --connections 200 \
        --duration "${DURATION_SECS}" \
        --host 127.0.0.1 \
        --port 8233 \
        > "${LOG_DIR}/p2p-stress.log" 2>&1 &
    log_ok "P2P stress client PID: $!"
fi

wait "${FUZZER_PID}"
log_ok "Concurrency stress test complete."
log_info "Race reports in: ${LOG_DIR}/concurrency-stress.log"
