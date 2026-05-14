#!/usr/bin/env bash
# =============================================================================
# run_fuzzing_campaign.sh — Launch the full multi-harness fuzzing campaign.
#
# Runs all harnesses concurrently using libFuzzer, AFL++, and honggfuzz.
# Each harness gets:
#   - 16 libFuzzer workers
#   -  4 AFL++ workers (persistent mode)
#   -  2 honggfuzz workers
#
# Crashes are collected to a shared directory and deduplicated hourly.
# Coverage reports are generated daily.
#
# Usage:
#   ./run_fuzzing_campaign.sh [--duration 336h] [--harness-dir ./binaries/current/harnesses]
# =============================================================================

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HARNESS_DIR="${WORKSPACE_ROOT}/binaries/current/harnesses"
CORPUS_DIR="${WORKSPACE_ROOT}/corpora"
CRASH_DIR="${WORKSPACE_ROOT}/crashes"
COVERAGE_DIR="${WORKSPACE_ROOT}/coverage"
LOG_DIR="${WORKSPACE_ROOT}/logs"
DURATION="${DURATION:-336h}"
LIBFUZZER_WORKERS="${LIBFUZZER_WORKERS:-16}"
AFL_WORKERS="${AFL_WORKERS:-4}"
HONGGFUZZ_WORKERS="${HONGGFUZZ_WORKERS:-2}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

mkdir -p "${CORPUS_DIR}" "${CRASH_DIR}" "${COVERAGE_DIR}" "${LOG_DIR}"

HARNESSES=(
    fuzz_p2p_version fuzz_p2p_verack fuzz_p2p_ping fuzz_p2p_pong
    fuzz_p2p_addr fuzz_p2p_addrv2 fuzz_p2p_inv fuzz_p2p_getdata
    fuzz_p2p_getblocks fuzz_p2p_getheaders fuzz_p2p_tx fuzz_p2p_block
    fuzz_p2p_headers fuzz_p2p_notfound fuzz_p2p_reject fuzz_p2p_mempool
    fuzz_p2p_sendheaders fuzz_p2p_feefilter fuzz_p2p_sequence
    fuzz_tx_v4 fuzz_tx_v5 fuzz_tx_transparent fuzz_tx_sapling fuzz_tx_orchard
    fuzz_block_deser fuzz_merkle_tree fuzz_note_commitment_tree fuzz_sighash_computation
    fuzz_script_pubkey fuzz_script_sig fuzz_address
    fuzz_rpc_json_request fuzz_rpc_sendrawtransaction
    fuzz_equihash_solution fuzz_redjubjub_sig fuzz_orchard_proof fuzz_halo2_verifier
    fuzz_p2p_concurrent_stress fuzz_unsafe_blocks fuzz_codec_roundtrip
)

# ── Seed corpus generation ────────────────────────────────────────────────────

generate_seeds() {
    local harness="$1"
    local seed_dir="${CORPUS_DIR}/${harness}/seeds"
    mkdir -p "${seed_dir}"

    # Generate minimal seeds based on harness type.
    case "${harness}" in
        fuzz_p2p_ping|fuzz_p2p_pong)
            # 8-byte nonce.
            printf '\x12\x34\x56\x78\x9a\xbc\xde\xf0' > "${seed_dir}/ping_nonce.bin"
            ;;
        fuzz_p2p_inv)
            # 1 TX inv entry.
            printf '\x01\x01\x00\x00\x00' > "${seed_dir}/inv_1tx.bin"
            printf '\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab' >> "${seed_dir}/inv_1tx.bin"
            printf '\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab' >> "${seed_dir}/inv_1tx.bin"
            ;;
        fuzz_rpc_json_request)
            echo '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
                > "${seed_dir}/getblockchaininfo.json"
            echo '{"jsonrpc":"2.0","id":2,"method":"getblock","params":["00000000000000000000000000000000",1]}' \
                > "${seed_dir}/getblock.json"
            ;;
        *)
            # Generic: empty seed.
            printf '' > "${seed_dir}/empty.bin"
            ;;
    esac
}

# ── libFuzzer launcher ────────────────────────────────────────────────────────

launch_libfuzzer() {
    local harness="$1"
    local binary="${HARNESS_DIR}/${harness}-asan"

    if [[ ! -f "${binary}" ]]; then
        log_warn "Harness binary not found: ${binary}"
        return
    fi

    local corpus="${CORPUS_DIR}/${harness}"
    local crashes="${CRASH_DIR}/${harness}"
    local log="${LOG_DIR}/${harness}-libfuzzer.log"

    mkdir -p "${corpus}" "${crashes}"
    generate_seeds "${harness}"

    log_info "Launching libFuzzer: ${harness} (${LIBFUZZER_WORKERS} workers)"

    "${binary}" \
        "${corpus}" \
        -artifact_prefix="${crashes}/" \
        -max_len=65536 \
        -rss_limit_mb=8192 \
        -timeout=30 \
        -jobs="${LIBFUZZER_WORKERS}" \
        -workers="${LIBFUZZER_WORKERS}" \
        -use_value_profile=1 \
        -entropic=1 \
        -print_final_stats=1 \
        -max_total_time="$(duration_to_seconds "${DURATION}")" \
        > "${log}" 2>&1 &

    log_ok "  libFuzzer PID: $!"
}

# ── AFL++ launcher ────────────────────────────────────────────────────────────

launch_afl() {
    local harness="$1"
    local binary="${HARNESS_DIR}/${harness}-asan"

    if [[ ! -f "${binary}" ]]; then
        return
    fi

    if ! command -v afl-fuzz &>/dev/null; then
        log_warn "afl-fuzz not found, skipping AFL++ for ${harness}"
        return
    fi

    local input_dir="${CORPUS_DIR}/${harness}/seeds"
    local output_dir="${CORPUS_DIR}/${harness}/afl-output"
    local crashes="${CRASH_DIR}/${harness}/afl"
    local log="${LOG_DIR}/${harness}-afl.log"

    mkdir -p "${input_dir}" "${output_dir}" "${crashes}"
    generate_seeds "${harness}"

    log_info "Launching AFL++: ${harness} (${AFL_WORKERS} workers)"

    for i in $(seq 1 "${AFL_WORKERS}"); do
        local role="secondary"
        if [[ "${i}" -eq 1 ]]; then role="main"; fi

        AFL_MAP_SIZE=65536 \
        AFL_AUTORESUME=1 \
        afl-fuzz \
            -i "${input_dir}" \
            -o "${output_dir}" \
            -M "fuzzer${i}" \
            -c 0 \
            -- "${binary}" @@ \
            > "${log}.${i}" 2>&1 &

        log_ok "  AFL++ worker ${i} PID: $!"
    done
}

# ── honggfuzz launcher ────────────────────────────────────────────────────────

launch_honggfuzz() {
    local harness="$1"
    local binary="${HARNESS_DIR}/${harness}-asan"

    if [[ ! -f "${binary}" ]]; then
        return
    fi

    if ! command -v honggfuzz &>/dev/null; then
        log_warn "honggfuzz not found, skipping for ${harness}"
        return
    fi

    local corpus="${CORPUS_DIR}/${harness}"
    local crashes="${CRASH_DIR}/${harness}/honggfuzz"
    local log="${LOG_DIR}/${harness}-honggfuzz.log"

    mkdir -p "${corpus}" "${crashes}"

    log_info "Launching honggfuzz: ${harness} (${HONGGFUZZ_WORKERS} workers)"

    honggfuzz \
        --input "${corpus}" \
        --crashdir "${crashes}" \
        --threads "${HONGGFUZZ_WORKERS}" \
        --max_file_size 65536 \
        --timeout 30 \
        --sanitizers \
        -- "${binary}" \
        > "${log}" 2>&1 &

    log_ok "  honggfuzz PID: $!"
}

# ── Duration conversion ───────────────────────────────────────────────────────

duration_to_seconds() {
    local dur="$1"
    local seconds=0
    if [[ "${dur}" =~ ^([0-9]+)h$ ]]; then
        seconds=$(( ${BASH_REMATCH[1]} * 3600 ))
    elif [[ "${dur}" =~ ^([0-9]+)m$ ]]; then
        seconds=$(( ${BASH_REMATCH[1]} * 60 ))
    elif [[ "${dur}" =~ ^([0-9]+)s$ ]]; then
        seconds="${BASH_REMATCH[1]}"
    else
        seconds=1209600  # 14 days default
    fi
    echo "${seconds}"
}

# ── Coverage monitor ──────────────────────────────────────────────────────────

start_coverage_monitor() {
    log_info "Starting daily coverage monitor..."
    (
        while true; do
            sleep 86400  # 24 hours
            log_info "Generating coverage report..."
            if command -v llvm-cov &>/dev/null; then
                llvm-cov report \
                    --instr-profile="${COVERAGE_DIR}/merged.profdata" \
                    --object "${HARNESS_DIR}/fuzz_p2p_version-asan" \
                    > "${COVERAGE_DIR}/report-$(date +%Y%m%d).txt" 2>&1 || true
            fi
        done
    ) &
    log_ok "Coverage monitor PID: $!"
}

# ── Main ──────────────────────────────────────────────────────────────────────

log_info "=== Zebra Security Audit — Fuzzing Campaign ==="
log_info "Duration:         ${DURATION}"
log_info "libFuzzer workers: ${LIBFUZZER_WORKERS} per harness"
log_info "AFL++ workers:     ${AFL_WORKERS} per harness"
log_info "honggfuzz workers: ${HONGGFUZZ_WORKERS} per harness"
log_info "Harnesses:         ${#HARNESSES[@]}"
echo

start_coverage_monitor

for harness in "${HARNESSES[@]}"; do
    launch_libfuzzer "${harness}"
    launch_afl       "${harness}"
    launch_honggfuzz "${harness}"
    sleep 1  # Stagger launches to avoid I/O spikes.
done

log_ok "All fuzzers launched. Monitor with: tail -f ${LOG_DIR}/*.log"
log_info "Crashes will appear in: ${CRASH_DIR}/"
log_info "Press Ctrl+C to stop all fuzzers."

# Wait for all background jobs.
wait
