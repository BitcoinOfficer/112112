#!/usr/bin/env bash
# =============================================================================
# build_sanitized.sh — Build all Zebra instrumented binaries for the audit.
#
# Produces the following binary variants for each Zebra version:
#   zebrad-asan    — AddressSanitizer
#   zebrad-msan    — MemorySanitizer
#   zebrad-ubsan   — UndefinedBehaviourSanitizer
#   zebrad-tsan    — ThreadSanitizer
#   zebrad-coverage — Source-based coverage
#   zebrad-debug   — Debug symbols, no sanitisers
#   zebrad-release — Optimised release build
#
# Usage:
#   ./build_sanitized.sh [--version 4.4.1] [--output-dir ./binaries]
#
# Requirements:
#   - Rust nightly toolchain (for -Zsanitizer flags)
#   - clang/llvm (for sanitiser runtime libraries)
#   - cargo-fuzz (for libFuzzer harnesses)
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZEBRA_ROOT="$(cd "${WORKSPACE_ROOT}/.." && pwd)"
OUTPUT_DIR="${WORKSPACE_ROOT}/binaries"
ZEBRA_VERSION="${ZEBRA_VERSION:-current}"
NIGHTLY_TOOLCHAIN="nightly"
TARGET="x86_64-unknown-linux-gnu"
JOBS="${JOBS:-$(nproc)}"

# ── Colours ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)    ZEBRA_VERSION="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2";    shift 2 ;;
        --jobs)       JOBS="$2";          shift 2 ;;
        *) log_error "Unknown argument: $1"; exit 1 ;;
    esac
done

mkdir -p "${OUTPUT_DIR}/${ZEBRA_VERSION}"

# ── Helper: build with given RUSTFLAGS ───────────────────────────────────────

build_variant() {
    local variant="$1"
    local rustflags="$2"
    local toolchain="$3"
    local extra_features="${4:-}"
    local output_name="zebrad-${variant}"

    log_info "Building ${output_name} (version=${ZEBRA_VERSION})"

    local cargo_cmd="cargo"
    if [[ "${toolchain}" == "nightly" ]]; then
        cargo_cmd="cargo +${NIGHTLY_TOOLCHAIN}"
    fi

    RUSTFLAGS="${rustflags}" \
    ${cargo_cmd} build \
        --manifest-path "${ZEBRA_ROOT}/Cargo.toml" \
        --package zebrad \
        --target "${TARGET}" \
        --jobs "${JOBS}" \
        ${extra_features} \
        2>&1 | tee "${OUTPUT_DIR}/${ZEBRA_VERSION}/${output_name}.build.log"

    local src_binary="${ZEBRA_ROOT}/target/${TARGET}/debug/zebrad"
    if [[ -f "${src_binary}" ]]; then
        cp "${src_binary}" "${OUTPUT_DIR}/${ZEBRA_VERSION}/${output_name}"
        log_ok "Built ${output_name}"
    else
        log_warn "Binary not found after build: ${src_binary}"
    fi
}

# ── Build variants ────────────────────────────────────────────────────────────

log_info "=== Zebra Security Audit — Sanitised Build ==="
log_info "Zebra root:  ${ZEBRA_ROOT}"
log_info "Output dir:  ${OUTPUT_DIR}/${ZEBRA_VERSION}"
log_info "Version:     ${ZEBRA_VERSION}"
log_info "Jobs:        ${JOBS}"
echo

# 1. ASAN — AddressSanitizer
build_variant "asan" \
    "-Zsanitizer=address -C opt-level=1 -C debuginfo=2" \
    "nightly"

# 2. MSAN — MemorySanitizer
build_variant "msan" \
    "-Zsanitizer=memory -Zsanitizer-memory-track-origins=2 -C opt-level=1 -C debuginfo=2" \
    "nightly"

# 3. UBSAN — UndefinedBehaviourSanitizer
build_variant "ubsan" \
    "-Zsanitizer=undefined -C opt-level=1 -C debuginfo=2" \
    "nightly"

# 4. TSAN — ThreadSanitizer
build_variant "tsan" \
    "-Zsanitizer=thread -C opt-level=1 -C debuginfo=2" \
    "nightly"

# 5. Coverage — Source-based coverage instrumentation
build_variant "coverage" \
    "-C instrument-coverage -C opt-level=0 -C debuginfo=2" \
    "nightly"

# 6. Debug — Full debug symbols, no sanitisers
build_variant "debug" \
    "-C debuginfo=2 -C opt-level=0 -C overflow-checks=on" \
    "stable"

# 7. Release — Optimised release build
RUSTFLAGS="-C opt-level=3 -C lto=thin" \
cargo build \
    --manifest-path "${ZEBRA_ROOT}/Cargo.toml" \
    --package zebrad \
    --target "${TARGET}" \
    --release \
    --jobs "${JOBS}" \
    2>&1 | tee "${OUTPUT_DIR}/${ZEBRA_VERSION}/zebrad-release.build.log"

if [[ -f "${ZEBRA_ROOT}/target/${TARGET}/release/zebrad" ]]; then
    cp "${ZEBRA_ROOT}/target/${TARGET}/release/zebrad" \
       "${OUTPUT_DIR}/${ZEBRA_VERSION}/zebrad-release"
    log_ok "Built zebrad-release"
fi

# ── Build fuzzing harnesses ───────────────────────────────────────────────────

log_info "Building fuzzing harnesses with ASAN..."

HARNESS_DIR="${WORKSPACE_ROOT}/harnesses"
HARNESS_OUTPUT="${OUTPUT_DIR}/${ZEBRA_VERSION}/harnesses"
mkdir -p "${HARNESS_OUTPUT}"

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

for harness in "${HARNESSES[@]}"; do
    log_info "Building harness: ${harness}"
    RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=2" \
    cargo +${NIGHTLY_TOOLCHAIN} build \
        --manifest-path "${WORKSPACE_ROOT}/Cargo.toml" \
        --package "${harness}" \
        --target "${TARGET}" \
        --jobs "${JOBS}" \
        2>&1 | tail -5

    local_bin="${WORKSPACE_ROOT}/target/${TARGET}/debug/${harness}"
    if [[ -f "${local_bin}" ]]; then
        cp "${local_bin}" "${HARNESS_OUTPUT}/${harness}-asan"
        log_ok "  Built ${harness}-asan"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────

echo
log_info "=== Build Summary ==="
ls -lh "${OUTPUT_DIR}/${ZEBRA_VERSION}/" 2>/dev/null || true
echo
log_ok "All builds complete. Output: ${OUTPUT_DIR}/${ZEBRA_VERSION}/"
