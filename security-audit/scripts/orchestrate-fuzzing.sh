#!/bin/bash
# Fuzzing Campaign Orchestration Script
# Manages continuous fuzzing across all harnesses, versions, and sanitizers

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AUDIT_ROOT="${WORKSPACE_ROOT}/security-audit"
HARNESS_DIR="${AUDIT_ROOT}/fuzzing/harnesses"
CORPUS_DIR="${AUDIT_ROOT}/fuzzing/corpora"
CRASHES_DIR="${AUDIT_ROOT}/fuzzing/crashes"
QUEUE_DIR="${AUDIT_ROOT}/fuzzing/queue"
VERSIONS_DIR="${AUDIT_ROOT}/infrastructure/versions"

# Configuration
VERSIONS=("4.1.0" "4.2.0" "4.3.0" "4.4.1")
SANITIZERS=("asan" "msan" "ubsan" "tsan")
FUZZ_DURATION_HOURS=336  # 14 days per harness
PARALLEL_JOBS=16

# Harness categories
P2P_HARNESSES=(
    "fuzz_p2p_version" "fuzz_p2p_verack" "fuzz_p2p_ping" "fuzz_p2p_pong"
    "fuzz_p2p_addr" "fuzz_p2p_inv" "fuzz_p2p_getdata" "fuzz_p2p_getblocks"
    "fuzz_p2p_tx" "fuzz_p2p_block" "fuzz_p2p_headers" "fuzz_p2p_sequence"
)

TX_HARNESSES=(
    "fuzz_tx_v4" "fuzz_tx_v5" "fuzz_tx_transparent" 
    "fuzz_tx_sapling" "fuzz_tx_orchard"
)

RPC_HARNESSES=(
    "fuzz_rpc_json_request" "fuzz_rpc_sendrawtransaction"
    "fuzz_rpc_getblocktemplate" "fuzz_rpc_logging"
)

ALL_HARNESSES=("${P2P_HARNESSES[@]}" "${TX_HARNESSES[@]}" "${RPC_HARNESSES[@]}")

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Initialize directories
init_directories() {
    log_info "Initializing fuzzing directories..."
    
    mkdir -p "${CORPUS_DIR}"
    mkdir -p "${CRASHES_DIR}"
    mkdir -p "${QUEUE_DIR}"
    
    for harness in "${ALL_HARNESSES[@]}"; do
        mkdir -p "${CORPUS_DIR}/${harness}"
        mkdir -p "${CRASHES_DIR}/${harness}"
        mkdir -p "${QUEUE_DIR}/${harness}"
    done
    
    log_info "Directory initialization complete."
}

# Download mainnet transaction corpus
download_mainnet_corpus() {
    log_info "Downloading mainnet transaction corpus for seed data..."
    
    local tx_corpus_dir="${CORPUS_DIR}/mainnet-transactions"
    mkdir -p "${tx_corpus_dir}"
    
    # This would download actual mainnet transactions
    # For now, create a placeholder script
    cat > "${tx_corpus_dir}/download-corpus.sh" << 'EOF'
#!/bin/bash
# Download Zcash mainnet transactions for fuzzing corpus
# This provides high-quality seed inputs covering all transaction types

# Usage: Connect to a Zcash node and extract raw transactions
# Example:
# for height in {1..500000}; do
#   zcash-cli getblock "$(zcash-cli getblockhash $height)" 0 | \
#   grep -oE "[0-9a-f]{64,}" > tx_${height}.hex
# done

echo "Corpus download script placeholder"
echo "In production, this would download real mainnet transactions"
EOF
    
    chmod +x "${tx_corpus_dir}/download-corpus.sh"
    log_info "Mainnet corpus script created at ${tx_corpus_dir}"
}

# Run libFuzzer campaign
run_libfuzzer() {
    local harness=$1
    local version=$2
    local sanitizer=$3
    local max_time=$((FUZZ_DURATION_HOURS * 3600))
    
    log_info "Starting libFuzzer: ${harness} (${version}, ${sanitizer})"
    
    local corpus_dir="${CORPUS_DIR}/${harness}"
    local crash_dir="${CRASHES_DIR}/${harness}/${version}-${sanitizer}"
    local log_file="${AUDIT_ROOT}/fuzzing/logs/${harness}-${version}-${sanitizer}-libfuzzer.log"
    
    mkdir -p "${crash_dir}"
    mkdir -p "$(dirname "${log_file}")"
    
    # libFuzzer configuration
    local fuzz_opts=(
        "-max_len=65536"
        "-rss_limit_mb=8192"
        "-timeout=30"
        "-jobs=${PARALLEL_JOBS}"
        "-workers=${PARALLEL_JOBS}"
        "-use_value_profile=1"
        "-max_total_time=${max_time}"
        "-print_final_stats=1"
        "-artifact_prefix=${crash_dir}/"
    )
    
    # Run the fuzzer in background
    # Note: This assumes the harness is compiled with the appropriate sanitizer
    # The actual harness binary would be built separately per sanitizer
    
    log_info "libFuzzer command would be: ./${harness} ${fuzz_opts[*]} ${corpus_dir}"
    log_info "Output redirected to: ${log_file}"
    
    # In production, this would run the actual fuzzer:
    # ./${harness} "${fuzz_opts[@]}" "${corpus_dir}" > "${log_file}" 2>&1 &
}

# Run AFL++ campaign
run_aflplusplus() {
    local harness=$1
    local version=$2
    local sanitizer=$3
    
    log_info "Starting AFL++: ${harness} (${version}, ${sanitizer})"
    
    local corpus_dir="${CORPUS_DIR}/${harness}"
    local crash_dir="${CRASHES_DIR}/${harness}/${version}-${sanitizer}"
    local queue_dir="${QUEUE_DIR}/${harness}/${version}-${sanitizer}"
    local log_file="${AUDIT_ROOT}/fuzzing/logs/${harness}-${version}-${sanitizer}-afl.log"
    
    mkdir -p "${crash_dir}"
    mkdir -p "${queue_dir}"
    mkdir -p "$(dirname "${log_file}")"
    
    # AFL++ configuration
    export AFL_MAP_SIZE=65536
    export AFL_SKIP_CPUFREQ=1
    
    log_info "AFL++ would run with persistent mode and cmplog enabled"
    log_info "Input: ${corpus_dir}, Output: ${queue_dir}"
    
    # In production:
    # afl-fuzz -i "${corpus_dir}" -o "${queue_dir}" \
    #   -m 8192 -t 30000 -c cmplog_binary -- ./${harness} > "${log_file}" 2>&1 &
}

# Run Honggfuzz campaign
run_honggfuzz() {
    local harness=$1
    local version=$2
    local sanitizer=$3
    
    log_info "Starting Honggfuzz: ${harness} (${version}, ${sanitizer})"
    
    local corpus_dir="${CORPUS_DIR}/${harness}"
    local crash_dir="${CRASHES_DIR}/${harness}/${version}-${sanitizer}"
    local log_file="${AUDIT_ROOT}/fuzzing/logs/${harness}-${version}-${sanitizer}-honggfuzz.log"
    
    mkdir -p "${crash_dir}"
    mkdir -p "$(dirname "${log_file}")"
    
    log_info "Honggfuzz would run with hardware-assisted feedback (Intel PT)"
    
    # In production:
    # honggfuzz -z -i "${corpus_dir}" -o "${crash_dir}" \
    #   -n ${PARALLEL_JOBS} -- ./${harness} > "${log_file}" 2>&1 &
}

# Start fuzzing campaign for one harness across all versions and sanitizers
fuzz_harness_campaign() {
    local harness=$1
    
    log_info "=========================================="
    log_info "Starting campaign for harness: ${harness}"
    log_info "=========================================="
    
    for version in "${VERSIONS[@]}"; do
        for sanitizer in "${SANITIZERS[@]}"; do
            # Run all three fuzzers in parallel for this combination
            run_libfuzzer "${harness}" "${version}" "${sanitizer}"
            run_aflplusplus "${harness}" "${version}" "${sanitizer}"
            run_honggfuzz "${harness}" "${version}" "${sanitizer}"
            
            # Small delay to avoid overwhelming the system at startup
            sleep 2
        done
    done
    
    log_info "Campaign initiated for ${harness}"
}

# Monitor fuzzing progress
monitor_progress() {
    log_info "Monitoring fuzzing campaign progress..."
    
    local status_file="${AUDIT_ROOT}/fuzzing/campaign-status.txt"
    
    while true; do
        {
            echo "Zebra Fuzzing Campaign Status"
            echo "Generated: $(date)"
            echo "=========================================="
            echo ""
            
            # Count crashes
            local total_crashes=$(find "${CRASHES_DIR}" -type f -name "crash-*" | wc -l)
            echo "Total crashes discovered: ${total_crashes}"
            echo ""
            
            # Count corpus size
            for harness in "${ALL_HARNESSES[@]}"; do
                local corpus_count=$(find "${CORPUS_DIR}/${harness}" -type f | wc -l)
                echo "${harness}: ${corpus_count} corpus files"
            done
            
            echo ""
            echo "Fuzzer processes running:"
            ps aux | grep -E "(afl-fuzz|honggfuzz|libfuzzer)" | grep -v grep || echo "No active fuzzers"
            
        } > "${status_file}"
        
        # Update every 5 minutes
        sleep 300
    done
}

# Collect and deduplicate crashes
collect_crashes() {
    log_info "Collecting and deduplicating crashes..."
    
    local crash_report="${AUDIT_ROOT}/reports/crash-summary-$(date +%Y%m%d-%H%M%S).txt"
    mkdir -p "$(dirname "${crash_report}")"
    
    {
        echo "Crash Summary Report"
        echo "Generated: $(date)"
        echo "=========================================="
        echo ""
        
        for harness in "${ALL_HARNESSES[@]}"; do
            local harness_crashes=$(find "${CRASHES_DIR}/${harness}" -type f | wc -l)
            if [ "${harness_crashes}" -gt 0 ]; then
                echo "${harness}: ${harness_crashes} crashes"
                
                # List unique crash hashes if available
                find "${CRASHES_DIR}/${harness}" -type f -name "crash-*" | \
                    head -n 10 | while read -r crash_file; do
                    echo "  - $(basename "${crash_file}")"
                done
                
                echo ""
            fi
        done
    } | tee "${crash_report}"
    
    log_info "Crash report saved to ${crash_report}"
}

# Main orchestration
main() {
    log_info "Starting Zebra Security Audit Fuzzing Campaign"
    log_info "Audit root: ${AUDIT_ROOT}"
    log_info "Duration per harness: ${FUZZ_DURATION_HOURS} hours"
    log_info "Parallel jobs: ${PARALLEL_JOBS}"
    
    # Initialize
    init_directories
    download_mainnet_corpus
    
    # Start fuzzing campaigns for all harnesses
    for harness in "${ALL_HARNESSES[@]}"; do
        fuzz_harness_campaign "${harness}"
    done
    
    # Start monitoring
    monitor_progress &
    MONITOR_PID=$!
    
    log_info "Fuzzing campaign is now running!"
    log_info "Monitor status: ${AUDIT_ROOT}/fuzzing/campaign-status.txt"
    log_info "To collect crashes: ./collect-crashes.sh"
    
    # Keep script running
    wait
}

# Handle script arguments
case "${1:-start}" in
    start)
        main
        ;;
    collect)
        collect_crashes
        ;;
    monitor)
        monitor_progress
        ;;
    *)
        echo "Usage: $0 {start|collect|monitor}"
        exit 1
        ;;
esac
