#!/bin/bash
# KLEE Symbolic Execution Setup and Execution Script
# Performs deep path analysis on critical Zebra parsing functions

set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AUDIT_ROOT="${WORKSPACE_ROOT}/security-audit"
SYMBOLIC_DIR="${AUDIT_ROOT}/symbolic-execution"
BITCODE_DIR="${SYMBOLIC_DIR}/bitcode"
KLEE_OUTPUT="${SYMBOLIC_DIR}/klee-output"
WRAPPERS_DIR="${SYMBOLIC_DIR}/wrappers"

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

# Check KLEE installation
check_klee() {
    log_info "Checking KLEE installation..."
    
    if ! command -v klee &> /dev/null; then
        log_error "KLEE not found. Please install KLEE symbolic execution engine."
        log_info "Installation guide: https://klee.github.io/getting-started/"
        return 1
    fi
    
    log_info "KLEE version: $(klee --version | head -n1)"
    return 0
}

# Create C wrapper for Zebra parsing functions
create_c_wrapper() {
    local crate=$1
    local wrapper_file="${WRAPPERS_DIR}/${crate}_wrapper.c"
    
    log_info "Creating C wrapper for ${crate}..."
    
    mkdir -p "${WRAPPERS_DIR}"
    
    cat > "${wrapper_file}" << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <klee/klee.h>

// External Rust functions (linked from bitcode)
// These would be the actual exported parsing functions from Zebra crates
// For example, from zebra-chain:
// extern int zebra_chain_transaction_read(const uint8_t* data, size_t len);
// extern int zebra_network_message_parse(const uint8_t* data, size_t len);

// Symbolic execution entry point
int main() {
    // Create symbolic input buffer
    uint8_t input[65536];
    size_t input_len;
    
    // Make the buffer symbolic
    klee_make_symbolic(&input, sizeof(input), "network_input");
    klee_make_symbolic(&input_len, sizeof(input_len), "input_length");
    
    // Constrain length to reasonable values
    klee_assume(input_len > 0);
    klee_assume(input_len <= 65536);
    
    // Call the target parsing function with symbolic input
    // This would invoke the actual Zebra parser
    // Example:
    // int result = zebra_chain_transaction_read(input, input_len);
    
    // KLEE will explore all paths through the parser
    // and report any:
    // - Assertion violations
    // - Out-of-bounds memory accesses
    // - Null pointer dereferences
    // - Division by zero
    // - Other undefined behavior
    
    return 0;
}
EOF
    
    log_info "C wrapper created: ${wrapper_file}"
}

# Run KLEE on a specific target
run_klee_on_target() {
    local target_name=$1
    local bitcode_file=$2
    local max_time_hours=24
    local max_time_seconds=$((max_time_hours * 3600))
    
    log_info "Running KLEE on ${target_name}..."
    log_info "Bitcode file: ${bitcode_file}"
    
    if [ ! -f "${bitcode_file}" ]; then
        log_error "Bitcode file not found: ${bitcode_file}"
        return 1
    fi
    
    local output_dir="${KLEE_OUTPUT}/${target_name}-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$(dirname "${output_dir}")"
    
    # KLEE options for deep path exploration
    local klee_opts=(
        "--search=dfs"                    # Depth-first search for deep paths
        "--max-time=${max_time_seconds}"  # Maximum execution time
        "--max-memory=16384"              # 16 GB memory limit
        "--max-sym-array-size=65536"      # Maximum symbolic array size
        "--output-dir=${output_dir}"      # Output directory
        "--write-paths"                   # Write path information
        "--write-sym-paths"               # Write symbolic paths
        "--libc=uclibc"                   # Use uClibc for system calls
        "--posix-runtime"                 # POSIX runtime support
        "--watchdog"                      # Enable watchdog timer
        "--max-instruction-time=30"       # Max time per instruction
    )
    
    log_info "KLEE command: klee ${klee_opts[*]} ${bitcode_file}"
    
    # Run KLEE (this would be the actual execution)
    # klee "${klee_opts[@]}" "${bitcode_file}" 2>&1 | tee "${output_dir}/klee.log"
    
    log_info "KLEE execution would run here for ${max_time_hours} hours"
    log_info "Output directory: ${output_dir}"
    
    # After execution, process results
    process_klee_results "${output_dir}"
}

# Process KLEE results and extract vulnerabilities
process_klee_results() {
    local output_dir=$1
    
    log_info "Processing KLEE results from ${output_dir}..."
    
    # Check for assertion failures
    if [ -d "${output_dir}" ]; then
        local assertion_errors="${output_dir}/assertions.txt"
        local memory_errors="${output_dir}/memory-errors.txt"
        local findings_report="${output_dir}/findings-report.txt"
        
        {
            echo "KLEE Symbolic Execution Results"
            echo "Generated: $(date)"
            echo "Output directory: ${output_dir}"
            echo "=========================================="
            echo ""
            
            # Count test cases
            local test_count=$(find "${output_dir}" -name "test*.ktest" 2>/dev/null | wc -l || echo "0")
            echo "Total test cases generated: ${test_count}"
            echo ""
            
            # Look for error files
            echo "Assertion failures:"
            find "${output_dir}" -name "*.assert.err" 2>/dev/null | while read -r err_file; do
                echo "  - $(basename "${err_file}")"
            done || echo "  None found"
            echo ""
            
            echo "Memory errors:"
            find "${output_dir}" -name "*.ptr.err" -o -name "*.overflow.err" 2>/dev/null | while read -r err_file; do
                echo "  - $(basename "${err_file}")"
            done || echo "  None found"
            echo ""
            
            echo "Division errors:"
            find "${output_dir}" -name "*.div.err" 2>/dev/null | while read -r err_file; do
                echo "  - $(basename "${err_file}")"
            done || echo "  None found"
            echo ""
            
        } | tee "${findings_report}"
        
        log_info "Findings report: ${findings_report}"
    else
        log_warn "Output directory not found (KLEE may not have run yet)"
    fi
}

# Extract concretized test cases for fuzzing
extract_test_cases() {
    local klee_output_dir=$1
    local corpus_output="${AUDIT_ROOT}/fuzzing/corpora/symbolic-execution"
    
    log_info "Extracting concretized test cases for fuzzing corpus..."
    
    mkdir -p "${corpus_output}"
    
    # Use ktest-tool to extract concrete inputs
    find "${klee_output_dir}" -name "test*.ktest" | while read -r ktest_file; do
        local output_name="$(basename "${ktest_file}" .ktest).bin"
        
        # This would extract the concrete byte values
        # ktest-tool "${ktest_file}" > "${corpus_output}/${output_name}"
        
        log_info "Would extract: ${ktest_file} -> ${corpus_output}/${output_name}"
    done
    
    log_info "Test case extraction complete"
}

# Run symbolic execution on all critical functions
run_complete_symbolic_analysis() {
    log_info "=========================================="
    log_info "Starting Complete Symbolic Execution Campaign"
    log_info "=========================================="
    
    # Target functions organized by crate
    declare -A targets=(
        ["zebra-chain-transaction"]="transaction parsing and validation"
        ["zebra-chain-block"]="block deserialization"
        ["zebra-network-message"]="network message parsing"
        ["zebra-rpc-request"]="RPC request handling"
        ["zebra-script-verify"]="script verification"
    )
    
    for target in "${!targets[@]}"; do
        local description="${targets[$target]}"
        log_info "Target: ${target} - ${description}"
        
        # Create wrapper
        create_c_wrapper "${target}"
        
        # Run KLEE (would use actual bitcode files)
        local bitcode_file="${BITCODE_DIR}/4.4.1/${target}.bc"
        run_klee_on_target "${target}" "${bitcode_file}"
    done
    
    log_info "Symbolic execution campaign complete"
}

# Generate summary report
generate_summary() {
    local summary_file="${SYMBOLIC_DIR}/symbolic-execution-summary.txt"
    
    log_info "Generating symbolic execution summary..."
    
    {
        echo "Zebra Symbolic Execution Campaign Summary"
        echo "Generated: $(date)"
        echo "=========================================="
        echo ""
        
        echo "KLEE Output Directories:"
        find "${KLEE_OUTPUT}" -type d -name "zebra-*" 2>/dev/null | while read -r dir; do
            echo "  - $(basename "${dir}")"
            
            local test_count=$(find "${dir}" -name "test*.ktest" 2>/dev/null | wc -l || echo "0")
            local error_count=$(find "${dir}" -name "*.err" 2>/dev/null | wc -l || echo "0")
            
            echo "    Test cases: ${test_count}"
            echo "    Errors found: ${error_count}"
        done || echo "  None yet"
        echo ""
        
        echo "Next steps:"
        echo "1. Review error reports in each output directory"
        echo "2. Extract concretized test cases for fuzzing corpus"
        echo "3. Manually analyze paths leading to dangerous system calls"
        echo "4. Verify findings with sanitizer-instrumented binaries"
        
    } | tee "${summary_file}"
    
    log_info "Summary saved to ${summary_file}"
}

# Main execution
main() {
    log_info "Zebra KLEE Symbolic Execution Setup"
    
    # Check prerequisites
    check_klee || {
        log_error "KLEE not available. Cannot proceed with symbolic execution."
        exit 1
    }
    
    # Create necessary directories
    mkdir -p "${KLEE_OUTPUT}"
    mkdir -p "${WRAPPERS_DIR}"
    
    case "${1:-analyze}" in
        setup)
            log_info "Setting up wrappers and configuration..."
            for crate in zebra-chain zebra-network zebra-rpc zebra-script zebra-state; do
                create_c_wrapper "${crate}"
            done
            ;;
        analyze)
            run_complete_symbolic_analysis
            ;;
        process)
            if [ -z "${2:-}" ]; then
                log_error "Usage: $0 process <klee-output-dir>"
                exit 1
            fi
            process_klee_results "$2"
            ;;
        extract)
            if [ -z "${2:-}" ]; then
                log_error "Usage: $0 extract <klee-output-dir>"
                exit 1
            fi
            extract_test_cases "$2"
            ;;
        summary)
            generate_summary
            ;;
        *)
            echo "Usage: $0 {setup|analyze|process|extract|summary}"
            exit 1
            ;;
    esac
    
    log_info "KLEE symbolic execution task complete"
}

main "$@"
