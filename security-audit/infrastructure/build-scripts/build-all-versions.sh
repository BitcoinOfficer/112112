#!/bin/bash
# Zebra Security Audit - Master Build Script
# Compiles all instrumented binaries for all target versions
# Each binary is compiled with different sanitizers and instrumentation

set -euo pipefail

# Configuration
VERSIONS=("4.1.0" "4.2.0" "4.3.0" "4.4.1")
WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)"
OUTPUT_DIR="${WORKSPACE_ROOT}/security-audit/infrastructure/versions"
LLVM_BC_DIR="${WORKSPACE_ROOT}/security-audit/symbolic-execution/bitcode"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "cargo not found. Please install Rust toolchain."
        exit 1
    fi
    
    if ! command -v rustup &> /dev/null; then
        log_error "rustup not found. Please install rustup."
        exit 1
    fi
    
    # Install required components
    log_info "Installing required Rust components..."
    rustup component add llvm-tools-preview
    rustup toolchain install nightly
    
    # Install cargo-fuzz if not present
    if ! command -v cargo-fuzz &> /dev/null; then
        log_info "Installing cargo-fuzz..."
        cargo install cargo-fuzz
    fi
    
    log_info "Prerequisites check completed."
}

# Clone Zebra repository at specific version
clone_version() {
    local version=$1
    local clone_dir="${OUTPUT_DIR}/zebra-${version}"
    
    log_info "Cloning Zebra version ${version}..."
    
    if [ -d "${clone_dir}" ]; then
        log_warn "Directory ${clone_dir} already exists. Skipping clone."
        return 0
    fi
    
    git clone --branch "v${version}" --depth 1 \
        https://github.com/ZcashFoundation/zebra.git "${clone_dir}" || {
        log_error "Failed to clone version ${version}"
        return 1
    }
    
    log_info "Successfully cloned version ${version}"
}

# Build with AddressSanitizer
build_asan() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local output_bin="${OUTPUT_DIR}/zebra-${version}-asan"
    
    log_info "Building ${version} with AddressSanitizer..."
    
    cd "${zebra_dir}"
    
    RUSTFLAGS="-Zsanitizer=address" \
    ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1" \
        cargo +nightly build --release --target x86_64-unknown-linux-gnu \
        --package zebrad 2>&1 | tee "${OUTPUT_DIR}/build-${version}-asan.log"
    
    cp target/x86_64-unknown-linux-gnu/release/zebrad "${output_bin}"
    
    log_info "ASAN build complete: ${output_bin}"
}

# Build with MemorySanitizer
build_msan() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local output_bin="${OUTPUT_DIR}/zebra-${version}-msan"
    
    log_info "Building ${version} with MemorySanitizer..."
    
    cd "${zebra_dir}"
    
    # MSAN requires rebuilding the standard library
    RUSTFLAGS="-Zsanitizer=memory -Zsanitizer-memory-track-origins" \
        cargo +nightly build -Zbuild-std --release \
        --target x86_64-unknown-linux-gnu --package zebrad \
        2>&1 | tee "${OUTPUT_DIR}/build-${version}-msan.log"
    
    cp target/x86_64-unknown-linux-gnu/release/zebrad "${output_bin}"
    
    log_info "MSAN build complete: ${output_bin}"
}

# Build with UndefinedBehaviorSanitizer
build_ubsan() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local output_bin="${OUTPUT_DIR}/zebra-${version}-ubsan"
    
    log_info "Building ${version} with UndefinedBehaviorSanitizer..."
    
    cd "${zebra_dir}"
    
    RUSTFLAGS="-Zsanitizer=undefined" \
        cargo +nightly build --release --target x86_64-unknown-linux-gnu \
        --package zebrad 2>&1 | tee "${OUTPUT_DIR}/build-${version}-ubsan.log"
    
    cp target/x86_64-unknown-linux-gnu/release/zebrad "${output_bin}"
    
    log_info "UBSAN build complete: ${output_bin}"
}

# Build with ThreadSanitizer
build_tsan() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local output_bin="${OUTPUT_DIR}/zebra-${version}-tsan"
    
    log_info "Building ${version} with ThreadSanitizer..."
    
    cd "${zebra_dir}"
    
    RUSTFLAGS="-Zsanitizer=thread" \
        cargo +nightly build --release --target x86_64-unknown-linux-gnu \
        --package zebrad 2>&1 | tee "${OUTPUT_DIR}/build-${version}-tsan.log"
    
    cp target/x86_64-unknown-linux-gnu/release/zebrad "${output_bin}"
    
    log_info "TSAN build complete: ${output_bin}"
}

# Build with coverage instrumentation
build_coverage() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local output_bin="${OUTPUT_DIR}/zebra-${version}-coverage"
    
    log_info "Building ${version} with coverage instrumentation..."
    
    cd "${zebra_dir}"
    
    RUSTFLAGS="-C instrument-coverage" \
        cargo +nightly build --release --package zebrad \
        2>&1 | tee "${OUTPUT_DIR}/build-${version}-coverage.log"
    
    cp target/release/zebrad "${output_bin}"
    
    log_info "Coverage build complete: ${output_bin}"
}

# Build debug version
build_debug() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local output_bin="${OUTPUT_DIR}/zebra-${version}-debug"
    
    log_info "Building ${version} with debug symbols..."
    
    cd "${zebra_dir}"
    
    RUSTFLAGS="-g -C debuginfo=2" \
        cargo build --package zebrad \
        2>&1 | tee "${OUTPUT_DIR}/build-${version}-debug.log"
    
    cp target/debug/zebrad "${output_bin}"
    
    log_info "Debug build complete: ${output_bin}"
}

# Build release version
build_release() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local output_bin="${OUTPUT_DIR}/zebra-${version}-release"
    
    log_info "Building ${version} release version..."
    
    cd "${zebra_dir}"
    
    cargo build --release --package zebrad \
        2>&1 | tee "${OUTPUT_DIR}/build-${version}-release.log"
    
    cp target/release/zebrad "${output_bin}"
    
    log_info "Release build complete: ${output_bin}"
}

# Build LLVM bitcode for symbolic execution
build_llvm_bitcode() {
    local version=$1
    local zebra_dir="${OUTPUT_DIR}/zebra-${version}"
    local bc_output_dir="${LLVM_BC_DIR}/${version}"
    
    log_info "Building ${version} LLVM bitcode for symbolic execution..."
    
    mkdir -p "${bc_output_dir}"
    cd "${zebra_dir}"
    
    # Key crates to compile to bitcode
    local crates=("zebra-chain" "zebra-network" "zebra-rpc" "zebra-script" "zebra-state")
    
    for crate in "${crates[@]}"; do
        log_info "Compiling ${crate} to LLVM bitcode..."
        
        RUSTFLAGS="--emit=llvm-bc" \
            cargo +nightly rustc --package "${crate}" --lib -- \
            --emit=llvm-bc 2>&1 | tee "${OUTPUT_DIR}/build-${version}-${crate}-bc.log"
        
        # Find and copy the .bc file
        find target -name "*.bc" -exec cp {} "${bc_output_dir}/" \;
    done
    
    log_info "LLVM bitcode build complete: ${bc_output_dir}"
}

# Build all variants for a specific version
build_version() {
    local version=$1
    
    log_info "=========================================="
    log_info "Building all variants for version ${version}"
    log_info "=========================================="
    
    # Clone the specific version
    clone_version "${version}" || return 1
    
    # Build all sanitizer variants
    build_asan "${version}" || log_error "ASAN build failed for ${version}"
    build_msan "${version}" || log_error "MSAN build failed for ${version}"
    build_ubsan "${version}" || log_error "UBSAN build failed for ${version}"
    build_tsan "${version}" || log_error "TSAN build failed for ${version}"
    
    # Build coverage and debug variants
    build_coverage "${version}" || log_error "Coverage build failed for ${version}"
    build_debug "${version}" || log_error "Debug build failed for ${version}"
    build_release "${version}" || log_error "Release build failed for ${version}"
    
    # Build LLVM bitcode
    build_llvm_bitcode "${version}" || log_error "LLVM bitcode build failed for ${version}"
    
    log_info "All builds complete for version ${version}"
}

# Generate build matrix summary
generate_summary() {
    log_info "Generating build matrix summary..."
    
    local summary_file="${OUTPUT_DIR}/build-matrix-summary.txt"
    
    {
        echo "Zebra Security Audit - Build Matrix Summary"
        echo "Generated: $(date)"
        echo "=========================================="
        echo ""
        
        for version in "${VERSIONS[@]}"; do
            echo "Version: ${version}"
            echo "  - ASAN:     ${OUTPUT_DIR}/zebra-${version}-asan"
            echo "  - MSAN:     ${OUTPUT_DIR}/zebra-${version}-msan"
            echo "  - UBSAN:    ${OUTPUT_DIR}/zebra-${version}-ubsan"
            echo "  - TSAN:     ${OUTPUT_DIR}/zebra-${version}-tsan"
            echo "  - Coverage: ${OUTPUT_DIR}/zebra-${version}-coverage"
            echo "  - Debug:    ${OUTPUT_DIR}/zebra-${version}-debug"
            echo "  - Release:  ${OUTPUT_DIR}/zebra-${version}-release"
            echo "  - Bitcode:  ${LLVM_BC_DIR}/${version}/"
            echo ""
        done
    } > "${summary_file}"
    
    log_info "Summary saved to ${summary_file}"
    cat "${summary_file}"
}

# Main execution
main() {
    log_info "Starting Zebra Security Audit Build Process"
    log_info "Workspace root: ${WORKSPACE_ROOT}"
    log_info "Output directory: ${OUTPUT_DIR}"
    
    # Create output directories
    mkdir -p "${OUTPUT_DIR}"
    mkdir -p "${LLVM_BC_DIR}"
    
    # Check prerequisites
    check_prerequisites
    
    # Build all versions
    for version in "${VERSIONS[@]}"; do
        build_version "${version}"
    done
    
    # Generate summary
    generate_summary
    
    log_info "Build process completed successfully!"
    log_info "All instrumented binaries are available in: ${OUTPUT_DIR}"
}

# Run main function
main "$@"
