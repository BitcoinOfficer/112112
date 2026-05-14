#!/bin/bash
# Zebra Security Investigation Commands
# Generated: 2026-05-14
# 
# This script contains commands for deeper security analysis of Zebra.
# Run these commands in a development environment with Rust toolchain installed.
#
# DO NOT run this script directly - it's a reference guide for manual investigation.

set -e

echo "======================================================================"
echo "Zebra Security Investigation Command Reference"
echo "======================================================================"
echo ""
echo "⚠️  This is a REFERENCE script. Review and run commands individually."
echo ""

# =============================================================================
# Section 1: Panic and Unwrap Audit
# =============================================================================

echo "## 1. PANIC AND UNWRAP AUDIT"
echo ""

echo "Finding all unwraps in network-facing code:"
echo "$ rg 'unwrap\(\)' --type rust zebra-network/src/ zebra-chain/src/serialization/ --line-number"
echo ""

echo "Finding all expects in network-facing code:"
echo "$ rg 'expect\(' --type rust zebra-network/src/ zebra-chain/src/serialization/ --line-number"
echo ""

echo "Finding all asserts in network-facing code:"
echo "$ rg 'assert!\(' --type rust zebra-network/src/ zebra-chain/src/serialization/ --line-number"
echo ""

echo "Finding all panics:"
echo "$ rg 'panic!\(' --type rust zebra-network/src/ zebra-chain/src/serialization/ --line-number"
echo ""

echo "Finding all unreachables:"
echo "$ rg 'unreachable!\(' --type rust zebra-network/src/ zebra-chain/src/serialization/ --line-number"
echo ""

echo "Exclude test code from panic search:"
echo "$ rg '(unwrap|expect|assert!|panic!)\(' --type rust --glob '!**/tests/**' --glob '!**/*test*.rs' zebra-network/src/ --line-number"
echo ""

# =============================================================================
# Section 2: Unsafe Code Audit
# =============================================================================

echo "## 2. UNSAFE CODE AUDIT"
echo ""

echo "Finding all unsafe blocks:"
echo "$ rg 'unsafe' --type rust -A 10 -B 2"
echo ""

echo "Count unsafe blocks by file:"
echo "$ rg 'unsafe' --type rust --count"
echo ""

echo "Generate detailed unsafe code report:"
echo "$ rg 'unsafe' --type rust -A 10 -B 2 > unsafe-code-audit.txt"
echo ""

# =============================================================================
# Section 3: Dependency Security
# =============================================================================

echo "## 3. DEPENDENCY SECURITY"
echo ""

echo "Install cargo-audit:"
echo "$ cargo install cargo-audit"
echo ""

echo "Run security audit:"
echo "$ cargo audit"
echo ""

echo "Generate JSON report:"
echo "$ cargo audit --json > security-audit.json"
echo ""

echo "Deny warnings (fail on vulnerabilities):"
echo "$ cargo audit --deny warnings"
echo ""

echo "Check specific advisory database:"
echo "$ cargo audit --db ./advisory-db"
echo ""

echo "Update advisory database:"
echo "$ cargo audit fetch"
echo ""

# =============================================================================
# Section 4: Fuzzing Setup
# =============================================================================

echo "## 4. FUZZING SETUP"
echo ""

echo "Install cargo-fuzz:"
echo "$ cargo install cargo-fuzz"
echo ""

echo "Initialize fuzzing for a crate:"
echo "$ cd zebra-network && cargo fuzz init"
echo ""

echo "Create message decode fuzzer:"
cat << 'EOF'
$ cat > fuzz/fuzz_targets/message_decode.rs << 'FUZZ_EOF'
#![no_main]
use libfuzzer_sys::fuzz_target;
use zebra_network::protocol::external::codec::Codec;
use tokio_util::codec::Decoder;
use bytes::BytesMut;

fuzz_target!(|data: &[u8]| {
    let mut codec = Codec::builder().finish();
    let mut buf = BytesMut::from(data);
    let _ = codec.decode(&mut buf);
});
FUZZ_EOF
EOF
echo ""

echo "Run fuzzer:"
echo "$ cargo fuzz run message_decode -- -max_total_time=3600"
echo ""

echo "Run fuzzer with ASan:"
echo "$ RUSTFLAGS='-Zsanitizer=address' cargo fuzz run message_decode"
echo ""

echo "Run all fuzzers:"
echo "$ cargo fuzz list | xargs -I {} cargo fuzz run {} -- -max_total_time=600"
echo ""

# =============================================================================
# Section 5: Formal Verification with Kani
# =============================================================================

echo "## 5. FORMAL VERIFICATION (KANI)"
echo ""

echo "Install Kani:"
echo "$ cargo install --locked kani-verifier"
echo "$ cargo kani setup"
echo ""

echo "Run Kani on a crate:"
echo "$ cargo kani --package zebra-network"
echo ""

echo "Verify specific module:"
echo "$ cargo kani --package zebra-network --harness verify_message_length_bounded"
echo ""

echo "Generate verification report:"
echo "$ cargo kani --package zebra-network --verbose > kani-report.txt"
echo ""

# =============================================================================
# Section 6: MIRI (Undefined Behavior Detection)
# =============================================================================

echo "## 6. MIRI (UNDEFINED BEHAVIOR DETECTION)"
echo ""

echo "Install MIRI:"
echo "$ rustup +nightly component add miri"
echo ""

echo "Run MIRI on tests:"
echo "$ cargo +nightly miri test"
echo ""

echo "Run MIRI on specific test:"
echo "$ cargo +nightly miri test --package zebra-network test_name"
echo ""

echo "Run with additional checks:"
echo "$ MIRIFLAGS='-Zmiri-symbolic-alignment-check' cargo +nightly miri test"
echo ""

# =============================================================================
# Section 7: Code Coverage
# =============================================================================

echo "## 7. CODE COVERAGE"
echo ""

echo "Install tarpaulin:"
echo "$ cargo install cargo-tarpaulin"
echo ""

echo "Run coverage:"
echo "$ cargo tarpaulin --out Html --output-dir coverage/"
echo ""

echo "Run coverage for specific crate:"
echo "$ cargo tarpaulin --package zebra-network --out Html"
echo ""

echo "Coverage with line-by-line output:"
echo "$ cargo tarpaulin --out Lcov --output-dir coverage/"
echo ""

# =============================================================================
# Section 8: Clippy and Linting
# =============================================================================

echo "## 8. CLIPPY AND LINTING"
echo ""

echo "Run clippy with all warnings:"
echo "$ cargo clippy --all-targets -- -D warnings"
echo ""

echo "Run clippy with pedantic:"
echo "$ cargo clippy --all-targets -- -W clippy::pedantic"
echo ""

echo "Run clippy with security-focused lints:"
echo "$ cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic"
echo ""

echo "Run clippy on all workspaces:"
echo "$ cargo clippy --workspace --all-targets -- -D warnings"
echo ""

# =============================================================================
# Section 9: Address Sanitizer
# =============================================================================

echo "## 9. ADDRESS SANITIZER (ASAN)"
echo ""

echo "Build with AddressSanitizer:"
echo "$ RUSTFLAGS='-Zsanitizer=address' cargo +nightly build --target x86_64-unknown-linux-gnu"
echo ""

echo "Run tests with AddressSanitizer:"
echo "$ RUSTFLAGS='-Zsanitizer=address' cargo +nightly test --target x86_64-unknown-linux-gnu"
echo ""

echo "Build with LeakSanitizer:"
echo "$ RUSTFLAGS='-Zsanitizer=leak' cargo +nightly test --target x86_64-unknown-linux-gnu"
echo ""

echo "Build with MemorySanitizer:"
echo "$ RUSTFLAGS='-Zsanitizer=memory' cargo +nightly build --target x86_64-unknown-linux-gnu"
echo ""

# =============================================================================
# Section 10: Property-Based Testing
# =============================================================================

echo "## 10. PROPERTY-BASED TESTING"
echo ""

echo "Run all property tests:"
echo "$ cargo test prop --package zebra-network"
echo ""

echo "Run with many iterations:"
echo "$ PROPTEST_CASES=10000 cargo test prop"
echo ""

echo "Run until failure:"
echo "$ PROPTEST_MAX_SHRINK_ITERS=100000 cargo test prop"
echo ""

# =============================================================================
# Section 11: Benchmarking and Performance
# =============================================================================

echo "## 11. BENCHMARKING"
echo ""

echo "Run benchmarks:"
echo "$ cargo bench"
echo ""

echo "Profile with perf:"
echo "$ cargo build --release"
echo "$ perf record --call-graph dwarf ./target/release/zebrad"
echo "$ perf report"
echo ""

echo "Profile with flamegraph:"
echo "$ cargo install flamegraph"
echo "$ cargo flamegraph"
echo ""

# =============================================================================
# Section 12: Static Analysis with Cargo Geiger
# =============================================================================

echo "## 12. UNSAFE CODE STATISTICS (CARGO-GEIGER)"
echo ""

echo "Install cargo-geiger:"
echo "$ cargo install cargo-geiger"
echo ""

echo "Scan for unsafe code:"
echo "$ cargo geiger"
echo ""

echo "Generate detailed report:"
echo "$ cargo geiger --output-format GitHubMarkdown > unsafe-report.md"
echo ""

# =============================================================================
# Section 13: Code Complexity Analysis
# =============================================================================

echo "## 13. COMPLEXITY ANALYSIS"
echo ""

echo "Install cargo-bloat (binary size):"
echo "$ cargo install cargo-bloat"
echo "$ cargo bloat --release"
echo ""

echo "Install tokei (line counts):"
echo "$ cargo install tokei"
echo "$ tokei"
echo ""

# =============================================================================
# Section 14: Specific Security Searches
# =============================================================================

echo "## 14. SPECIFIC SECURITY PATTERN SEARCHES"
echo ""

echo "Find all uses of TrustedPreallocate:"
echo "$ rg 'TrustedPreallocate' --type rust -A 5"
echo ""

echo "Find all uses of with_capacity:"
echo "$ rg 'with_capacity' --type rust zebra-network/ zebra-chain/"
echo ""

echo "Find all external_count deserialization:"
echo "$ rg 'zcash_deserialize_external_count' --type rust -A 3"
echo ""

echo "Find all CompactSize parsing:"
echo "$ rg 'CompactSizeMessage' --type rust"
echo ""

echo "Find all FFI boundaries:"
echo "$ rg 'extern \"C\"' --type rust"
echo ""

echo "Find all raw pointer usage:"
echo "$ rg '\*const|\*mut' --type rust"
echo ""

echo "Find all transmutes:"
echo "$ rg 'transmute' --type rust"
echo ""

echo "Find all as casts:"
echo "$ rg ' as ' --type rust zebra-network/src/ | head -50"
echo ""

# =============================================================================
# Section 15: Network-Specific Searches
# =============================================================================

echo "## 15. NETWORK PROTOCOL SEARCHES"
echo ""

echo "Find all message type handlers:"
echo "$ rg 'fn read_' --type rust zebra-network/src/protocol/external/codec.rs"
echo ""

echo "Find all message encoders:"
echo "$ rg 'Message::' --type rust zebra-network/src/protocol/external/codec.rs -A 2"
echo ""

echo "Find all MAX constants:"
echo "$ rg 'const MAX_' --type rust zebra-network/"
echo ""

echo "Find all length validations:"
echo "$ rg 'len\(\).*>' --type rust zebra-network/src/protocol/"
echo ""

# =============================================================================
# Section 16: Deserialization Analysis
# =============================================================================

echo "## 16. DESERIALIZATION ANALYSIS"
echo ""

echo "Find all ZcashDeserialize implementations:"
echo "$ rg 'impl.*ZcashDeserialize' --type rust -A 10"
echo ""

echo "Find all read_exact calls:"
echo "$ rg 'read_exact' --type rust zebra-chain/src/serialization/"
echo ""

echo "Find all Vec allocations in deserialization:"
echo "$ rg 'Vec::with_capacity|vec!\[' --type rust zebra-chain/src/serialization/"
echo ""

# =============================================================================
# Section 17: Error Handling Analysis
# =============================================================================

echo "## 17. ERROR HANDLING ANALYSIS"
echo ""

echo "Find all Result types:"
echo "$ rg 'Result<' --type rust zebra-network/src/protocol/ | head -20"
echo ""

echo "Find all error propagation:"
echo "$ rg '\?' --type rust zebra-network/src/protocol/external/codec.rs | wc -l"
echo ""

echo "Find all custom error types:"
echo "$ rg '#\[derive.*Error\]' --type rust -A 5"
echo ""

# =============================================================================
# Section 18: Integration Testing
# =============================================================================

echo "## 18. INTEGRATION TESTING"
echo ""

echo "Run all tests:"
echo "$ cargo test --workspace"
echo ""

echo "Run integration tests only:"
echo "$ cargo test --test '*'"
echo ""

echo "Run with nextest:"
echo "$ cargo install cargo-nextest"
echo "$ cargo nextest run"
echo ""

echo "Run long tests:"
echo "$ cargo test --release -- --ignored"
echo ""

# =============================================================================
# Section 19: Documentation
# =============================================================================

echo "## 19. DOCUMENTATION GENERATION"
echo ""

echo "Build documentation:"
echo "$ cargo doc --no-deps --open"
echo ""

echo "Build with all features:"
echo "$ cargo doc --all-features"
echo ""

echo "Check for missing docs:"
echo "$ RUSTDOCFLAGS='-D warnings' cargo doc"
echo ""

# =============================================================================
# Section 20: Advanced Analysis Commands
# =============================================================================

echo "## 20. ADVANCED ANALYSIS"
echo ""

echo "Generate call graph:"
echo "$ cargo install cargo-call-stack"
echo "$ cargo call-stack --bin zebrad > call-stack.dot"
echo "$ dot -Tpng call-stack.dot > call-stack.png"
echo ""

echo "Analyze binary size:"
echo "$ cargo bloat --release -n 50"
echo ""

echo "Check build times:"
echo "$ cargo clean"
echo "$ cargo build --timings"
echo ""

echo "Generate dependency tree:"
echo "$ cargo tree > deps.txt"
echo ""

echo "Check for duplicate dependencies:"
echo "$ cargo tree --duplicates"
echo ""

# =============================================================================
# Section 21: Continuous Monitoring
# =============================================================================

echo "## 21. CONTINUOUS MONITORING SETUP"
echo ""

echo "Add to CI/CD (.github/workflows/security.yml):"
cat << 'EOF'
name: Security Audit
on: [push, pull_request]
jobs:
  security_audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run cargo-audit
        run: |
          cargo install cargo-audit
          cargo audit
      - name: Run clippy
        run: cargo clippy --all-targets -- -D warnings
      - name: Run tests
        run: cargo test --workspace
EOF
echo ""

# =============================================================================
# Conclusion
# =============================================================================

echo "======================================================================"
echo "Investigation Complete"
echo "======================================================================"
echo ""
echo "Next steps:"
echo "1. Run panic audit commands and review all results"
echo "2. Set up continuous fuzzing infrastructure"
echo "3. Install and run Kani for formal verification"
echo "4. Run MIRI on all tests"
echo "5. Address all findings before production use"
echo ""
echo "For questions or to report security issues:"
echo "- See SECURITY.md in the repository"
echo "- Contact the Zebra security team privately"
echo ""

# End of script
