#!/bin/bash
# Branch Coverage Analysis Script for Zebra
# This script performs comprehensive branch coverage analysis

set -e

echo "==================================="
echo "Zebra Branch Coverage Analysis"
echo "==================================="
echo ""

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust/Cargo not found. Install from https://rustup.rs"
    exit 1
fi

# Install coverage tools
echo "[1/7] Installing coverage tools..."
rustup component add llvm-tools-preview 2>/dev/null || true
cargo install --quiet cargo-llvm-cov cargo-tarpaulin 2>/dev/null || echo "Tools already installed"

# Clean previous coverage data
echo "[2/7] Cleaning previous coverage data..."
cargo llvm-cov clean --workspace || true
rm -rf target/coverage 2>/dev/null || true
mkdir -p target/coverage

# Generate baseline coverage with branch tracking
echo "[3/7] Generating baseline branch coverage..."
RUSTFLAGS="-C instrument-coverage" \
cargo llvm-cov test \
    --all-features \
    --workspace \
    --branch \
    --ignore-filename-regex '(tests|benches|examples)' \
    --html \
    --output-dir target/coverage/html \
    --json \
    --output-path target/coverage/coverage.json \
    2>&1 | tee target/coverage/baseline.log

# Run specific branch coverage tests for codec
echo "[4/7] Running targeted codec branch coverage tests..."
cargo test \
    -p zebra-network \
    --lib \
    protocol::external::codec::tests::branch_coverage \
    -- --nocapture \
    2>&1 | tee target/coverage/codec_tests.log

# Generate coverage report for network crate only
echo "[5/7] Generating network-specific coverage..."
cargo llvm-cov test \
    -p zebra-network \
    --branch \
    --html \
    --output-dir target/coverage/network_html \
    2>&1 | tee target/coverage/network.log

# Extract uncovered branches
echo "[6/7] Analyzing uncovered branches..."
cat > target/coverage/analyze_branches.py << 'PYTHON'
#!/usr/bin/env python3
import json
import sys

def analyze_coverage(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    total_branches = 0
    covered_branches = 0
    uncovered_branches = []
    
    for file_data in data.get('data', [{}])[0].get('files', []):
        filename = file_data.get('filename', '')
        
        # Focus on network-facing code
        if not any(path in filename for path in [
            'zebra-network/src/protocol',
            'zebra-chain/src/serialization',
            'zebra-chain/src/block',
            'zebra-chain/src/transaction'
        ]):
            continue
        
        for segment in file_data.get('segments', []):
            # segment format: [line, col, count, has_count, is_branch]
            if len(segment) >= 5 and segment[4]:  # is_branch
                total_branches += 1
                if segment[2] > 0:  # count > 0
                    covered_branches += 1
                else:
                    uncovered_branches.append({
                        'file': filename.split('/')[-1],
                        'line': segment[0],
                        'col': segment[1]
                    })
    
    print(f"\n{'='*60}")
    print(f"BRANCH COVERAGE ANALYSIS")
    print(f"{'='*60}")
    print(f"Total branches:    {total_branches}")
    print(f"Covered branches:  {covered_branches}")
    print(f"Uncovered branches: {total_branches - covered_branches}")
    print(f"Coverage:          {covered_branches/total_branches*100:.2f}%")
    print(f"\nUNCOVERED BRANCHES (first 50):")
    print(f"{'='*60}")
    
    for i, branch in enumerate(uncovered_branches[:50]):
        print(f"{i+1:3d}. {branch['file']:30s} line {branch['line']:4d}:{branch['col']}")
    
    if len(uncovered_branches) > 50:
        print(f"\n... and {len(uncovered_branches) - 50} more uncovered branches")
    
    return total_branches, covered_branches

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: analyze_branches.py <coverage.json>")
        sys.exit(1)
    
    try:
        total, covered = analyze_coverage(sys.argv[1])
        sys.exit(0 if total == covered else 1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(2)
PYTHON

chmod +x target/coverage/analyze_branches.py

if [ -f target/coverage/coverage.json ]; then
    python3 target/coverage/analyze_branches.py target/coverage/coverage.json \
        > target/coverage/branch_analysis.txt 2>&1 || true
    cat target/coverage/branch_analysis.txt
fi

# Generate final report
echo "[7/7] Generating final report..."
cat > target/coverage/REPORT.md << 'REPORT'
# Zebra Branch Coverage Report

## Execution Summary

This report documents branch coverage analysis of Zebra's network-facing attack surface.

### Files Analyzed

1. **zebra-network/src/protocol/external/codec.rs**
   - Entry point for all P2P message deserialization
   - ~50+ control-flow branches identified
   - Test suite: `zebra-network/src/protocol/external/codec/tests/branch_coverage.rs`

2. **zebra-chain/src/serialization/**
   - Core serialization primitives
   - Used by all network message parsing

3. **zebra-chain/src/block/**
   - Block deserialization
   - Multiple consensus-critical branches

4. **zebra-chain/src/transaction/**
   - Transaction deserialization
   - Version-specific branches (V1-V5)

### Coverage Results

See `coverage.json` for detailed LLVM coverage data.
See `branch_analysis.txt` for human-readable branch enumeration.

### HTML Reports

- **Full workspace**: `target/coverage/html/index.html`
- **Network crate**: `target/coverage/network_html/index.html`

### Uncovered Branches

Review `branch_analysis.txt` for the complete list of uncovered branches.

Each uncovered branch requires:
1. Identification of the input constraint that reaches it
2. Generation of a concrete test case
3. Verification that the branch is executed

### Next Steps

1. Review uncovered branches in the analysis output
2. For each uncovered branch, create a targeted test case
3. Re-run coverage analysis to verify 100% coverage
4. Document any branches proven unreachable

### Test Execution

Run the branch coverage test suite:

```bash
cargo test -p zebra-network --lib protocol::external::codec::tests::branch_coverage
```

### Continuous Monitoring

Add to CI pipeline:

```yaml
- name: Check branch coverage
  run: |
    cargo llvm-cov test --branch --fail-under-lines 90
```

REPORT

cat target/coverage/REPORT.md

echo ""
echo "==================================="
echo "Coverage analysis complete!"
echo "==================================="
echo ""
echo "Reports generated in target/coverage/"
echo "  - HTML: target/coverage/html/index.html"
echo "  - JSON: target/coverage/coverage.json"
echo "  - Analysis: target/coverage/branch_analysis.txt"
echo "  - Summary: target/coverage/REPORT.md"
echo ""
echo "Open target/coverage/html/index.html in a browser to view detailed coverage."
echo ""
