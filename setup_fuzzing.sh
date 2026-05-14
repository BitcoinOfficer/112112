#!/bin/bash
# Zebra Security Fuzzing Infrastructure Setup
# Usage: ./setup_fuzzing.sh

set -e

echo "=================================================="
echo "Zebra Security Fuzzing Infrastructure Setup"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Must be run from Zebra repository root"
    exit 1
fi

# Install required tools
echo ""
echo "📦 Installing fuzzing tools..."
rustup install nightly
cargo +nightly install cargo-fuzz --force || true

# Initialize fuzz directory if it doesn't exist
if [ ! -d "fuzz" ]; then
    echo ""
    echo "🔧 Initializing cargo-fuzz..."
    cargo +nightly fuzz init
fi

# Create fuzz target directory
mkdir -p fuzz/fuzz_targets

echo ""
echo "📝 Creating fuzz targets..."

# ============================================================================
# FUZZ TARGET 1: Network Codec (CRITICAL)
# ============================================================================
cat > fuzz/fuzz_targets/network_codec.rs << 'FUZZEOF'
#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::BytesMut;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    // Test network message decoder with arbitrary input
    let mut buf = BytesMut::from(data);
    
    let mut codec = zebra_network::protocol::external::Codec::builder()
        .for_network(&zebra_chain::parameters::Network::Mainnet)
        .finish();
    
    // Should never panic, only return Ok(None) or Err
    let _ = codec.decode(&mut buf);
    
    // Test with Testnet as well
    let mut codec_testnet = zebra_network::protocol::external::Codec::builder()
        .for_network(&zebra_chain::parameters::Network::Testnet)
        .finish();
    
    let mut buf2 = BytesMut::from(data);
    let _ = codec_testnet.decode(&mut buf2);
});
FUZZEOF

# ============================================================================
# FUZZ TARGET 2: Cryptographic Deserialization (CRITICAL)
# ============================================================================
cat > fuzz/fuzz_targets/crypto_deser.rs << 'FUZZEOF'
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only test with 32-byte inputs (valid length for points)
    if data.len() != 32 {
        return;
    }
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(data);
    
    // Test JubJub point deserialization
    let _ = jubjub::AffinePoint::from_bytes(bytes);
    let _ = jubjub::Fq::from_bytes(&bytes);
    
    // Test Pallas point deserialization
    use group::{ff::PrimeField, GroupEncoding};
    let _ = halo2::pasta::pallas::Affine::from_bytes(&bytes);
    let _ = halo2::pasta::pallas::Base::from_repr(bytes);
    let _ = halo2::pasta::pallas::Scalar::from_repr(bytes);
    
    // These should never panic - they return Option<T>
});
FUZZEOF

# ============================================================================
# FUZZ TARGET 3: Transaction Deserialization (HIGH)
# ============================================================================
cat > fuzz/fuzz_targets/transaction_deser.rs << 'FUZZEOF'
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    let reader = Cursor::new(data);
    
    // Try to deserialize as transaction
    // Should handle malformed data gracefully
    let _ = zebra_chain::transaction::Transaction::zcash_deserialize(reader);
});
FUZZEOF

# ============================================================================
# FUZZ TARGET 4: Block Deserialization (HIGH)
# ============================================================================
cat > fuzz/fuzz_targets/block_deser.rs << 'FUZZEOF'
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    let reader = Cursor::new(data);
    
    // Try to deserialize as block
    let _ = zebra_chain::block::Block::zcash_deserialize(reader);
});
FUZZEOF

# ============================================================================
# FUZZ TARGET 5: Script Verification (MEDIUM)
# ============================================================================
cat > fuzz/fuzz_targets/script_verify.rs << 'FUZZEOF'
#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the script verification logic
fuzz_target!(|data: &[u8]| {
    // Split input into script_pub_key and script_sig
    if data.len() < 2 {
        return;
    }
    
    let split_point = (data[0] as usize) % data.len();
    let script_pub_key = &data[1..split_point.min(data.len())];
    let script_sig = &data[split_point.min(data.len())..];
    
    // Create a minimal transaction for testing
    // This is simplified - in production, use proper transaction construction
    // The goal is to fuzz the script parsing/verification without panicking
    
    // TODO: Implement proper transaction fuzzing
    // For now, just test that arbitrary script bytes don't cause panics
});
FUZZEOF

# ============================================================================
# FUZZ TARGET 6: Address Deserialization (MEDIUM)
# ============================================================================
cat > fuzz/fuzz_targets/address_deser.rs << 'FUZZEOF'
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Fuzz various address formats
    let reader = Cursor::new(data);
    
    use zebra_chain::serialization::ZcashDeserialize;
    
    // Try to parse as AddrV1
    let _ = zebra_network::protocol::external::addr::AddrV1::zcash_deserialize(reader.clone());
    
    // Try to parse as AddrV2
    let _ = zebra_network::protocol::external::addr::AddrV2::zcash_deserialize(reader);
});
FUZZEOF

echo "✅ Fuzz targets created"

# Create fuzzing runner script
cat > run_fuzzing.sh << 'RUNEOF'
#!/bin/bash
# Run all fuzz targets with appropriate settings

set -e

FUZZ_TIME=${FUZZ_TIME:-300}  # 5 minutes default, override with env var
JOBS=${JOBS:-$(nproc)}

echo "Running fuzzing campaign..."
echo "Duration per target: ${FUZZ_TIME} seconds"
echo "Parallel jobs: ${JOBS}"

# Run each target
TARGETS=(
    "network_codec"
    "crypto_deser"
    "transaction_deser"
    "block_deser"
    "address_deser"
)

for target in "${TARGETS[@]}"; do
    echo ""
    echo "=================================================="
    echo "Fuzzing: $target"
    echo "=================================================="
    
    cargo +nightly fuzz run "$target" \
        --release \
        --jobs "$JOBS" \
        -- \
        -max_total_time="$FUZZ_TIME" \
        -print_final_stats=1 \
        -print_corpus_stats=1 \
        -print_coverage=1 \
        || echo "⚠️  Target $target found issues or crashed"
done

echo ""
echo "✅ Fuzzing campaign complete!"
echo "Check fuzz/artifacts/ for any crashes"
RUNEOF

chmod +x run_fuzzing.sh

# Create coverage analysis script
cat > analyze_coverage.sh << 'COVEOF'
#!/bin/bash
# Analyze fuzzing coverage

set -e

echo "Analyzing fuzzing coverage..."

for target in fuzz/fuzz_targets/*.rs; do
    target_name=$(basename "$target" .rs)
    echo ""
    echo "Coverage for: $target_name"
    
    cargo +nightly fuzz coverage "$target_name" || true
    
    # Generate HTML report if llvm-cov is available
    if command -v llvm-cov &> /dev/null; then
        echo "Generating HTML coverage report..."
        
        # This would need the correct paths - adjust based on actual build output
        # llvm-cov show target/x86_64-unknown-linux-gnu/release/$target_name \
        #     -format=html \
        #     > "coverage_${target_name}.html"
    fi
done

echo "✅ Coverage analysis complete"
COVEOF

chmod +x analyze_coverage.sh

# Create continuous fuzzing script
cat > continuous_fuzz.sh << 'CONTEOF'
#!/bin/bash
# Run continuous fuzzing until stopped

set -e

echo "Starting continuous fuzzing..."
echo "Press Ctrl+C to stop"

while true; do
    echo ""
    echo "=========================================="
    echo "Fuzzing cycle started: $(date)"
    echo "=========================================="
    
    FUZZ_TIME=3600 ./run_fuzzing.sh  # 1 hour per cycle
    
    echo ""
    echo "Cycle complete. Checking for crashes..."
    if [ -d "fuzz/artifacts" ] && [ "$(ls -A fuzz/artifacts)" ]; then
        echo "⚠️  CRASHES FOUND! Check fuzz/artifacts/"
        echo "Continuing fuzzing to find more issues..."
    else
        echo "✅ No crashes in this cycle"
    fi
    
    sleep 60  # 1 minute break between cycles
done
CONTEOF

chmod +x continuous_fuzz.sh

# Create Dockerfile for fuzzing environment
cat > Dockerfile.fuzzing << 'DOCKERFILE'
FROM rust:latest

# Install fuzzing dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# Install nightly and cargo-fuzz
RUN rustup install nightly
RUN cargo +nightly install cargo-fuzz

WORKDIR /zebra

# Copy project
COPY . .

# Build fuzz targets
RUN cargo +nightly fuzz build

CMD ["./continuous_fuzz.sh"]
DOCKERFILE

echo ""
echo "✅ Setup complete!"
echo ""
echo "=================================================="
echo "Next Steps:"
echo "=================================================="
echo ""
echo "1. Quick test (5 minutes per target):"
echo "   ./run_fuzzing.sh"
echo ""
echo "2. Extended fuzzing (1 hour per target):"
echo "   FUZZ_TIME=3600 ./run_fuzzing.sh"
echo ""
echo "3. Continuous fuzzing (until stopped):"
echo "   ./continuous_fuzz.sh"
echo ""
echo "4. Run in Docker (isolated):"
echo "   docker build -f Dockerfile.fuzzing -t zebra-fuzz ."
echo "   docker run zebra-fuzz"
echo ""
echo "5. Analyze coverage:"
echo "   ./analyze_coverage.sh"
echo ""
echo "=================================================="
echo "Fuzzing Targets Created:"
echo "=================================================="
echo "  - network_codec: Network message parsing"
echo "  - crypto_deser: Cryptographic point deserialization"
echo "  - transaction_deser: Transaction parsing"
echo "  - block_deser: Block parsing"
echo "  - address_deser: Network address parsing"
echo ""
echo "Check fuzz/artifacts/ for any crashes found"
echo ""
