#!/bin/bash
# Generate fuzzing harnesses for all P2P network messages

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="${HARNESS_DIR}/../../../"

# P2P message types to fuzz
P2P_MESSAGES=(
    "version" "verack" "ping" "pong" "addr" "addrv2" "inv" "getdata"
    "getblocks" "getheaders" "tx" "block" "headers" "notfound" "reject"
    "filterload" "filteradd" "filterclear" "mempool" "sendheaders"
    "sendcmpct" "feefilter"
)

# Create Cargo.toml for fuzzing workspace
create_fuzz_cargo_toml() {
    cat > "${HARNESS_DIR}/Cargo.toml" << 'EOF'
[package]
name = "zebra-fuzz-harnesses"
version = "0.1.0"
edition = "2021"

[dependencies]
zebra-chain = { path = "../../../zebra-chain" }
zebra-network = { path = "../../../zebra-network" }
zebra-rpc = { path = "../../../zebra-rpc" }
zebra-script = { path = "../../../zebra-script" }
zebra-state = { path = "../../../zebra-state" }
libfuzzer-sys = "0.4"
arbitrary = { version = "1", features = ["derive"] }

[[bin]]
name = "fuzz_p2p_sequence"
path = "fuzz_p2p_sequence.rs"

EOF

    # Add bin entries for each message type
    for msg in "${P2P_MESSAGES[@]}"; do
        cat >> "${HARNESS_DIR}/Cargo.toml" << EOF
[[bin]]
name = "fuzz_p2p_${msg}"
path = "fuzz_p2p_${msg}.rs"

EOF
    done
}

echo "[INFO] Creating fuzzing harness Cargo.toml..."
create_fuzz_cargo_toml

echo "[INFO] Fuzzing harness structure created successfully!"
echo "[INFO] Harnesses are located in: ${HARNESS_DIR}"
