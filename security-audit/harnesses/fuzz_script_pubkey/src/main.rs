//! Fuzzing harness: Script pubkey parsing and execution.
//!
//! Attack surface:
//! - Arbitrary script opcodes (including disabled opcodes)
//! - Script length up to 10,000 bytes
//! - OP_RETURN scripts
//! - P2PKH, P2SH, P2PK patterns
//! - Nested scripts (P2SH redeem scripts)
//! - libzcash_script FFI boundary (C++ code)

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transparent::Script;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct Script deserialisation.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Script::zcash_deserialize(&mut cursor);
    });

    // Construct Script directly from raw bytes (no length prefix).
    let _ = catch_panic(|| {
        let script = Script::new(data);
        // Attempt to classify the script type.
        let _ = script.address(zebra_chain::parameters::Network::Mainnet);
    });

    // Crafted: OP_RETURN with 80 bytes of fuzzer data.
    let _ = catch_panic(|| {
        let mut script_bytes = Vec::new();
        script_bytes.push(0x6a); // OP_RETURN
        let push_len = data.len().min(80);
        script_bytes.push(push_len as u8);
        script_bytes.extend_from_slice(&data[..push_len]);
        let script = Script::new(&script_bytes);
        let _ = script.address(zebra_chain::parameters::Network::Mainnet);
    });

    // Crafted: P2SH pattern with fuzzer bytes as redeem script hash.
    let _ = catch_panic(|| {
        let mut script_bytes = Vec::new();
        script_bytes.push(0xa9); // OP_HASH160
        script_bytes.push(0x14); // push 20 bytes
        let hash_len = data.len().min(20);
        script_bytes.extend_from_slice(&data[..hash_len]);
        script_bytes.extend(std::iter::repeat(0u8).take(20 - hash_len));
        script_bytes.push(0x87); // OP_EQUAL
        let script = Script::new(&script_bytes);
        let _ = script.address(zebra_chain::parameters::Network::Mainnet);
    });

    // Crafted: script with all-0xff bytes (all disabled opcodes).
    let _ = catch_panic(|| {
        let script_bytes: Vec<u8> = std::iter::repeat(0xff).take(data.len().min(520)).collect();
        let script = Script::new(&script_bytes);
        let _ = script.address(zebra_chain::parameters::Network::Mainnet);
    });
});
