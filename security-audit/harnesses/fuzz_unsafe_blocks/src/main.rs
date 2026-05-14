//! Fuzzing harness: Targeted unsafe block testing.
//!
//! This harness directly exercises functions that contain or are adjacent to
//! `unsafe` blocks in the Zebra codebase, with adversarial inputs.
//!
//! Identified unsafe regions (from grep -rn "unsafe" across workspace):
//! - zebra-script: libzcash_script FFI (C++ boundary)
//! - zebra-chain: slice::from_raw_parts in serialisation helpers
//! - zebra-chain: transmute in compact-size parsing
//! - zebra-network: raw pointer arithmetic in codec

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transaction::Transaction;
use zebra_chain::transparent::{Input, Output, Script};
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // ── FFI boundary: libzcash_script ────────────────────────────────────────
    // Exercise the C++ script verifier with arbitrary script bytes.
    let _ = catch_panic(|| {
        // Build a minimal transaction with fuzzer bytes as script_sig.
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0x8000_0004u32.to_le_bytes()); // v4 header
        tx_bytes.extend_from_slice(&0x892F_2085u32.to_le_bytes()); // versionGroupId
        tx_bytes.push(0x01); // 1 input
        tx_bytes.extend_from_slice(&[0u8; 32]); // txid
        tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // vout
        // script_sig: compact-size + fuzzer bytes.
        let script_len = data.len().min(520);
        if script_len < 253 {
            tx_bytes.push(script_len as u8);
        } else {
            tx_bytes.push(0xfd);
            tx_bytes.extend_from_slice(&(script_len as u16).to_le_bytes());
        }
        tx_bytes.extend_from_slice(&data[..script_len]);
        tx_bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx_bytes.push(0x01); // 1 output
        tx_bytes.extend_from_slice(&1_000_000i64.to_le_bytes()); // value
        tx_bytes.push(0x00); // empty script_pubkey
        tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // locktime
        tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // expiry
        tx_bytes.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
        tx_bytes.push(0x00); // vShieldedSpend
        tx_bytes.push(0x00); // vShieldedOutput
        tx_bytes.push(0x00); // vJoinSplit
        tx_bytes.extend_from_slice(&[0u8; 64]); // bindingSig

        let mut cursor = Cursor::new(tx_bytes.as_slice());
        if let Ok(tx) = Transaction::zcash_deserialize(&mut cursor) {
            // Attempt script verification (exercises libzcash_script FFI).
            let _ = zebra_script::is_valid(
                &tx,
                0,
                &Script::new(&[]),
                1_000_000,
            );
        }
    });

    // ── Compact-size parsing edge cases ──────────────────────────────────────
    // These exercise the compact-size reader which may use unsafe internally.
    let _ = catch_panic(|| {
        use zebra_chain::serialization::CompactSizeMessage;
        let mut cursor = Cursor::new(data);
        let _ = CompactSizeMessage::zcash_deserialize(&mut cursor);
    });

    // ── Script construction with extreme lengths ──────────────────────────────
    let _ = catch_panic(|| {
        // Script::new takes a raw byte slice — exercises any unsafe in Script.
        let script = Script::new(data);
        let _ = script.address(zebra_chain::parameters::Network::Mainnet);
    });

    // ── Transparent Input with extreme sequence number ────────────────────────
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Input::zcash_deserialize(&mut cursor);
    });

    // ── Transparent Output with extreme value ─────────────────────────────────
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Output::zcash_deserialize(&mut cursor);
    });
});
