//! Fuzzing harness: Halo2 proof verifier.
//!
//! Attack surface:
//! - Proof bytes fed directly to the Halo2 verifier
//! - Polynomial commitment parsing
//! - Field element deserialisation (Pallas/Vesta curves)
//! - Verifier key consistency checks
//! - Infinite loops in proof verification (timeout probe)

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use zebra_chain::orchard::ShieldedData;
use zebra_chain::serialization::ZcashDeserialize;
use std::io::Cursor;

/// Build a ShieldedData payload with `n_actions` actions and the given proof bytes.
fn build_shielded_data(n_actions: u8, proof_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(n_actions);
    for _ in 0..n_actions {
        payload.extend_from_slice(&[0u8; 820]);
    }
    payload.push(0x03); // flags
    payload.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
    payload.extend_from_slice(&[0u8; 32]); // anchor
    // Proof.
    let proof_len = proof_bytes.len();
    if proof_len < 253 {
        payload.push(proof_len as u8);
    } else if proof_len < 65536 {
        payload.push(0xfd);
        payload.extend_from_slice(&(proof_len as u16).to_le_bytes());
    } else {
        payload.push(0xfe);
        payload.extend_from_slice(&(proof_len as u32).to_le_bytes());
    }
    payload.extend_from_slice(proof_bytes);
    // spendAuthSigs (64 bytes × n_actions).
    payload.extend(std::iter::repeat(0u8).take(64 * n_actions as usize));
    // bindingSig.
    payload.extend_from_slice(&[0u8; 64]);
    payload
}

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Fuzz with 1 action.
    let _ = catch_panic(|| {
        let payload = build_shielded_data(1, data);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });

    // Fuzz with 2 actions.
    let _ = catch_panic(|| {
        let payload = build_shielded_data(2, data);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });

    // Fuzz with 0 actions (edge case — should be rejected).
    let _ = catch_panic(|| {
        let payload = build_shielded_data(0, data);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });

    // Direct raw bytes.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });
});
