//! Fuzzing harness: Orchard proof deserialisation.
//!
//! Attack surface:
//! - Halo2 proof bytes (variable length, compact-size prefixed)
//! - Proof structure parsing (polynomial commitments, evaluations)
//! - Verifier key loading
//! - Proof verification (expensive — may cause timeouts)

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use zebra_chain::orchard::ShieldedData;
use zebra_chain::serialization::ZcashDeserialize;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct ShieldedData deserialisation (includes proof bytes).
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });

    // Crafted: 1 action + fuzzer bytes as Halo2 proof.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0x01); // 1 action
        // Action: 820 bytes of zeros.
        payload.extend_from_slice(&[0u8; 820]);
        payload.push(0x03); // flags
        payload.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
        payload.extend_from_slice(&[0u8; 32]); // anchor
        // Halo2 proof: compact-size + fuzzer bytes.
        let proof_len = data.len().min(65535);
        if proof_len < 253 {
            payload.push(proof_len as u8);
        } else {
            payload.push(0xfd);
            payload.extend_from_slice(&(proof_len as u16).to_le_bytes());
        }
        payload.extend_from_slice(&data[..proof_len]);
        // spendAuthSig + bindingSig.
        payload.extend_from_slice(&[0u8; 128]);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });

    // Crafted: empty proof (0 bytes).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0x01); // 1 action
        payload.extend_from_slice(&[0u8; 820]);
        payload.push(0x03);
        payload.extend_from_slice(&0i64.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]);
        payload.push(0x00); // proof len = 0
        payload.extend_from_slice(&[0u8; 128]);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });
});
