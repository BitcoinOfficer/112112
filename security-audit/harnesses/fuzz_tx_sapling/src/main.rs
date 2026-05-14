//! Fuzzing harness: Sapling spend/output deserialisation.
//!
//! Attack surface:
//! - cv (value commitment, 32 bytes)
//! - anchor (32 bytes)
//! - nullifier (32 bytes)
//! - rk (randomised verifying key, 32 bytes)
//! - zkproof (192 bytes — Groth16)
//! - spendAuthSig (64 bytes)
//! - encCiphertext (580 bytes)
//! - outCiphertext (80 bytes)
//! - ephemeralKey (32 bytes)
//! - cmu (32 bytes)

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging, roundtrip_check};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::sapling::{Spend, Output};
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Fuzz Sapling Spend.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Spend<sapling_crypto::bundle::PerSpendAnchor>>(data);
    });

    // Fuzz Sapling Output.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Output>(data);
    });

    // Crafted: Spend with all-zero fields (valid structure, invalid crypto).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 32]); // cv
        payload.extend_from_slice(&[0u8; 32]); // anchor
        payload.extend_from_slice(&[0u8; 32]); // nullifier
        payload.extend_from_slice(&[0u8; 32]); // rk
        payload.extend_from_slice(&[0u8; 192]); // zkproof
        payload.extend_from_slice(&[0u8; 64]); // spendAuthSig
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Spend::<sapling_crypto::bundle::PerSpendAnchor>::zcash_deserialize(&mut cursor);
    });

    // Crafted: Output with all-zero fields.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 32]); // cv
        payload.extend_from_slice(&[0u8; 32]); // cmu
        payload.extend_from_slice(&[0u8; 32]); // ephemeralKey
        payload.extend_from_slice(&[0u8; 580]); // encCiphertext
        payload.extend_from_slice(&[0u8; 80]); // outCiphertext
        payload.extend_from_slice(&[0u8; 192]); // zkproof
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Output::zcash_deserialize(&mut cursor);
    });

    // Crafted: Spend with fuzzer bytes in the proof field.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 32]); // cv
        payload.extend_from_slice(&[0u8; 32]); // anchor
        payload.extend_from_slice(&[0u8; 32]); // nullifier
        payload.extend_from_slice(&[0u8; 32]); // rk
        // zkproof: splice fuzzer bytes.
        let proof_len = data.len().min(192);
        payload.extend_from_slice(&data[..proof_len]);
        payload.extend(std::iter::repeat(0u8).take(192 - proof_len));
        payload.extend_from_slice(&[0u8; 64]); // spendAuthSig
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Spend::<sapling_crypto::bundle::PerSpendAnchor>::zcash_deserialize(&mut cursor);
    });
});
