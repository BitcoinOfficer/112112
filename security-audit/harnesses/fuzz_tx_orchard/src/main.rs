//! Fuzzing harness: Orchard action bundle deserialisation.
//!
//! Attack surface:
//! - Action count (compact-size) → large Halo2 proof allocation
//! - Per-action: cv(32) + nullifier(32) + rk(32) + cmx(32) +
//!               ephemeralKey(32) + encCiphertext(580) + outCiphertext(80)
//! - flags byte (enableSpendsOrchard | enableOutputsOrchard)
//! - valueBalanceOrchard (i64)
//! - anchor (32 bytes)
//! - Halo2 proof (variable length, compact-size prefixed)
//! - spendAuthSigs (64 bytes × action_count)
//! - bindingSigOrchard (64 bytes)

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging, roundtrip_check};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::orchard::ShieldedData;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct Orchard ShieldedData deserialisation.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<ShieldedData>(data);
    });

    // Crafted: 1 action, flags=0x03, zero proof.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0x01); // nActionsOrchard = 1
        // Action data (820 bytes).
        payload.extend_from_slice(&[0u8; 32]); // cv
        payload.extend_from_slice(&[0u8; 32]); // nullifier
        payload.extend_from_slice(&[0u8; 32]); // rk
        payload.extend_from_slice(&[0u8; 32]); // cmx
        payload.extend_from_slice(&[0u8; 32]); // ephemeralKey
        payload.extend_from_slice(&[0u8; 580]); // encCiphertext
        payload.extend_from_slice(&[0u8; 80]); // outCiphertext
        payload.push(0x03); // flags
        payload.write_i64::<LittleEndian>(0).unwrap(); // valueBalance
        payload.extend_from_slice(&[0u8; 32]); // anchor
        // Halo2 proof: compact-size 0 (empty proof).
        payload.push(0x00);
        // spendAuthSig (64 bytes).
        payload.extend_from_slice(&[0u8; 64]);
        // bindingSig (64 bytes).
        payload.extend_from_slice(&[0u8; 64]);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });

    // Crafted: 1000 actions (OOM probe).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(1000).unwrap();
        // Only 1 action worth of data (truncated).
        payload.extend_from_slice(&[0u8; 820]);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });

    // Crafted: 1 action with fuzzer bytes in proof field.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0x01); // 1 action
        payload.extend_from_slice(&[0u8; 820]); // action
        payload.push(0x03); // flags
        payload.write_i64::<LittleEndian>(0).unwrap();
        payload.extend_from_slice(&[0u8; 32]); // anchor
        // Halo2 proof: fuzzer bytes.
        let proof_len = data.len().min(10_000);
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(proof_len as u16).unwrap();
        payload.extend_from_slice(&data[..proof_len]);
        payload.extend_from_slice(&[0u8; 64]); // spendAuthSig
        payload.extend_from_slice(&[0u8; 64]); // bindingSig
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = ShieldedData::zcash_deserialize(&mut cursor);
    });
});
