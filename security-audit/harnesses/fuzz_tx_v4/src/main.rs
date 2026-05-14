//! Fuzzing harness: Zcash v4 transaction deserialisation.
//!
//! v4 transactions include:
//! - Transparent inputs/outputs
//! - JoinSplit descriptions (Sprout)
//! - Sapling spends and outputs
//! - Binding signature
//!
//! Attack surface:
//! - Compact-size counts for each section
//! - Proof bytes (192 bytes per Sapling spend/output)
//! - JoinSplit data (1698 bytes each)
//! - Value commitments and nullifiers

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging, roundtrip_check};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transaction::Transaction;
use zebra_chain::serialization::ZcashDeserialize;

/// Build a minimal v4 transaction skeleton.
fn minimal_v4_tx() -> Vec<u8> {
    let mut v = Vec::new();
    // header: version=4 | fOverwintered=1 → 0x80000004
    v.write_u32::<LittleEndian>(0x8000_0004).unwrap();
    // nVersionGroupId = 0x892F2085 (Sapling)
    v.write_u32::<LittleEndian>(0x892F_2085).unwrap();
    // vin count = 0
    v.push(0x00);
    // vout count = 0
    v.push(0x00);
    // nLockTime = 0
    v.write_u32::<LittleEndian>(0).unwrap();
    // nExpiryHeight = 0
    v.write_u32::<LittleEndian>(0).unwrap();
    // valueBalance = 0
    v.write_i64::<LittleEndian>(0).unwrap();
    // vShieldedSpend count = 0
    v.push(0x00);
    // vShieldedOutput count = 0
    v.push(0x00);
    // vJoinSplit count = 0
    v.push(0x00);
    // bindingSig (64 bytes of zeros)
    v.extend_from_slice(&[0u8; 64]);
    v
}

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct deserialisation with round-trip check.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Transaction>(data);
    });

    // Splice fuzzer bytes into a valid v4 skeleton.
    let _ = catch_panic(|| {
        let mut tx = minimal_v4_tx();
        let splice_at = tx.len().saturating_sub(64); // before bindingSig
        if !data.is_empty() {
            let splice_len = data.len().min(64);
            tx[splice_at..splice_at + splice_len]
                .copy_from_slice(&data[..splice_len]);
        }
        let mut cursor = Cursor::new(tx.as_slice());
        let _ = Transaction::zcash_deserialize(&mut cursor);
    });

    // Crafted: v4 with 1000 Sapling spends (OOM probe).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_u32::<LittleEndian>(0x8000_0004).unwrap();
        payload.write_u32::<LittleEndian>(0x892F_2085).unwrap();
        payload.push(0x00); // vin
        payload.push(0x00); // vout
        payload.write_u32::<LittleEndian>(0).unwrap(); // locktime
        payload.write_u32::<LittleEndian>(0).unwrap(); // expiry
        payload.write_i64::<LittleEndian>(0).unwrap(); // valueBalance
        // vShieldedSpend count = 1000
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(1000).unwrap();
        // Only 1 spend worth of data (truncated).
        payload.extend_from_slice(&[0u8; 384]); // cv(32)+anchor(32)+nullifier(32)+rk(32)+proof(192)+spendAuthSig(64)
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Transaction::zcash_deserialize(&mut cursor);
    });
});
