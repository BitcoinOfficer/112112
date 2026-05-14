//! Fuzzing harness: Zcash v5 transaction deserialisation.
//!
//! v5 transactions (NU5+) include:
//! - Transparent inputs/outputs
//! - Sapling spends/outputs (no JoinSplits)
//! - Orchard action bundles with Halo2 proofs
//!
//! Attack surface:
//! - Orchard action count (compact-size) → large Halo2 proof allocation
//! - enableSpendsOrchard / enableOutputsOrchard flags
//! - Orchard binding signature (64 bytes)
//! - Halo2 proof bytes (variable length)

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging, roundtrip_check};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transaction::Transaction;
use zebra_chain::serialization::ZcashDeserialize;

/// Build a minimal v5 transaction skeleton.
fn minimal_v5_tx() -> Vec<u8> {
    let mut v = Vec::new();
    // header: version=5 | fOverwintered=1 → 0x80000005
    v.write_u32::<LittleEndian>(0x8000_0005).unwrap();
    // nVersionGroupId = 0x26A7270A (NU5)
    v.write_u32::<LittleEndian>(0x26A7_270A).unwrap();
    // nConsensusBranchId = 0xC2D6D0B4 (NU5 mainnet)
    v.write_u32::<LittleEndian>(0xC2D6_D0B4).unwrap();
    // nLockTime = 0
    v.write_u32::<LittleEndian>(0).unwrap();
    // nExpiryHeight = 0
    v.write_u32::<LittleEndian>(0).unwrap();
    // vin count = 0
    v.push(0x00);
    // vout count = 0
    v.push(0x00);
    // vSpendsSapling count = 0
    v.push(0x00);
    // vOutputsSapling count = 0
    v.push(0x00);
    // valueBalanceSapling = 0
    v.write_i64::<LittleEndian>(0).unwrap();
    // Orchard: nActionsOrchard = 0
    v.push(0x00);
    v
}

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct deserialisation with round-trip check.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Transaction>(data);
    });

    // Splice fuzzer bytes into a valid v5 skeleton.
    let _ = catch_panic(|| {
        let mut tx = minimal_v5_tx();
        if !data.is_empty() {
            tx.extend_from_slice(data);
        }
        let mut cursor = Cursor::new(tx.as_slice());
        let _ = Transaction::zcash_deserialize(&mut cursor);
    });

    // Crafted: v5 with 1000 Orchard actions (OOM probe).
    let _ = catch_panic(|| {
        let mut payload = minimal_v5_tx();
        // Replace the trailing 0x00 (nActionsOrchard) with 1000.
        let last = payload.len() - 1;
        payload[last] = 0xfd;
        payload.write_u16::<LittleEndian>(1000).unwrap();
        // One action worth of data (truncated).
        // Each Orchard action: cv(32)+nullifier(32)+rk(32)+cmx(32)+ephemeralKey(32)+encCiphertext(580)+outCiphertext(80)
        payload.extend_from_slice(&[0u8; 820]);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Transaction::zcash_deserialize(&mut cursor);
    });

    // Crafted: v5 with flags byte = 0xff (all flags set).
    let _ = catch_panic(|| {
        let mut payload = minimal_v5_tx();
        let last = payload.len() - 1;
        payload[last] = 0x01; // 1 action
        // flags byte
        payload.push(0xff);
        // action data (truncated)
        payload.extend_from_slice(&[0u8; 100]);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Transaction::zcash_deserialize(&mut cursor);
    });
});
