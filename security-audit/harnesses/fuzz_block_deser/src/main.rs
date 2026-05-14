//! Fuzzing harness: Full block deserialisation.
//!
//! Attack surface:
//! - Block header (version, prev_hash, merkle_root, final_sapling_root,
//!   time, bits, nonce, equihash_solution)
//! - Transaction count (compact-size)
//! - All transactions (v4 and v5)
//! - Merkle tree construction from transaction hashes

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging, roundtrip_check};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::block::Block;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct block deserialisation with round-trip check.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Block>(data);
    });

    // Crafted: valid header + 0 transactions.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_i32::<LittleEndian>(4).unwrap(); // version
        payload.extend_from_slice(&[0u8; 32]); // prev_hash
        payload.extend_from_slice(&[0u8; 32]); // merkle_root
        payload.extend_from_slice(&[0u8; 32]); // final_sapling_root
        payload.write_u32::<LittleEndian>(1_700_000_000).unwrap(); // time
        payload.write_u32::<LittleEndian>(0x1f07ffff).unwrap(); // bits
        payload.extend_from_slice(&[0u8; 32]); // nonce
        // Equihash solution: compact-size 1344 bytes.
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(1344).unwrap();
        payload.extend_from_slice(&[0u8; 1344]);
        // tx_count = 0
        payload.push(0x00);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Block::zcash_deserialize(&mut cursor);
    });

    // Crafted: valid header + fuzzer bytes as transactions.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_i32::<LittleEndian>(4).unwrap();
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0u8; 32]);
        payload.write_u32::<LittleEndian>(1_700_000_000).unwrap();
        payload.write_u32::<LittleEndian>(0x1f07ffff).unwrap();
        payload.extend_from_slice(&[0u8; 32]);
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(1344).unwrap();
        payload.extend_from_slice(&[0u8; 1344]);
        // tx_count = 1, then fuzzer bytes as the transaction.
        payload.push(0x01);
        payload.extend_from_slice(data);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Block::zcash_deserialize(&mut cursor);
    });
});
