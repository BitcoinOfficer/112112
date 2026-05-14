//! Fuzzing harness: P2P `block` message deserialisation.
//!
//! Attack surface:
//! - Block header (version, prev_hash, merkle_root, time, bits, nonce, solution)
//! - Equihash solution bytes (200 bytes for Zcash mainnet)
//! - Transaction count (compact-size) + all transactions
//! - Extremely large transaction counts → OOM

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging, roundtrip_check};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::block::Block;
use zebra_chain::serialization::ZcashDeserialize;
use zebra_network::protocol::external::Message;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"block\x00\x00\x00\x00\x00\x00\x00";

    // Direct block deserialisation with round-trip check.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Block>(data);
    });

    // Via P2P frame.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Raw frame.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: valid-looking header + tx_count = u32::MAX (truncated).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        // Block header: version(4) + prev_hash(32) + merkle_root(32) +
        //               final_sapling_root(32) + time(4) + bits(4) +
        //               nonce(32) + solution_size(3) + solution(1344)
        payload.write_i32::<LittleEndian>(4).unwrap(); // version
        payload.extend_from_slice(&[0u8; 32]); // prev_hash
        payload.extend_from_slice(&[0u8; 32]); // merkle_root
        payload.extend_from_slice(&[0u8; 32]); // final_sapling_root
        payload.write_u32::<LittleEndian>(1_700_000_000).unwrap(); // time
        payload.write_u32::<LittleEndian>(0x1f07ffff).unwrap(); // bits
        payload.extend_from_slice(&[0u8; 32]); // nonce
        // Equihash solution: compact-size 0xfd 0x40 0x05 = 1344 bytes
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(1344).unwrap();
        payload.extend_from_slice(&[0u8; 1344]);
        // tx_count = 0xfe + u32::MAX
        payload.push(0xfe);
        payload.write_u32::<LittleEndian>(u32::MAX).unwrap();
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
