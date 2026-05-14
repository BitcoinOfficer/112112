//! Fuzzing harness: P2P `inv` message deserialisation.
//!
//! Attack surface:
//! - Compact-size count (can claim 50,000+ inventory entries → OOM)
//! - Per-entry: type (u32 LE) + hash (32 bytes)
//! - Unknown inventory types (e.g., 0xffffffff)
//! - Duplicate hashes (mempool flooding)

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging, seed_inv_payload};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"inv\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    // Raw bytes as frame.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Fuzzer bytes as inv payload.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: 50,000 entries (max allowed) with unknown type.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(50_000).unwrap();
        for _ in 0..50_000u32 {
            payload.write_u32::<LittleEndian>(0xffff_ffff).unwrap();
            payload.extend_from_slice(&[0u8; 32]);
        }
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: count claims 50,001 entries but payload is truncated.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(50_001).unwrap();
        payload.extend_from_slice(&[0u8; 36]); // only 1 entry worth of data
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Valid seed with fuzzer bytes spliced into hash field.
    let _ = catch_panic(|| {
        let mut seed = seed_inv_payload();
        if data.len() >= 4 {
            seed[5..5 + data.len().min(32)].copy_from_slice(&data[..data.len().min(32)]);
        }
        let frame = build_p2p_frame(&cmd, &seed);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
