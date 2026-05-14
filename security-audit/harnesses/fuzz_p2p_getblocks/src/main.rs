//! Fuzzing harness: P2P `getblocks` message deserialisation.
//!
//! Attack surface:
//! - version (u32 LE)
//! - block_locator_hashes: compact-size count + 32-byte hashes each
//! - hash_stop: 32-byte hash
//! - Oversized locator count (can claim 2000+ hashes → OOM)

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"getblocks\x00\x00\x00";

    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: version=170100, 2000 locator hashes, hash_stop=0.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_u32::<LittleEndian>(170_100).unwrap();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(2000).unwrap();
        for _ in 0..2000u32 {
            payload.extend_from_slice(&[0xcc; 32]);
        }
        payload.extend_from_slice(&[0u8; 32]); // hash_stop
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: count = u16::MAX (truncated payload).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_u32::<LittleEndian>(170_100).unwrap();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(u16::MAX).unwrap();
        payload.extend_from_slice(&[0u8; 32]); // only 1 hash
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
