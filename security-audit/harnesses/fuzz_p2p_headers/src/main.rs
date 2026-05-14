//! Fuzzing harness: P2P `headers` message deserialisation.
//!
//! Attack surface:
//! - Compact-size count of block headers (can claim 2000+)
//! - Each header: 140 bytes (header) + 1 byte tx_count (always 0 in headers msg)
//! - Oversized count → OOM

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

    let cmd = *b"headers\x00\x00\x00\x00\x00";

    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: 2000 headers (max allowed), each 141 bytes.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(2000).unwrap();
        for _ in 0..2000u32 {
            // Minimal block header (140 bytes) + tx_count byte (0).
            payload.extend_from_slice(&[0u8; 140]);
            payload.push(0x00);
        }
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: count = u16::MAX, truncated payload.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(u16::MAX).unwrap();
        payload.extend_from_slice(&[0u8; 141]); // only 1 header
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
