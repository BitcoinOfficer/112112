//! Fuzzing harness: P2P `addr` message deserialisation.
//!
//! Attack surface:
//! - Compact-size count field (can claim millions of addresses → OOM)
//! - Per-entry: timestamp (u32), services (u64), IPv6 (16 bytes), port (u16)
//! - Extremely large count values triggering Vec::reserve / allocation panics

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

/// Build an `addr` payload with `count` entries, each filled with `fill`.
fn build_addr_payload(count_varint: &[u8], entry_fill: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(count_varint);
    v.extend_from_slice(entry_fill);
    v
}

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"addr\x00\x00\x00\x00\x00\x00\x00\x00";

    // Raw bytes as frame.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Fuzzer bytes as addr payload.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: count = 0xfd (2-byte compact size) with value 1000.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(1000).unwrap();
        // One valid-looking entry (30 bytes: 4+8+16+2).
        payload.extend_from_slice(&[0u8; 30]);
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: count = 0xfe (4-byte compact size) with u32::MAX → OOM probe.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfe);
        payload.write_u32::<LittleEndian>(u32::MAX).unwrap();
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: count = 0xff (8-byte compact size) with u64::MAX → OOM probe.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xff);
        payload.write_u64::<LittleEndian>(u64::MAX).unwrap();
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Fuzzer-controlled count prefix + fuzzer body.
    if data.len() >= 2 {
        let _ = catch_panic(|| {
            let payload = build_addr_payload(&data[..1], &data[1..]);
            let frame = build_p2p_frame(&cmd, &payload);
            let mut cursor = Cursor::new(frame.as_slice());
            let _ = Message::zcash_deserialize(&mut cursor);
        });
    }
});
