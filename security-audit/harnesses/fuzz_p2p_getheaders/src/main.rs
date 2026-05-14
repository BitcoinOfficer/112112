//! Fuzzing harness: P2P `getheaders` message deserialisation.
//!
//! Same structure as `getblocks`. Tests the headers-specific handler path.

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

    let cmd = *b"getheaders\x00\x00";

    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: 2000 locator hashes.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_u32::<LittleEndian>(170_100).unwrap();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(2000).unwrap();
        for _ in 0..2000u32 {
            payload.extend_from_slice(&[0xdd; 32]);
        }
        payload.extend_from_slice(&[0u8; 32]);
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
