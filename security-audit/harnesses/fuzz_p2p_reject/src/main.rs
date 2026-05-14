//! Fuzzing harness: P2P `reject` message deserialisation.
//!
//! Attack surface:
//! - Variable-length message string (compact-size prefix)
//! - Reject code byte
//! - Variable-length reason string
//! - Optional 32-byte data field (for TX/block rejections)
//! - Extremely long strings → OOM / stack overflow

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"reject\x00\x00\x00\x00\x00\x00";

    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: message = "tx", code = 0x10, reason = 64KB string.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0x02); // message len = 2
        payload.extend_from_slice(b"tx");
        payload.push(0x10); // REJECT_INVALID
        // reason: compact-size 0xfd + 60000
        payload.push(0xfd);
        let reason_len: u16 = 60_000;
        payload.extend_from_slice(&reason_len.to_le_bytes());
        payload.extend(std::iter::repeat(b'A').take(reason_len as usize));
        payload.extend_from_slice(&[0u8; 32]); // data
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: message len = 0xff (8-byte compact-size) → huge allocation.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xff);
        payload.extend_from_slice(&u64::MAX.to_le_bytes());
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
