//! Fuzzing harness: P2P `ping` message deserialisation.
//!
//! Payload: 8-byte nonce (u64 LE). Attack surface is minimal but we test
//! truncated payloads, oversized payloads, and header manipulation.

#![no_main]

use harness_common::{
    build_p2p_frame, build_p2p_frame_bad_checksum, build_p2p_frame_oversized_len,
    catch_panic, clamp_input, init_logging, seed_ping_payload,
};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"ping\x00\x00\x00\x00\x00\x00\x00\x00";

    // Raw bytes as frame.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Fuzzer bytes as payload.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Bad checksum — should be rejected cleanly.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame_bad_checksum(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Oversized length field — length-confusion attack.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame_oversized_len(&cmd, &seed_ping_payload());
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
