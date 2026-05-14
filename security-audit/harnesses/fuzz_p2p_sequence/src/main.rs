//! Fuzzing harness: concatenated P2P message stream.
//!
//! This harness feeds a raw byte stream to the codec as if it arrived over TCP.
//! It tests the framing layer's ability to handle:
//! - Multiple messages concatenated without gaps
//! - Partial messages (stream cut mid-frame)
//! - Interleaved valid and invalid frames
//! - Magic byte mismatches mid-stream
//! - Length fields that span message boundaries

#![no_main]

use harness_common::{
    build_p2p_frame, catch_panic, clamp_input, init_logging, seed_inv_payload, seed_ping_payload,
    seed_version_payload,
};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

/// Build a stream of N valid frames followed by fuzzer bytes.
fn build_mixed_stream(fuzzer_bytes: &[u8]) -> Vec<u8> {
    let mut stream = Vec::new();

    let ping_cmd = *b"ping\x00\x00\x00\x00\x00\x00\x00\x00";
    let inv_cmd  = *b"inv\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let ver_cmd  = *b"version\x00\x00\x00\x00\x00";

    stream.extend_from_slice(&build_p2p_frame(&ping_cmd, &seed_ping_payload()));
    stream.extend_from_slice(&build_p2p_frame(&inv_cmd,  &seed_inv_payload()));
    stream.extend_from_slice(&build_p2p_frame(&ver_cmd,  &seed_version_payload()));
    // Append fuzzer bytes — may form a partial or malformed frame.
    stream.extend_from_slice(fuzzer_bytes);
    stream
}

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Strategy 1: raw byte stream.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        // Drain all messages from the stream.
        loop {
            match Message::zcash_deserialize(&mut cursor) {
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // Strategy 2: valid frames + fuzzer suffix.
    let _ = catch_panic(|| {
        let stream = build_mixed_stream(data);
        let mut cursor = Cursor::new(stream.as_slice());
        loop {
            match Message::zcash_deserialize(&mut cursor) {
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // Strategy 3: fuzzer bytes as a single frame payload for each command type.
    for cmd_str in &["ping", "inv", "version", "block", "tx", "headers"] {
        let _ = catch_panic(|| {
            let mut cmd = [0u8; 12];
            let b = cmd_str.as_bytes();
            cmd[..b.len()].copy_from_slice(b);
            let frame = build_p2p_frame(&cmd, data);
            let mut cursor = Cursor::new(frame.as_slice());
            let _ = Message::zcash_deserialize(&mut cursor);
        });
    }
});
