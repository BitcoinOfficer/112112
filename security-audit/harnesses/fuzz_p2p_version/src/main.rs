//! Fuzzing harness: P2P `version` message deserialisation.
//!
//! Attack surface:
//! - Integer parsing of protocol version, services, timestamp, start_height
//! - Variable-length user-agent string (compact-size prefix)
//! - IPv4/IPv6 address parsing inside addr_recv / addr_from
//! - Relay flag byte
//!
//! Sanitisers: ASAN (buffer overflows), MSAN (uninit reads), UBSAN (integer UB)
//! Fuzzer: libFuzzer via libfuzzer-sys, AFL++ persistent mode

#![no_main]

use harness_common::{
    build_p2p_frame, catch_panic, clamp_input, init_logging, seed_version_payload,
};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Strategy 1: treat raw bytes as a complete P2P frame.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Strategy 2: wrap fuzzer bytes as the payload of a `version` frame.
    let _ = catch_panic(|| {
        let cmd = *b"version\x00\x00\x00\x00\x00";
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Strategy 3: mutate a valid seed payload.
    let _ = catch_panic(|| {
        let mut seed = seed_version_payload();
        // Splice fuzzer bytes into the user-agent length field (byte 80).
        if !data.is_empty() && seed.len() > 80 {
            seed[80] = data[0];
        }
        let cmd = *b"version\x00\x00\x00\x00\x00";
        let frame = build_p2p_frame(&cmd, &seed);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
