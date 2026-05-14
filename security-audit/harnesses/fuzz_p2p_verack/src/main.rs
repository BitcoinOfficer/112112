//! Fuzzing harness: P2P `verack` message deserialisation.
//!
//! `verack` has an empty payload; the interesting attack surface is the
//! message header (magic, command, length, checksum) and any trailing bytes.

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Raw frame attempt.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Valid verack frame with fuzzer bytes appended (trailing-data robustness).
    let _ = catch_panic(|| {
        let cmd = *b"verack\x00\x00\x00\x00\x00\x00";
        let mut payload = Vec::new();
        payload.extend_from_slice(data); // verack should have empty payload
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
