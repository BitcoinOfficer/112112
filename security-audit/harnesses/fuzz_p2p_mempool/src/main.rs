//! Fuzzing harness: P2P `mempool` message deserialisation.
//!
//! `mempool` has an empty payload. Tests header robustness and trailing bytes.

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"mempool\x00\x00\x00\x00\x00";

    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Empty payload (correct).
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, &[]);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Non-empty payload (should be rejected or ignored).
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
