//! Fuzzing harness: P2P `tx` message deserialisation.
//!
//! Attack surface:
//! - Full transaction deserialisation (v4 and v5 formats)
//! - Transparent inputs/outputs with arbitrary scripts
//! - Sapling spends/outputs with proof bytes
//! - Orchard action bundles
//! - Binding signatures and value commitments

#![no_main]

use harness_common::{build_p2p_frame, catch_panic, clamp_input, init_logging, roundtrip_check};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transaction::Transaction;
use zebra_chain::serialization::ZcashDeserialize;
use zebra_network::protocol::external::Message;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    let cmd = *b"tx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    // Attempt direct transaction deserialisation.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Transaction>(data);
    });

    // Attempt via P2P frame.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Raw frame attempt.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
