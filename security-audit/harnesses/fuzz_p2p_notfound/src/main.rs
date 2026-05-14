//! Fuzzing harness: P2P `notfound` message deserialisation.
//!
//! Same wire format as `inv`. Tests the notfound handler path.

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

    let cmd = *b"notfound\x00\x00\x00\x00";

    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // OOM probe.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(50_000).unwrap();
        payload.extend_from_slice(&[0u8; 36]);
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
