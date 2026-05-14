//! Fuzzing harness: P2P `getdata` message deserialisation.
//!
//! Same wire format as `inv` — compact-size count + inventory vectors.
//! Attack surface identical to `fuzz_p2p_inv` but exercises the `getdata`
//! handler path which may have different allocation behaviour.

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

    let cmd = *b"getdata\x00\x00\x00\x00\x00";

    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // OOM probe: claim 50,000 entries.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(50_000).unwrap();
        payload.extend_from_slice(&[0u8; 36]); // truncated
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
