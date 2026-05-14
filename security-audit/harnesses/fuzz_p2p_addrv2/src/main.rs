//! Fuzzing harness: P2P `addrv2` (BIP-155) message deserialisation.
//!
//! Attack surface:
//! - Variable-length network ID byte (0x01=IPv4, 0x02=IPv6, 0x04=Tor v3, etc.)
//! - Per-entry addr_len compact-size field (can be crafted to be huge)
//! - Unknown network IDs with arbitrary addr bytes

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

    let cmd = *b"addrv2\x00\x00\x00\x00\x00\x00";

    // Raw bytes as frame.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Fuzzer bytes as addrv2 payload.
    let _ = catch_panic(|| {
        let frame = build_p2p_frame(&cmd, data);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: 1 entry, Tor v3 network (0x04), addr_len = 32.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0x01); // count = 1
        payload.write_u32::<LittleEndian>(1_700_000_000).unwrap(); // time
        payload.write_u64::<LittleEndian>(1).unwrap(); // services
        payload.push(0x04); // network = Tor v3
        payload.push(32); // addr_len
        payload.extend_from_slice(&[0xab; 32]); // addr
        payload.write_u16::<LittleEndian>(8233).unwrap(); // port
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });

    // Crafted: unknown network ID 0xff with oversized addr_len.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0x01); // count = 1
        payload.write_u32::<LittleEndian>(0).unwrap(); // time
        payload.write_u64::<LittleEndian>(0).unwrap(); // services
        payload.push(0xff); // unknown network
        payload.push(0xfd); // compact-size 2-byte prefix
        payload.write_u16::<LittleEndian>(60000).unwrap(); // addr_len = 60000
        payload.extend_from_slice(&[0u8; 60]); // truncated addr
        let frame = build_p2p_frame(&cmd, &payload);
        let mut cursor = Cursor::new(frame.as_slice());
        let _ = Message::zcash_deserialize(&mut cursor);
    });
});
