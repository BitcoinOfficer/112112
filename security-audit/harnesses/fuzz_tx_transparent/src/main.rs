//! Fuzzing harness: Transparent transaction input/output deserialisation.
//!
//! Attack surface:
//! - Script length (compact-size) → arbitrary script bytes
//! - Sequence number (u32)
//! - Value (i64) — negative values, overflow
//! - Outpoint (txid + vout index)

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging, roundtrip_check};
use byteorder::{LittleEndian, WriteBytesExt};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transparent::{Input, Output};
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Fuzz transparent Input.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Input>(data);
    });

    // Fuzz transparent Output.
    let _ = catch_panic(|| {
        let _ = roundtrip_check::<Output>(data);
    });

    // Crafted: Input with script_sig length = u32::MAX (OOM probe).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 32]); // txid
        payload.write_u32::<LittleEndian>(0).unwrap(); // vout
        // script_sig length: compact-size 0xfe + u32::MAX
        payload.push(0xfe);
        payload.write_u32::<LittleEndian>(u32::MAX).unwrap();
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Input::zcash_deserialize(&mut cursor);
    });

    // Crafted: Output with value = i64::MIN (negative overflow).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_i64::<LittleEndian>(i64::MIN).unwrap();
        // script_pubkey length = 0
        payload.push(0x00);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Output::zcash_deserialize(&mut cursor);
    });

    // Crafted: Output with value = i64::MAX.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.write_i64::<LittleEndian>(i64::MAX).unwrap();
        payload.push(0x00);
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Output::zcash_deserialize(&mut cursor);
    });

    // Crafted: Input with 10,000-byte script_sig.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 32]); // txid
        payload.write_u32::<LittleEndian>(0).unwrap(); // vout
        payload.push(0xfd);
        payload.write_u16::<LittleEndian>(10_000).unwrap();
        payload.extend(std::iter::repeat(0x51u8).take(10_000)); // OP_1 * 10000
        payload.write_u32::<LittleEndian>(0xffff_ffff).unwrap(); // sequence
        let mut cursor = Cursor::new(payload.as_slice());
        let _ = Input::zcash_deserialize(&mut cursor);
    });
});
