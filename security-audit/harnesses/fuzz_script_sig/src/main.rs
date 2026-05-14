//! Fuzzing harness: Script signature parsing.
//!
//! Attack surface:
//! - DER-encoded ECDSA signatures with arbitrary bytes
//! - Signature hash type byte (last byte)
//! - Multisig scripts (OP_0 + multiple sigs)
//! - Script execution via libzcash_script FFI

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transparent::Script;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct Script deserialisation (script_sig has same wire format).
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Script::zcash_deserialize(&mut cursor);
    });

    // Construct script_sig directly.
    let _ = catch_panic(|| {
        let _script = Script::new(data);
    });

    // Crafted: DER signature push + sighash type.
    let _ = catch_panic(|| {
        let mut script_bytes = Vec::new();
        // Push a 71-byte DER signature.
        script_bytes.push(0x47); // push 71 bytes
        // DER header.
        script_bytes.push(0x30); // SEQUENCE
        script_bytes.push(0x44); // length 68
        script_bytes.push(0x02); // INTEGER (r)
        script_bytes.push(0x20); // length 32
        let r_len = data.len().min(32);
        script_bytes.extend_from_slice(&data[..r_len]);
        script_bytes.extend(std::iter::repeat(0u8).take(32 - r_len));
        script_bytes.push(0x02); // INTEGER (s)
        script_bytes.push(0x20); // length 32
        script_bytes.extend_from_slice(&[0u8; 32]);
        script_bytes.push(0x01); // SIGHASH_ALL
        let _script = Script::new(&script_bytes);
    });

    // Crafted: OP_0 + multiple signature pushes (multisig).
    let _ = catch_panic(|| {
        let mut script_bytes = Vec::new();
        script_bytes.push(0x00); // OP_0
        for _ in 0..3 {
            script_bytes.push(0x47); // push 71 bytes
            script_bytes.extend_from_slice(&data[..data.len().min(71)]);
            script_bytes.extend(std::iter::repeat(0u8).take(71usize.saturating_sub(data.len())));
        }
        let _script = Script::new(&script_bytes);
    });
});
