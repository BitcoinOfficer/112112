//! Fuzzing harness: `sendrawtransaction` RPC endpoint.
//!
//! Attack surface:
//! - Hex decoding of arbitrary strings
//! - Transaction deserialisation from decoded bytes
//! - Validation logic (script verification, consensus rules)
//! - Mempool insertion logic

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transaction::Transaction;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Strategy 1: treat data as raw transaction bytes.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Transaction::zcash_deserialize(&mut cursor);
    });

    // Strategy 2: hex-encode data and then decode (simulates RPC hex param).
    let _ = catch_panic(|| {
        let hex_str = hex::encode(data);
        if let Ok(decoded) = hex::decode(&hex_str) {
            let mut cursor = Cursor::new(decoded.as_slice());
            let _ = Transaction::zcash_deserialize(&mut cursor);
        }
    });

    // Strategy 3: use fuzzer bytes as a hex string directly.
    let _ = catch_panic(|| {
        if let Ok(s) = std::str::from_utf8(data) {
            if let Ok(decoded) = hex::decode(s.trim()) {
                let mut cursor = Cursor::new(decoded.as_slice());
                let _ = Transaction::zcash_deserialize(&mut cursor);
            }
        }
    });

    // Strategy 4: inject non-hex characters.
    let _ = catch_panic(|| {
        let malicious_hex = [
            "gg",
            "0x1234",
            "  ",
            "\n\r\t",
            &"ff".repeat(100_000),
            "zzzzzzzzzzzzzzzz",
        ];
        for s in &malicious_hex {
            let _ = hex::decode(s);
        }
    });
});
