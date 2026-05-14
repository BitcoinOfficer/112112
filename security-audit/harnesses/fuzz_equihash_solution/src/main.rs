//! Fuzzing harness: Equihash solution verification.
//!
//! Attack surface:
//! - 1344-byte solution bytes (Zcash mainnet: n=200, k=9)
//! - Solution verification algorithm (XOR-based)
//! - Proof-of-work check (solution + nonce + header)
//! - Integer overflow in index computation

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use zebra_chain::work::equihash::Solution;
use zebra_chain::serialization::ZcashDeserialize;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Direct Solution deserialisation.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = Solution::zcash_deserialize(&mut cursor);
    });

    // Crafted: compact-size 1344 + fuzzer bytes as solution.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.extend_from_slice(&1344u16.to_le_bytes());
        let sol_len = data.len().min(1344);
        payload.extend_from_slice(&data[..sol_len]);
        payload.extend(std::iter::repeat(0u8).take(1344 - sol_len));
        let mut cursor = Cursor::new(payload.as_slice());
        if let Ok(solution) = Solution::zcash_deserialize(&mut cursor) {
            // Attempt to verify the solution against a dummy header.
            let dummy_header = [0u8; 140];
            let _ = solution.check(&dummy_header);
        }
    });

    // Crafted: all-zero solution (invalid but structurally valid).
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.extend_from_slice(&1344u16.to_le_bytes());
        payload.extend_from_slice(&[0u8; 1344]);
        let mut cursor = Cursor::new(payload.as_slice());
        if let Ok(solution) = Solution::zcash_deserialize(&mut cursor) {
            let dummy_header = [0u8; 140];
            let _ = solution.check(&dummy_header);
        }
    });

    // Crafted: all-0xff solution.
    let _ = catch_panic(|| {
        let mut payload = Vec::new();
        payload.push(0xfd);
        payload.extend_from_slice(&1344u16.to_le_bytes());
        payload.extend_from_slice(&[0xffu8; 1344]);
        let mut cursor = Cursor::new(payload.as_slice());
        if let Ok(solution) = Solution::zcash_deserialize(&mut cursor) {
            let dummy_header = [0u8; 140];
            let _ = solution.check(&dummy_header);
        }
    });
});
