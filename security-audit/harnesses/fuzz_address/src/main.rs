//! Fuzzing harness: Zcash address parsing.
//!
//! Attack surface:
//! - Transparent P2PKH addresses (t1...)
//! - Transparent P2SH addresses (t3...)
//! - Sapling shielded addresses (zs1...)
//! - Unified addresses (u1...)
//! - Base58Check decoding (checksum validation)
//! - Bech32/Bech32m decoding
//! - Invalid HRP (human-readable part)
//! - Oversized address strings

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::str;
use zebra_chain::parameters::Network;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Attempt to parse as a UTF-8 string and then as a Zcash address.
    let _ = catch_panic(|| {
        if let Ok(s) = str::from_utf8(data) {
            let _ = s.parse::<zebra_chain::transparent::Address>();
        }
    });

    // Attempt to parse as a shielded address.
    let _ = catch_panic(|| {
        if let Ok(s) = str::from_utf8(data) {
            let _ = zebra_chain::sapling::PaymentAddress::from_str_with_network(s);
        }
    });

    // Attempt to parse via zcash_address crate.
    let _ = catch_panic(|| {
        if let Ok(s) = str::from_utf8(data) {
            let _ = zcash_address::ZcashAddress::try_from_encoded(s);
        }
    });

    // Crafted: valid t1 prefix + fuzzer bytes (base58 alphabet).
    let _ = catch_panic(|| {
        let base58_chars = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut addr = b"t1".to_vec();
        for &b in data.iter().take(32) {
            addr.push(base58_chars[(b as usize) % base58_chars.len()]);
        }
        if let Ok(s) = str::from_utf8(&addr) {
            let _ = s.parse::<zebra_chain::transparent::Address>();
        }
    });

    // Crafted: valid zs1 prefix + fuzzer bytes (bech32 alphabet).
    let _ = catch_panic(|| {
        let bech32_chars = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let mut addr = b"zs1".to_vec();
        for &b in data.iter().take(80) {
            addr.push(bech32_chars[(b as usize) % bech32_chars.len()]);
        }
        if let Ok(s) = str::from_utf8(&addr) {
            let _ = zebra_chain::sapling::PaymentAddress::from_str_with_network(s);
        }
    });
});

// Bring the trait into scope for the shielded address parsing.
use std::str::FromStr;
trait FromStrWithNetwork: Sized {
    fn from_str_with_network(s: &str) -> Result<Self, Box<dyn std::error::Error>>;
}

impl FromStrWithNetwork for zebra_chain::sapling::PaymentAddress {
    fn from_str_with_network(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        s.parse::<zebra_chain::sapling::PaymentAddress>()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}
