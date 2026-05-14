//! Fuzzing harness: Sighash computation paths.
//!
//! Attack surface:
//! - SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY
//! - ZIP-243 (Sapling) and ZIP-244 (Orchard/NU5) sighash algorithms
//! - Input index out-of-bounds
//! - Empty transaction inputs
//! - Overflow in value summation

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_chain::transaction::{Transaction, SigHashType};
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    if data.len() < 2 {
        return;
    }

    // Use first byte to select sighash type, rest as transaction bytes.
    let sighash_byte = data[0];
    let tx_bytes = &data[1..];

    let sighash_type = match sighash_byte & 0x1f {
        0x01 => SigHashType::All,
        0x02 => SigHashType::None,
        0x03 => SigHashType::Single,
        _ => SigHashType::All,
    };
    let anyone_can_pay = (sighash_byte & 0x80) != 0;

    // Attempt to deserialise a transaction and compute its sighash.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(tx_bytes);
        if let Ok(tx) = Transaction::zcash_deserialize(&mut cursor) {
            // Compute sighash for each input index.
            let input_count = tx.inputs().len();
            for idx in 0..input_count.min(10) {
                let _ = tx.sighash(
                    zebra_chain::parameters::NetworkUpgrade::Nu5,
                    sighash_type,
                    anyone_can_pay,
                    Some(idx),
                    None,
                );
            }
            // Also try out-of-bounds index.
            let _ = tx.sighash(
                zebra_chain::parameters::NetworkUpgrade::Nu5,
                sighash_type,
                anyone_can_pay,
                Some(usize::MAX),
                None,
            );
        }
    });

    // Attempt sighash on raw fuzzer bytes as transaction.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        if let Ok(tx) = Transaction::zcash_deserialize(&mut cursor) {
            let _ = tx.sighash(
                zebra_chain::parameters::NetworkUpgrade::Sapling,
                SigHashType::All,
                false,
                Some(0),
                None,
            );
        }
    });
});
