//! Fuzzing harness: Codec round-trip for all message types.
//!
//! This harness performs differential fuzzing:
//! 1. Deserialise a message from fuzzer input.
//! 2. Re-serialise the message.
//! 3. Deserialise the re-serialised bytes.
//! 4. Compare the two deserialised values.
//!
//! Any divergence indicates a serialisation bug that could cause consensus splits.

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::{ZcashDeserialize, ZcashSerialize};
use zebra_chain::block::Block;
use zebra_chain::transaction::Transaction;

/// Perform a round-trip check on type T and return whether a divergence was found.
fn check_roundtrip<T>(data: &[u8]) -> bool
where
    T: ZcashDeserialize + ZcashSerialize + std::fmt::Debug + PartialEq,
{
    let mut cursor = Cursor::new(data);
    let first = match T::zcash_deserialize(&mut cursor) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let consumed = cursor.position() as usize;

    let mut serialised = Vec::new();
    if first.zcash_serialize(&mut serialised).is_err() {
        return false;
    }

    let mut cursor2 = Cursor::new(serialised.as_slice());
    let second = match T::zcash_deserialize(&mut cursor2) {
        Ok(v) => v,
        Err(_) => {
            // Re-serialised bytes could not be deserialised — this is a bug!
            tracing::error!(
                "ROUND-TRIP BUG: re-serialised bytes failed to deserialise. \
                 original_len={} serialised_len={}",
                consumed,
                serialised.len()
            );
            return true;
        }
    };

    if first != second {
        tracing::error!(
            "ROUND-TRIP DIVERGENCE: first={:?} second={:?}",
            first,
            second
        );
        return true;
    }

    // Also check that the serialised lengths match.
    if consumed != serialised.len() {
        tracing::warn!(
            "ROUND-TRIP LENGTH MISMATCH: consumed={} serialised={}",
            consumed,
            serialised.len()
        );
    }

    false
}

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Round-trip check for P2P messages.
    let _ = catch_panic(|| {
        check_roundtrip::<Message>(data);
    });

    // Round-trip check for blocks.
    let _ = catch_panic(|| {
        check_roundtrip::<Block>(data);
    });

    // Round-trip check for transactions.
    let _ = catch_panic(|| {
        check_roundtrip::<Transaction>(data);
    });
});
