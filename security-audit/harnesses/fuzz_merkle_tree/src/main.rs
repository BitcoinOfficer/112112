//! Fuzzing harness: Merkle tree construction.
//!
//! Attack surface:
//! - AuthDataRootHash computation from arbitrary transaction hashes
//! - Root computation with 0, 1, 2, odd, and even numbers of leaves
//! - Potential integer overflow in tree height calculation

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use zebra_chain::block::merkle::Root;
use zebra_chain::transaction::Transaction;
use zebra_chain::serialization::ZcashDeserialize;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Attempt to deserialise multiple transactions from the fuzzer input,
    // then compute the Merkle root.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let mut txs = Vec::new();
        while cursor.position() < data.len() as u64 {
            match Transaction::zcash_deserialize(&mut cursor) {
                Ok(tx) => txs.push(std::sync::Arc::new(tx)),
                Err(_) => break,
            }
        }
        if !txs.is_empty() {
            let _ = Root::from_iter(txs.iter().map(|tx| tx.as_ref()));
        }
    });

    // Crafted: compute root from 0 transactions.
    let _ = catch_panic(|| {
        let txs: Vec<std::sync::Arc<Transaction>> = Vec::new();
        let _ = Root::from_iter(txs.iter().map(|tx| tx.as_ref()));
    });

    // Crafted: compute root from 1 transaction (edge case).
    let _ = catch_panic(|| {
        // Minimal coinbase-like v4 transaction.
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&0x8000_0004u32.to_le_bytes()); // header
        tx_bytes.extend_from_slice(&0x892F_2085u32.to_le_bytes()); // versionGroupId
        tx_bytes.push(0x01); // vin count = 1
        // Coinbase input: txid=0, vout=0xffffffff, script, sequence.
        tx_bytes.extend_from_slice(&[0u8; 32]); // txid
        tx_bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // vout
        tx_bytes.push(0x04); // script len = 4
        tx_bytes.extend_from_slice(&[0x03, 0x4e, 0x00, 0x00]); // block height script
        tx_bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx_bytes.push(0x00); // vout count = 0
        tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // locktime
        tx_bytes.extend_from_slice(&0u32.to_le_bytes()); // expiry
        tx_bytes.extend_from_slice(&0i64.to_le_bytes()); // valueBalance
        tx_bytes.push(0x00); // vShieldedSpend
        tx_bytes.push(0x00); // vShieldedOutput
        tx_bytes.push(0x00); // vJoinSplit
        tx_bytes.extend_from_slice(&[0u8; 64]); // bindingSig

        let mut cursor = Cursor::new(tx_bytes.as_slice());
        if let Ok(tx) = Transaction::zcash_deserialize(&mut cursor) {
            let txs = vec![std::sync::Arc::new(tx)];
            let _ = Root::from_iter(txs.iter().map(|t| t.as_ref()));
        }
    });
});
