//! Fuzzing harness: Note commitment tree operations.
//!
//! Attack surface:
//! - Sapling note commitment tree (incremental Merkle tree)
//! - Orchard note commitment tree
//! - Append operations with arbitrary commitment bytes
//! - Root computation after arbitrary appends
//! - Serialisation/deserialisation of tree state

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use zebra_chain::sapling::tree::NoteCommitmentTree as SaplingTree;
use zebra_chain::orchard::tree::NoteCommitmentTree as OrchardTree;
use zebra_chain::serialization::ZcashDeserialize;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    // Fuzz Sapling note commitment tree deserialisation.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = SaplingTree::zcash_deserialize(&mut cursor);
    });

    // Fuzz Orchard note commitment tree deserialisation.
    let _ = catch_panic(|| {
        let mut cursor = Cursor::new(data);
        let _ = OrchardTree::zcash_deserialize(&mut cursor);
    });

    // Append arbitrary 32-byte commitments to a fresh Sapling tree.
    let _ = catch_panic(|| {
        let mut tree = SaplingTree::default();
        let chunks = data.chunks(32);
        for chunk in chunks.take(100) {
            if chunk.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                // Attempt to append; ignore errors (invalid commitments expected).
                let _ = tree.append(sapling_crypto::Node::from_bytes(arr));
            }
        }
        // Compute root after appends.
        let _ = tree.root();
    });

    // Append arbitrary 32-byte commitments to a fresh Orchard tree.
    let _ = catch_panic(|| {
        let mut tree = OrchardTree::default();
        let chunks = data.chunks(32);
        for chunk in chunks.take(100) {
            if chunk.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk);
                let node = orchard::tree::MerkleHashOrchard::from_bytes(&arr);
                if node.is_some().into() {
                    let _ = tree.append(node.unwrap());
                }
            }
        }
        let _ = tree.root();
    });
});
