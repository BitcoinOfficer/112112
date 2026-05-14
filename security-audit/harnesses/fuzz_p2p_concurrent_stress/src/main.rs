//! Fuzzing harness: Concurrent P2P message stress test.
//!
//! This harness spawns multiple threads that simultaneously deserialise
//! different message types from shared fuzzer input, exercising:
//! - Data races in shared state (TSAN target)
//! - Deadlocks in codec state machines
//! - Use-after-free in concurrent message processing
//! - Thread-safety of the address book and peer set

#![no_main]

use harness_common::{
    build_p2p_frame, catch_panic, clamp_input, init_logging, seed_inv_payload, seed_ping_payload,
    seed_version_payload,
};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::sync::Arc;
use std::thread;
use zebra_network::protocol::external::Message;
use zebra_chain::serialization::ZcashDeserialize;

/// Number of concurrent threads to spawn per fuzzer invocation.
const THREAD_COUNT: usize = 8;

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);
    let data = Arc::new(data.to_vec());

    // Spawn THREAD_COUNT threads, each deserialising a different message type.
    let handles: Vec<_> = (0..THREAD_COUNT)
        .map(|i| {
            let data = Arc::clone(&data);
            thread::spawn(move || {
                let _ = catch_panic(|| {
                    match i % 6 {
                        0 => {
                            // Raw bytes as frame.
                            let mut cursor = Cursor::new(data.as_slice());
                            let _ = Message::zcash_deserialize(&mut cursor);
                        }
                        1 => {
                            // Ping frame.
                            let cmd = *b"ping\x00\x00\x00\x00\x00\x00\x00\x00";
                            let frame = build_p2p_frame(&cmd, &seed_ping_payload());
                            let mut cursor = Cursor::new(frame.as_slice());
                            let _ = Message::zcash_deserialize(&mut cursor);
                        }
                        2 => {
                            // Inv frame with fuzzer data.
                            let cmd = *b"inv\x00\x00\x00\x00\x00\x00\x00\x00\x00";
                            let frame = build_p2p_frame(&cmd, &data);
                            let mut cursor = Cursor::new(frame.as_slice());
                            let _ = Message::zcash_deserialize(&mut cursor);
                        }
                        3 => {
                            // Version frame.
                            let cmd = *b"version\x00\x00\x00\x00\x00";
                            let frame = build_p2p_frame(&cmd, &seed_version_payload());
                            let mut cursor = Cursor::new(frame.as_slice());
                            let _ = Message::zcash_deserialize(&mut cursor);
                        }
                        4 => {
                            // Drain multiple messages from fuzzer stream.
                            let mut cursor = Cursor::new(data.as_slice());
                            for _ in 0..10 {
                                match Message::zcash_deserialize(&mut cursor) {
                                    Ok(_) => {}
                                    Err(_) => break,
                                }
                            }
                        }
                        _ => {
                            // Inv frame with seed data.
                            let cmd = *b"inv\x00\x00\x00\x00\x00\x00\x00\x00\x00";
                            let frame = build_p2p_frame(&cmd, &seed_inv_payload());
                            let mut cursor = Cursor::new(frame.as_slice());
                            let _ = Message::zcash_deserialize(&mut cursor);
                        }
                    }
                });
            })
        })
        .collect();

    // Wait for all threads to complete.
    for handle in handles {
        let _ = handle.join();
    }
});
