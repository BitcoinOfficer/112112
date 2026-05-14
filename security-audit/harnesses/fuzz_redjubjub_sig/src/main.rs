//! Fuzzing harness: RedJubjub signature verification.
//!
//! Attack surface:
//! - 64-byte signature bytes (R + S components on Jubjub curve)
//! - Verification key (32 bytes, compressed Jubjub point)
//! - Message bytes (arbitrary length)
//! - Invalid curve points (not on Jubjub)
//! - Small-subgroup attacks
//! - Signature malleability

#![no_main]

use harness_common::{catch_panic, clamp_input, init_logging};
use libfuzzer_sys::fuzz_target;
use redjubjub::{Signature, VerificationKey, SpendAuth};

fuzz_target!(|data: &[u8]| {
    init_logging();
    let data = clamp_input(data);

    if data.len() < 96 {
        return; // Need at least 32 (vk) + 64 (sig) bytes.
    }

    let vk_bytes: [u8; 32] = data[..32].try_into().unwrap();
    let sig_bytes: [u8; 64] = data[32..96].try_into().unwrap();
    let message = &data[96..];

    // Attempt to parse verification key.
    let _ = catch_panic(|| {
        if let Ok(vk) = VerificationKey::<SpendAuth>::try_from(vk_bytes) {
            let sig = Signature::<SpendAuth>::from(sig_bytes);
            // Verify with arbitrary message.
            let _ = vk.verify(message, &sig);
        }
    });

    // Attempt with all-zero vk (identity point — small subgroup).
    let _ = catch_panic(|| {
        let zero_vk = [0u8; 32];
        if let Ok(vk) = VerificationKey::<SpendAuth>::try_from(zero_vk) {
            let sig = Signature::<SpendAuth>::from(sig_bytes);
            let _ = vk.verify(message, &sig);
        }
    });

    // Attempt with all-0xff vk (invalid point).
    let _ = catch_panic(|| {
        let ff_vk = [0xffu8; 32];
        if let Ok(vk) = VerificationKey::<SpendAuth>::try_from(ff_vk) {
            let sig = Signature::<SpendAuth>::from(sig_bytes);
            let _ = vk.verify(message, &sig);
        }
    });

    // Attempt with all-zero signature.
    let _ = catch_panic(|| {
        if let Ok(vk) = VerificationKey::<SpendAuth>::try_from(vk_bytes) {
            let zero_sig = Signature::<SpendAuth>::from([0u8; 64]);
            let _ = vk.verify(message, &zero_sig);
        }
    });
});
