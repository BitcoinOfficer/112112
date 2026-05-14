//! Common utilities shared across all Zebra security audit fuzzing harnesses.
//!
//! This crate provides:
//! - Wire-format helpers for constructing and mutating Zcash P2P messages
//! - Round-trip verification (serialise → deserialise → re-serialise → compare)
//! - Crash-safe panic catching wrappers
//! - Structured logging for sanitizer findings
//! - Corpus seed generation utilities

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::io::Cursor;
use std::panic;

use byteorder::{LittleEndian, WriteBytesExt};
use bytes::Bytes;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use zebra_chain::serialization::{ZcashDeserialize, ZcashSerialize};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Zcash mainnet magic bytes (little-endian).
pub const MAINNET_MAGIC: [u8; 4] = [0x24, 0xe9, 0x27, 0x64];

/// Zcash testnet magic bytes.
pub const TESTNET_MAGIC: [u8; 4] = [0xfa, 0x1a, 0xf9, 0xbf];

/// Maximum P2P message payload size (2 MiB).
pub const MAX_PAYLOAD_SIZE: usize = 2 * 1024 * 1024;

/// Maximum fuzzer input length we accept before truncating.
pub const MAX_FUZZ_INPUT: usize = 65_536;

// ── Wire-format helpers ───────────────────────────────────────────────────────

/// Build a complete Zcash P2P message frame around `payload`.
///
/// Layout: `magic(4) | command(12) | length(4 LE) | checksum(4) | payload`
///
/// The checksum is computed as the first 4 bytes of `SHA256d(payload)`.
pub fn build_p2p_frame(command: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + 12 + 4 + 4 + payload.len());
    frame.extend_from_slice(&MAINNET_MAGIC);
    frame.extend_from_slice(command);
    frame
        .write_u32::<LittleEndian>(payload.len() as u32)
        .expect("write to Vec never fails");
    let checksum = sha256d_checksum(payload);
    frame.extend_from_slice(&checksum);
    frame.extend_from_slice(payload);
    frame
}

/// Build a P2P frame with a deliberately wrong checksum (for negative testing).
pub fn build_p2p_frame_bad_checksum(command: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let mut frame = build_p2p_frame(command, payload);
    // Flip the first checksum byte.
    frame[16] ^= 0xff;
    frame
}

/// Build a P2P frame with an oversized length field (for length-confusion attacks).
pub fn build_p2p_frame_oversized_len(command: &[u8; 12], payload: &[u8]) -> Vec<u8> {
    let mut frame = build_p2p_frame(command, payload);
    // Overwrite the length field with u32::MAX.
    frame[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    frame
}

/// Compute SHA-256d checksum (first 4 bytes of SHA256(SHA256(data))).
pub fn sha256d_checksum(data: &[u8]) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

// ── Round-trip verification ───────────────────────────────────────────────────

/// Deserialise `T` from `data`, then re-serialise and compare byte-for-byte.
///
/// Returns `Ok(())` if the round-trip is lossless, or an error describing the
/// divergence. A divergence is a potential consensus bug or serialisation flaw.
pub fn roundtrip_check<T>(data: &[u8]) -> Result<(), RoundTripError>
where
    T: ZcashDeserialize + ZcashSerialize + std::fmt::Debug,
{
    let mut cursor = Cursor::new(data);
    let value = T::zcash_deserialize(&mut cursor).map_err(|e| RoundTripError::DeserFailed {
        reason: e.to_string(),
    })?;

    let mut serialised = Vec::new();
    value
        .zcash_serialize(&mut serialised)
        .map_err(|e| RoundTripError::SerFailed {
            reason: e.to_string(),
        })?;

    // The consumed prefix of `data` must equal `serialised`.
    let consumed = cursor.position() as usize;
    let original_slice = &data[..consumed];

    if original_slice != serialised.as_slice() {
        return Err(RoundTripError::Divergence {
            original: hex::encode(original_slice),
            reserialized: hex::encode(&serialised),
        });
    }
    Ok(())
}

/// Errors produced by [`roundtrip_check`].
#[derive(Debug, thiserror::Error)]
pub enum RoundTripError {
    /// Deserialisation failed (expected for most fuzz inputs).
    #[error("deserialisation failed: {reason}")]
    DeserFailed {
        /// The underlying error message.
        reason: String,
    },
    /// Re-serialisation failed (unexpected; indicates a bug).
    #[error("re-serialisation failed: {reason}")]
    SerFailed {
        /// The underlying error message.
        reason: String,
    },
    /// The re-serialised bytes differ from the original (consensus bug candidate).
    #[error("round-trip divergence: original={original} reserialized={reserialized}")]
    Divergence {
        /// Hex-encoded original bytes.
        original: String,
        /// Hex-encoded re-serialised bytes.
        reserialized: String,
    },
}

// ── Panic-safe wrapper ────────────────────────────────────────────────────────

/// Run `f` inside a `catch_unwind` boundary.
///
/// Returns `true` if `f` completed without panicking, `false` if it panicked.
/// The fuzzer should treat a panic as a finding only when the sanitiser also
/// fires; controlled panics (e.g., from `unwrap` on invalid input) are expected.
pub fn catch_panic<F: FnOnce() + panic::UnwindSafe>(f: F) -> bool {
    panic::catch_unwind(f).is_ok()
}

// ── Corpus seed helpers ───────────────────────────────────────────────────────

/// Return a minimal valid `version` message payload (for corpus seeding).
pub fn seed_version_payload() -> Vec<u8> {
    let mut v = Vec::new();
    // version (i32 LE) = 170100
    v.write_i32::<LittleEndian>(170_100).unwrap();
    // services (u64 LE) = NODE_NETWORK
    v.write_u64::<LittleEndian>(1).unwrap();
    // timestamp (i64 LE)
    v.write_i64::<LittleEndian>(1_700_000_000).unwrap();
    // addr_recv (26 bytes: services + IPv6 + port)
    v.extend_from_slice(&[0u8; 26]);
    // addr_from (26 bytes)
    v.extend_from_slice(&[0u8; 26]);
    // nonce (u64 LE)
    v.write_u64::<LittleEndian>(0xdeadbeef_cafebabe).unwrap();
    // user_agent (compact size 0 = empty string)
    v.push(0x00);
    // start_height (i32 LE)
    v.write_i32::<LittleEndian>(0).unwrap();
    // relay (bool)
    v.push(0x01);
    v
}

/// Return a minimal valid `ping` payload (8-byte nonce).
pub fn seed_ping_payload() -> Vec<u8> {
    let mut v = Vec::new();
    v.write_u64::<LittleEndian>(0x1234_5678_9abc_def0).unwrap();
    v
}

/// Return a minimal valid `inv` payload with one TX entry.
pub fn seed_inv_payload() -> Vec<u8> {
    let mut v = Vec::new();
    // count = 1 (compact size)
    v.push(0x01);
    // type = MSG_TX (1, LE u32)
    v.write_u32::<LittleEndian>(1).unwrap();
    // hash (32 bytes)
    v.extend_from_slice(&[0xab; 32]);
    v
}

// ── Logging initialisation ────────────────────────────────────────────────────

/// Initialise a minimal tracing subscriber for harness output.
///
/// Call once at the start of each harness binary's `main` function.
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();
}

// ── Mutation helpers ──────────────────────────────────────────────────────────

/// Truncate `data` to at most `MAX_FUZZ_INPUT` bytes.
pub fn clamp_input(data: &[u8]) -> &[u8] {
    if data.len() > MAX_FUZZ_INPUT {
        &data[..MAX_FUZZ_INPUT]
    } else {
        data
    }
}

/// Wrap raw fuzzer bytes in a valid P2P frame for the given command string.
///
/// `command_str` must be at most 12 ASCII bytes; it is zero-padded to 12 bytes.
pub fn wrap_in_frame(command_str: &str, payload: &[u8]) -> Vec<u8> {
    let mut cmd = [0u8; 12];
    let bytes = command_str.as_bytes();
    let len = bytes.len().min(12);
    cmd[..len].copy_from_slice(&bytes[..len]);
    build_p2p_frame(&cmd, payload)
}

/// Produce a `Bytes` view of the given slice (zero-copy).
pub fn as_bytes(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

// ── SHA-2 re-export (needed by sha256d_checksum) ──────────────────────────────
mod sha2 {
    pub use ::sha2::*;
}
