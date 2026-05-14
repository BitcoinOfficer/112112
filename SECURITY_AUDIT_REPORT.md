# Zebra Security Audit Report
**Date:** May 14, 2026  
**Auditor:** Autonomous Security Analysis Engine  
**Scope:** Comprehensive security review of Zebra Zcash full node implementation

## Executive Summary

This audit identifies security concerns across the Zebra codebase, focusing on:
- Memory safety in FFI boundaries
- Input validation in network parsers
- Cryptographic primitive handling
- Concurrency and race conditions
- Denial-of-service vectors

**Risk Classification:**
- 🔴 CRITICAL: Immediate attention required
- 🟡 MEDIUM: Should be addressed
- 🟢 LOW: Minor improvements

---

## 1. FFI Boundary Analysis (`zebra-script`)

### Finding 1.1: Cryptographic Validation Workaround 🟡 MEDIUM

**Location:** `zebra-script/src/lib.rs:236-253`

**Issue:** The sighash callback uses a random dummy hash when validation fails, rather than propagating errors properly.

```rust
Some(computed.unwrap_or_else(|| {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}))
```

**Risk:** 
- This workaround exists because the C++ FFI callback cannot propagate failures
- An attacker could potentially craft transactions that trigger this path
- Using random bytes means signatures will fail with "overwhelming probability" but not certainty

**Recommendation:**
- Document why this is safe (attacker can't predict random value)
- Consider upstream fix in libzcash_script to propagate callback errors
- Add extensive test coverage for error conditions

**Status:** Documented in code; safe by design but non-obvious

---

### Finding 1.2: Expect Usage in Critical Paths 🟢 LOW

**Location:** `zebra-script/src/lib.rs:313-316`

**Issue:** Uses `.expect()` on coinbase script reconstruction:

```rust
transparent::Input::Coinbase { .. } => input
    .coinbase_script()
    .expect("coinbase_script reconstructs from a deserialized coinbase input"),
```

**Risk:** Low - expect message correctly explains invariant

**Verification:** This is safe because deserialized coinbase inputs can always reconstruct their script. The expect message follows project guidelines.

**Status:** ✅ ACCEPTABLE

---

## 2. Network Protocol Input Validation

### Finding 2.1: Message Length Enforcement ✅ SECURE

**Location:** `zebra-network/src/protocol/external/codec.rs:396-398`

The codec properly validates message body length:

```rust
if body_len > self.builder.max_len {
    return Err(Parse("body length exceeded maximum size"));
}
```

**Analysis:** 
- ✅ Checks against `MAX_PROTOCOL_MESSAGE_LEN` (2MB)
- ✅ Validation occurs before allocation
- ✅ Prevents memory exhaustion attacks

**Status:** ✅ SECURE

---

### Finding 2.2: String Length Limits ✅ SECURE

**Location:** Multiple locations in codec.rs

The code enforces strict limits on untrusted string fields:

- User agent: 256 bytes max (`MAX_USER_AGENT_LENGTH`)
- Reject message: 12 bytes max (`MAX_REJECT_MESSAGE_LENGTH`)  
- Reject reason: 111 bytes max (`MAX_REJECT_REASON_LENGTH`)

**Example (lines 528-532):**

```rust
if byte_count > MAX_USER_AGENT_LENGTH {
    return Err(Error::Parse(
        "user agent too long: must be 256 bytes or less",
    ));
}
```

**Analysis:**
- ✅ Prevents memory exhaustion via large strings
- ✅ Limits enforced before allocation
- ✅ Matches zcashd consensus rules

**Status:** ✅ SECURE

---

### Finding 2.3: Address Message DoS Protection ✅ SECURE

**Location:** `zebra-network/src/protocol/external/codec.rs:619-623`

```rust
if addrs.len() > constants::MAX_ADDRS_IN_MESSAGE {
    return Err(Error::Parse(
        "more than MAX_ADDRS_IN_MESSAGE in addr message",
    ));
}
```

**Analysis:**
- ✅ Limits address list size
- ✅ Prevents memory exhaustion
- ✅ Applied to both `addr` and `addrv2` messages

**Status:** ✅ SECURE

---

### Finding 2.4: Filter Message Size Limits ✅ SECURE

**Location:** `zebra-network/src/protocol/external/codec.rs:733-747`

```rust
const MAX_FILTERLOAD_FILTER_LENGTH: usize = 36000;
// ...
if !(FILTERLOAD_FIELDS_LENGTH..=MAX_FILTERLOAD_MESSAGE_LENGTH).contains(&body_len) {
    return Err(Error::Parse("Invalid filterload message body length."));
}
```

**Analysis:**
- ✅ Strictly validates filterload message size
- ✅ Uses externally-counted deserialization
- ✅ Similar protection for filteradd (520 byte limit)

**Status:** ✅ SECURE

---

## 3. Cryptographic Deserialization

### Finding 3.1: Unwrap in Serde Helpers 🔴 CRITICAL

**Location:** `zebra-chain/src/serialization/serde_helpers.rs`

**Multiple instances of `.unwrap()` in cryptographic point deserialization:**

Lines 13, 26, 39, 52, 65, 78, 91, 110:

```rust
impl From<AffinePoint> for jubjub::AffinePoint {
    fn from(local: AffinePoint) -> Self {
        jubjub::AffinePoint::from_bytes(local.bytes).unwrap()  // ❌
    }
}
```

**Risk:** 🔴 CRITICAL
- If malformed bytes are deserialized, this will panic
- Panics in deserialization can cause DoS
- Applies to: JubJub points, Pallas points, value commitments, note commitments

**Attack Vector:**
1. Attacker sends malformed transaction with invalid point encoding
2. Deserialization panics
3. Node crashes or becomes unresponsive

**Recommendation:**
- Replace all `.unwrap()` with proper error handling
- Return `Result` types from `From` implementations (or use `TryFrom`)
- Add fuzzing tests for malformed cryptographic data

**Proof of Concept Required:** Test with invalid point encodings

**Status:** 🔴 REQUIRES IMMEDIATE FIX

---

## 4. Concurrency Patterns

### Finding 4.1: Transaction/Block Deserialization Threading

**Location:** `zebra-network/src/protocol/external/codec.rs:777-819`

**Code Pattern:**

```rust
fn deserialize_transaction_spawning<R: Read + std::marker::Send>(
    reader: R,
) -> Result<Transaction, Error> {
    let mut result = None;
    tokio::task::block_in_place(|| {
        rayon::in_place_scope_fifo(|s| {
            s.spawn_fifo(|_s| result = Some(Transaction::zcash_deserialize(reader)))
        })
    });
    result.expect("scope has already finished")
}
```

**Analysis:**
- Uses `block_in_place` to prevent blocking async executor
- Offloads CPU-intensive deserialization to rayon thread pool
- The `.expect()` is safe because scope guarantees completion

**Potential Issues:**
- Blocking other futures on same connection task (documented)
- Could use `spawn_blocking` with owned data instead

**Status:** 🟡 MEDIUM - Consider refactoring for better concurrency

---

## 5. Integer Overflow & Arithmetic Safety

### Finding 5.1: Safe Casts in Codec

**Location:** `zebra-network/src/protocol/external/codec.rs:169,377`

```rust
dst.write_u32::<LittleEndian>(body_length as u32)?;
// ...
let body_len = header_reader.read_u32::<LittleEndian>()? as usize;
```

**Analysis:**
- Cast from `usize` to `u32`: Safe because length checked against `max_len` first
- Cast from `u32` to `usize`: Always safe (u32 fits in usize on all platforms)

**Status:** ✅ SECURE (implicit bounds checking via prior validation)

---

## 6. Timestamp Handling

### Finding 6.1: Timestamp Validation ✅ SECURE

**Location:** `zebra-network/src/protocol/external/codec.rs:509-514`

```rust
timestamp: Utc
    .timestamp_opt(reader.read_i64::<LittleEndian>()?, 0)
    .single()
    .ok_or(Error::Parse(
        "version timestamp is out of range for DateTime",
    ))?,
```

**Analysis:**
- ✅ Properly validates timestamp range
- ✅ Uses `timestamp_opt` which handles out-of-range values
- ✅ Rejects ambiguous timestamps

**Status:** ✅ SECURE

---

## 7. Unknown Message Handling

### Finding 7.1: Defensive Unknown Command Handling ✅ SECURE

**Location:** `zebra-network/src/protocol/external/codec.rs:462-474`

```rust
_ => {
    let command_string = String::from_utf8_lossy(&command);
    debug!(?command, %command_string, "unknown message command from peer");
    return Ok(None);
}
```

**Analysis:**
- ✅ Unknown messages are logged but not fatal
- ✅ Prevents DoS via connection closure
- ✅ Resilient against protocol fuzzing

**Rationale:** Connections are unauthenticated, so closing on unknown messages would enable attacks

**Status:** ✅ SECURE - Good defensive design

---

## 8. Checksum Verification

### Finding 8.1: Message Integrity ✅ SECURE

**Location:** `zebra-network/src/protocol/external/codec.rs:434-438`

```rust
if checksum != sha256d::Checksum::from(&body[..]) {
    return Err(Parse(
        "supplied message checksum does not match computed checksum",
    ));
}
```

**Analysis:**
- ✅ Full message body checksummed
- ✅ Verification before processing
- ✅ Prevents corruption and detects tampering

**Status:** ✅ SECURE

---

## Priority Action Items

### Immediate (Within 1 Week)

1. **🔴 Fix cryptographic deserialization unwraps** (`serde_helpers.rs`)
   - Replace all `.unwrap()` with proper error handling
   - Add fuzzing for malformed cryptographic data
   - Test with invalid point encodings

### Short Term (Within 1 Month)

2. **🟡 Audit FFI callback error handling** (`zebra-script`)
   - Document safety of random sighash workaround
   - Consider upstream libzcash_script improvements
   - Expand test coverage for error paths

3. **🟡 Review deserialization threading model** (`codec.rs`)
   - Consider owned-data spawn_blocking approach
   - Profile to ensure no performance regression
   - Document concurrency model more clearly

### Medium Term (Within 3 Months)

4. **Run comprehensive fuzzing campaign**
   - Fuzz all network message parsers
   - Fuzz cryptographic deserialization
   - Fuzz transaction and block parsing
   - Target: 72+ hours per harness with coverage tracking

5. **Add symbolic execution for unsafe paths**
   - Identify all `unsafe` blocks across codebase
   - Use KLEE or similar to verify safety invariants
   - Document safety proofs

---

## Fuzzing Recommendations

### Recommended Fuzzing Targets (Priority Order)

1. **Network message codec** (`zebra-network/src/protocol/external/codec.rs`)
   - Fuzz all message type parsers
   - Test with malformed headers, invalid lengths, bad checksums
   - Run with ASAN, UBSAN, MSAN

2. **Cryptographic deserialization** (`zebra-chain/src/serialization/`)
   - Fuzz point deserialization with invalid encodings
   - Test all ZcashDeserialize implementations
   - Critical for preventing panics

3. **Script verification** (`zebra-script/src/lib.rs`)
   - Fuzz scriptSig/scriptPubKey combinations
   - Test sighash calculation edge cases
   - Verify P2SH redeem script extraction

4. **Transaction/block parsing** (via codec)
   - Fuzz with protocol-level transaction messages
   - Test consensus-critical validation
   - Verify sigop counting logic

### Fuzzing Infrastructure

**Recommended Setup:**
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run with sanitizers
RUSTFLAGS="-Z sanitizer=address" cargo +nightly fuzz run codec_fuzzer

# Continuous fuzzing (minimize finding manual)
cargo fuzz run --release codec_fuzzer -- -max_total_time=259200  # 72 hours
```

**Coverage Tracking:**
```bash
# Use llvm-source-based coverage
cargo fuzz coverage codec_fuzzer
llvm-cov show target/*/release/codec_fuzzer -format=html > coverage.html
```

---

## Testing Recommendations

### Unit Tests Needed

1. **Cryptographic error handling**
   - Test invalid point encodings for all curve types
   - Verify proper error propagation (not panics)

2. **Message length limits**
   - Test at boundary conditions (max_len, max_len+1)
   - Verify memory usage stays bounded

3. **Concurrency stress tests**
   - Already recommended: 200-connection TSAN tests
   - Duration: 21 days per version (as originally planned)

### Integration Tests Needed

1. **Malformed message handling**
   - Send invalid messages to running node
   - Verify graceful rejection without crashes

2. **Resource exhaustion resistance**
   - Attempt memory exhaustion via large messages
   - Verify rate limiting and connection management

---

## Conclusion

**Overall Security Posture:** 🟢 GOOD

The Zebra codebase demonstrates strong security practices:
- ✅ Comprehensive input validation on network boundaries
- ✅ Proper memory bounds checking
- ✅ DoS resistance through message size limits
- ✅ Good defensive programming (unknown message handling)

**Critical Issues:** 1 (cryptographic deserialization unwraps)

**Medium Issues:** 2 (FFI error handling, threading model)

**Positive Findings:**
- Network codec is well-protected against DoS
- Input validation is thorough and consistent
- Code follows Rust safety best practices in most areas
- Security comments explain rationale for designs

**Next Steps:**
1. Fix the cryptographic deserialization unwraps immediately
2. Set up fuzzing infrastructure for continuous testing
3. Run TSAN concurrency tests as originally planned
4. Document all FFI safety invariants

---

## Appendix A: Fuzzing Setup Script

```bash
#!/bin/bash
# Zebra Security Fuzzing Setup

set -e

echo "Setting up Zebra fuzzing environment..."

# Install fuzzing tools
cargo install cargo-fuzz
rustup install nightly

# Create fuzz targets directory
mkdir -p fuzz/fuzz_targets

# Network codec fuzzer
cat > fuzz/fuzz_targets/codec.rs << 'EOF'
#![no_main]
use libfuzzer_sys::fuzz_target;
use bytes::BytesMut;
use tokio_util::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);
    let mut codec = zebra_network::protocol::external::Codec::builder()
        .for_network(&zebra_chain::parameters::Network::Mainnet)
        .finish();
    
    let _ = codec.decode(&mut buf);
});
EOF

# Cryptographic deserialization fuzzer
cat > fuzz/fuzz_targets/crypto_deser.rs << 'EOF'
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() == 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(data);
        
        // Test all point deserialization paths
        let _ = jubjub::AffinePoint::from_bytes(bytes);
        let _ = halo2::pasta::pallas::Affine::from_bytes(&bytes);
        // Add more as needed
    }
});
EOF

echo "Fuzzing setup complete!"
echo "Run: cargo +nightly fuzz run codec"
```

---

## Appendix B: Security Checklist for Code Reviews

Use this checklist when reviewing Zebra PRs:

### Memory Safety
- [ ] No `.unwrap()` or `.expect()` on untrusted input
- [ ] All allocations bounded by constants
- [ ] No unbounded loops over attacker-controlled data
- [ ] Arithmetic uses checked/saturating operations

### Network Input Validation  
- [ ] Message length checked before allocation
- [ ] String fields have maximum lengths
- [ ] Collection sizes validated against MAX constants
- [ ] Unknown/malformed input handled gracefully

### Concurrency
- [ ] CPU-intensive work uses `spawn_blocking` or `block_in_place`
- [ ] All external waits have timeouts
- [ ] Shared state uses appropriate synchronization
- [ ] No data races possible (verify with TSAN)

### Cryptography
- [ ] All point deserialization has error handling
- [ ] Signature verification failures don't panic
- [ ] Constant-time operations where required

### FFI/Unsafe
- [ ] Safety invariants documented
- [ ] Pointer lifetimes are correct
- [ ] No undefined behavior possible

---

**Report Generated:** 2026-05-14  
**Next Review:** Recommend quarterly security audits  
**Fuzzing Status:** Setup provided, execution pending
