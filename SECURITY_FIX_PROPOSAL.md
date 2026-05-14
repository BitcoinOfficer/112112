# Security Fix Proposal: Cryptographic Deserialization Safety

**Issue:** CRITICAL - Panic on malformed cryptographic data  
**Status:** Requires team discussion before implementation  
**Risk Level:** 🔴 HIGH - DoS via crafted JSON/Serde inputs

---

## Problem Statement

The `serde_helpers.rs` module uses `.unwrap()` in multiple `From` implementations for cryptographic types. This can cause panics when deserializing malformed data.

### Affected Code

File: `zebra-chain/src/serialization/serde_helpers.rs`

All `From` implementations unwrap deserialization results:

```rust
impl From<AffinePoint> for jubjub::AffinePoint {
    fn from(local: AffinePoint) -> Self {
        jubjub::AffinePoint::from_bytes(local.bytes).unwrap()  // ❌ Can panic!
    }
}
```

### Attack Scenario

1. **JSON RPC Input:** Attacker sends malformed JSON with invalid point encoding
2. **Serde Deserialization:** Serde calls `From::from()` to convert bytes to point
3. **Panic:** Invalid bytes cause `.unwrap()` to panic
4. **Node Crash:** Depending on panic handling, node may crash or become unresponsive

### Currently Affected Types

- `jubjub::AffinePoint` (line 13)
- `jubjub::Fq` (line 26)
- `pallas::Affine` (line 39)
- `pallas::Scalar` (line 52)
- `pallas::Base` (line 65)
- `sapling_crypto::value::ValueCommitment` (line 78)
- `sapling_crypto::note::ExtractedNoteCommitment` (line 91)
- `sapling_crypto::Node` (line 110)

---

## Why This Exists

### Context

Zebra has **two separate deserialization paths**:

1. **Wire Format (Binary)**: Uses `ZcashDeserialize` trait
   - ✅ Properly handles errors
   - Used for network protocol messages
   - Example: `sapling_crypto::value::ValueCommitment::zcash_deserialize()` properly returns `Result`

2. **Human-Readable (JSON)**: Uses Serde with custom helpers
   - ❌ Currently uses `unwrap()`
   - Used for: RPC responses, cached state, debugging
   - This is the vulnerable path

### Design Rationale

The `From` trait doesn't support fallible conversion (`From` returns `T`, not `Result<T, E>`).

Serde's derive macros use `From` for the `#[serde(with = "...")]` pattern, which is why these helpers exist.

---

## Risk Assessment

### Exploitation Difficulty

**MEDIUM-HIGH** for production nodes:

- Requires access to JSON deserialization path
- Most network protocol uses binary `ZcashDeserialize` (safe)
- Risk mainly from:
  - RPC endpoints accepting JSON
  - Cached state loaded from disk (if compromised)
  - Testing/debugging tools

### Impact

**HIGH**:
- Node panic → service disruption
- Repeated attacks → DoS
- May affect consensus if state cache is corrupted

### Probability

**LOW-MEDIUM**:
- JSON deserialization is less common than binary
- Requires crafting specific invalid point encodings
- Most inputs go through binary deserialization first

---

## Proposed Solutions

### Solution 1: Use TryFrom (RECOMMENDED)

Replace `From` with `TryFrom` for fallible conversions.

**Changes Required:**

```rust
// serde_helpers.rs
impl TryFrom<AffinePoint> for jubjub::AffinePoint {
    type Error = &'static str;
    
    fn try_from(local: AffinePoint) -> Result<Self, Self::Error> {
        jubjub::AffinePoint::from_bytes(local.bytes)
            .into_option()
            .ok_or("invalid jubjub::AffinePoint encoding")
    }
}
```

**Serde Integration:**

Serde doesn't automatically use `TryFrom`, so we need custom deserialize functions:

```rust
#[derive(Deserialize, Serialize)]
#[serde(remote = "jubjub::AffinePoint")]
pub struct AffinePoint {
    #[serde(getter = "jubjub::AffinePoint::to_bytes")]
    bytes: [u8; 32],
}

impl From<AffinePoint> for jubjub::AffinePoint {
    fn from(local: AffinePoint) -> Self {
        Self::try_from(local)
            .expect("serde validation should ensure valid bytes")
    }
}

// Add validation during deserialization
pub fn deserialize<'de, D>(deserializer: D) -> Result<jubjub::AffinePoint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let bytes = <[u8; 32]>::deserialize(deserializer)?;
    jubjub::AffinePoint::from_bytes(bytes)
        .into_option()
        .ok_or_else(|| D::Error::custom("invalid jubjub::AffinePoint encoding"))
}
```

**Pros:**
- ✅ Proper error handling
- ✅ Serde errors are user-friendly
- ✅ No panic possible

**Cons:**
- Requires rewriting all serde helpers
- More verbose code
- Need to update all usage sites

### Solution 2: Validate in Deserialize

Add validation during the serde deserialization step before `From` is called.

**Pros:**
- ✅ Catches errors early
- ✅ Keeps `From` trait usage

**Cons:**
- Requires custom deserialize for each field
- Still has `.expect()` in `From` (but should never fire)

### Solution 3: Document as Feature, Not Bug

Accept the current behavior if analysis shows JSON deserialization is only used in trusted contexts.

**Requirements:**
1. Audit all code paths that use JSON deserialization
2. Confirm no untrusted input reaches these paths
3. Add explicit comments explaining safety
4. Add tests that verify panic behavior

**Pros:**
- ✅ No code changes needed
- ✅ May be acceptable if risk is truly low

**Cons:**
- ❌ Risk of future code introducing vulnerability
- ❌ Defensive programming suggests fixing anyway
- ❌ Fails secure-by-default principle

---

## Implementation Plan (Solution 1 - Recommended)

### Phase 1: Audit Usage (Week 1)

1. **Find all JSON deserialization entry points:**
   ```bash
   rg "from_str|from_reader|from_slice" --type rust zebra-rpc/
   rg "Deserialize.*for.*" --type rust zebra-chain/
   ```

2. **Classify each by trust level:**
   - UNTRUSTED: Public RPC, user input
   - TRUSTED: Internal state, test fixtures

3. **Prioritize fixes:**
   - Critical: Public-facing RPC endpoints
   - High: State cache loading
   - Medium: Internal APIs
   - Low: Test-only code

### Phase 2: Implement TryFrom (Week 2)

1. **Add TryFrom implementations:**

```rust
// zebra-chain/src/serialization/serde_helpers.rs

use std::convert::TryFrom;

// For each type, add TryFrom:
impl TryFrom<AffinePoint> for jubjub::AffinePoint {
    type Error = &'static str;
    fn try_from(local: AffinePoint) -> Result<Self, Self::Error> {
        jubjub::AffinePoint::from_bytes(local.bytes)
            .into_option()
            .ok_or("invalid jubjub::AffinePoint bytes")
    }
}

impl TryFrom<Fq> for jubjub::Fq {
    type Error = &'static str;
    fn try_from(local: Fq) -> Result<Self, Self::Error> {
        jubjub::Fq::from_bytes(&local.bytes)
            .into_option()
            .ok_or("invalid jubjub::Fq bytes")
    }
}

// ... repeat for all 8 types
```

2. **Add custom Serde deserialize functions:**

```rust
pub mod affine_point {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(point: &jubjub::AffinePoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&point.to_bytes())
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<jubjub::AffinePoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        jubjub::AffinePoint::from_bytes(bytes)
            .into_option()
            .ok_or_else(|| D::Error::custom("invalid jubjub::AffinePoint encoding"))
    }
}
```

3. **Update usage sites:**

```rust
// Old:
#[derive(Deserialize, Serialize)]
pub struct EphemeralPublicKey(
    #[serde(with = "serde_helpers::AffinePoint")] 
    pub(crate) jubjub::AffinePoint,
);

// New:
#[derive(Deserialize, Serialize)]
pub struct EphemeralPublicKey(
    #[serde(with = "serde_helpers::affine_point")] 
    pub(crate) jubjub::AffinePoint,
);
```

### Phase 3: Testing (Week 3)

1. **Add malformed data tests:**

```rust
#[cfg(test)]
mod malformed_tests {
    use super::*;
    
    #[test]
    fn test_invalid_affine_point_json() {
        let invalid_json = r#"{"bytes": [255, 255, 255, /* ... */, 255]}"#;
        let result: Result<EphemeralPublicKey, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        // Should NOT panic!
    }
    
    // Test all 8 types with various invalid encodings
}
```

2. **Fuzzing:**

```rust
// fuzz/fuzz_targets/crypto_serde.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use zebra_chain::sapling::keys::EphemeralPublicKey;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize arbitrary bytes
    let _ = serde_json::from_slice::<EphemeralPublicKey>(data);
    // Must not panic!
});
```

3. **Integration tests:**
   - Verify RPC endpoints reject malformed data gracefully
   - Test state cache recovery with corrupted data

### Phase 4: Deployment (Week 4)

1. **Code review:** Security-focused review of changes
2. **Run full test suite:** Ensure no regressions
3. **Canary testing:** Deploy to test network first
4. **Mainnet rollout:** Standard release process

---

## Testing Strategy

### Unit Tests

```rust
#[test]
fn test_all_invalid_point_encodings() {
    // All zeros
    let zeros = [0u8; 32];
    assert!(jubjub::AffinePoint::from_bytes(zeros).is_none());
    
    // All ones (very unlikely to be valid)
    let ones = [255u8; 32];
    assert!(jubjub::AffinePoint::from_bytes(ones).is_none());
    
    // Non-canonical field element
    // ...
}
```

### Fuzzing Targets

**Target 1: JSON Deserialization**
- Input: Arbitrary JSON data
- Target: All types using serde_helpers
- Duration: 72 hours minimum
- Sanitizers: ASAN, UBSAN

**Target 2: Direct Point Deserialization**
- Input: 32-byte arrays
- Target: All cryptographic point types
- Check: No panics, proper error propagation

### Integration Tests

**Test RPC Endpoints:**
```bash
# Send malformed transaction to RPC
curl -X POST http://localhost:8232 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "sendrawtransaction",
    "params": ["<malformed_hex_with_invalid_points>"]
  }'

# Expected: HTTP 400 or 500, not connection close
```

---

## Rollout Considerations

### Breaking Changes

**Potentially breaking:**
- Error messages change (from panic to serde error)
- API behavior changes (return error instead of panic)

**Mitigation:**
- This is internal serialization format
- No on-chain consensus impact
- May affect RPC clients that expect panics (unlikely)

### Performance Impact

**Expected: Negligible**
- Validation already happens in underlying libraries
- Just changing panic to error return
- No additional computation

**Benchmark anyway:**
```bash
cargo bench --bench serde_crypto
```

### Documentation Updates

Update docs to clarify:
1. Wire format (binary) vs JSON format validation
2. Error handling for malformed cryptographic data
3. RPC client expectations

---

## Alternative: Immediate Mitigation

If full fix takes too long, immediate mitigation:

### Option A: Add Panic Handlers

```rust
// In RPC server initialization:
std::panic::set_hook(Box::new(|panic_info| {
    error!("Panic during JSON deserialization: {}", panic_info);
    // Log, but don't crash the server
}));
```

**Pros:** Quick to implement  
**Cons:** Doesn't actually fix the issue, just contains it

### Option B: Input Validation Layer

Add validation before deserialization:

```rust
fn validate_json_crypto_data(json: &str) -> Result<(), Error> {
    // Pre-parse and validate all hex-encoded crypto data
    // Reject before deserialization
}
```

**Pros:** Defense in depth  
**Cons:** Duplicates validation logic

---

## Recommendation

**Implement Solution 1 (TryFrom + Custom Deserialize)**

**Rationale:**
1. Proper error handling is Zebra's standard practice
2. Defensive programming: even low-probability bugs should be fixed
3. Future-proofs against new code paths that use JSON deserialization
4. Aligns with Rust best practices (fallible operations should return Result)
5. Relatively low effort (~3-4 weeks total)

**Priority:** HIGH (not urgent, but should be in next release)

**Next Steps:**
1. ✅ Document the issue (this document)
2. ⏳ Discuss with team (get consensus on approach)
3. ⏳ Create GitHub issue
4. ⏳ Implement fix
5. ⏳ Comprehensive testing
6. ⏳ Security review
7. ⏳ Deploy in next release

---

## Questions for Team Discussion

1. **Scope:** Should we fix all 8 types or prioritize based on usage?
2. **Timeline:** Is 3-4 week timeline acceptable, or do we need faster mitigation?
3. **Testing:** What level of fuzzing is required before merging?
4. **Breaking:** Are there any API compatibility concerns I'm missing?
5. **Alternatives:** Is there a simpler approach that still provides safety?

---

## References

- Serde error handling: https://serde.rs/error-handling.html
- Rust TryFrom trait: https://doc.rust-lang.org/std/convert/trait.TryFrom.html
- Current code: `zebra-chain/src/serialization/serde_helpers.rs`
- Binary deserialization (correct): `zebra-chain/src/sapling/commitment.rs:89-99`

---

**Document Status:** DRAFT - Awaiting team review  
**Author:** Security Audit Analysis  
**Date:** 2026-05-14
