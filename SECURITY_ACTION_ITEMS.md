# Zebra Security Action Items

**Generated**: 2026-05-14  
**Priority**: IMMEDIATE REVIEW REQUIRED

---

## Critical Action Items

### 1. PANIC-FREE GUARANTEE VERIFICATION

**Priority**: 🔴 CRITICAL  
**File**: `zebra-network/src/protocol/external/codec.rs`

#### Issue 1.1: Assert in Addr Message Encoding
**Location**: Line 276-278
```rust
assert!(
    addrs.len() <= constants::MAX_ADDRS_IN_MESSAGE,
    "unexpectedly large Addr message: greater than MAX_ADDRS_IN_MESSAGE addresses"
);
```

**Risk**: Low (output path only)  
**Action Required**:
- [ ] Verify that all callers enforce `MAX_ADDRS_IN_MESSAGE` limit
- [ ] Search codebase for all construction sites of `Message::Addr`
- [ ] Add test case that attempts to create oversized Addr message
- [ ] Consider replacing with early return if this is a DoS vector

**Command to investigate**:
```bash
rg "Message::Addr" --type rust -A 5 -B 5
rg "MAX_ADDRS_IN_MESSAGE" --type rust
```

#### Issue 1.2: Unwrap in Debug Formatting
**Location**: Line 387 in debug output
```rust
.unwrap()
```

**Risk**: Very Low (logging code only)  
**Action Required**:
- [ ] Verify this unwrap is in `fmt::Debug` or trace! macro only
- [ ] If in hot path, replace with `.unwrap_or_default()` or similar
- [ ] Add comment explaining why unwrap is safe

#### Issue 1.3: Expect After Thread Scope
**Locations**: Lines 796, 817
```rust
result.expect("scope has already finished")
```

**Risk**: Very Low (should be unreachable)  
**Action Required**:
- [ ] Review rayon scope semantics to confirm this is impossible
- [ ] Add test that verifies result is always Some
- [ ] Consider defensive programming: use unwrap_or_else with error logging

### 2. FFI BOUNDARY SECURITY AUDIT

**Priority**: 🔴 CRITICAL  
**File**: `zebra-script/src/lib.rs`

#### Issue 2.1: Unsafe FFI to C++ zcash_script
**Locations**: Lines 68-76, 179-266

**Current Implementation**:
```rust
let interpreter = get_interpreter(&calculate_sighash, lock_time, is_final);
interpreter
    .verify_callback(&script, flags)
    .map_err(|(_, e)| Error::from(e))
```

**Action Required**:
- [ ] **MANUAL AUDIT**: Review zcash_script C++ library for memory safety
- [ ] Run Valgrind/ASan on script verification paths
- [ ] Fuzz the FFI boundary with malformed scripts
- [ ] Document all assumptions about C++ library behavior
- [ ] Verify callback mechanism cannot cause use-after-free
- [ ] Test with maximum-complexity scripts

**Fuzzing Target**:
```rust
// Create fuzzing harness for CachedFfiTransaction::is_valid()
#[cfg(fuzzing)]
mod fuzz {
    use super::*;
    
    pub fn fuzz_script_verification(data: &[u8]) {
        // Deserialize transaction from fuzzer input
        // Call is_valid() on all inputs
        // Monitor for crashes, hangs, memory leaks
    }
}
```

#### Issue 2.2: Random Sighash Workaround
**Location**: Lines 235-254

**Concern**: Error handling via random values instead of proper error propagation

**Action Required**:
- [ ] Document why libzcash_script API doesn't allow error propagation
- [ ] File upstream issue to fix callback API
- [ ] Verify cryptographic soundness of random value approach
- [ ] Add test cases for all error conditions
- [ ] Monitor for any cases where valid signature verifies against random hash

### 3. COMPREHENSIVE PANIC AUDIT

**Priority**: 🟠 HIGH  
**Scope**: Entire codebase

**Action Required**:
- [ ] Run: `rg "unwrap\(\)" --type rust zebra-network/src/ | wc -l`
- [ ] Run: `rg "expect\(" --type rust zebra-network/src/ | wc -l`  
- [ ] Run: `rg "assert!\(" --type rust zebra-network/src/ | wc -l`
- [ ] For each occurrence, verify it cannot be triggered by network input
- [ ] Add comments documenting why each panic is safe
- [ ] Consider `#![deny(clippy::unwrap_used)]` in network-facing modules

**Automated Check**:
```bash
# Find all panics in network code
rg "(unwrap|expect|assert!|panic!|unreachable!)\(" \
   --type rust \
   zebra-network/src/ \
   zebra-chain/src/serialization/ \
   --line-number

# Exclude test code
rg "(unwrap|expect|assert!|panic!|unreachable!)\(" \
   --type rust \
   --glob '!**/tests/**' \
   --glob '!**/*test*.rs' \
   zebra-network/src/ \
   --line-number
```

---

## High Priority Action Items

### 4. FUZZING INFRASTRUCTURE

**Priority**: 🟠 HIGH  
**Timeline**: 1-2 weeks

#### 4.1 Set Up Continuous Fuzzing
**Action Required**:
- [ ] Apply to OSS-Fuzz (Google's free fuzzing service)
- [ ] Create fuzzing harnesses for:
  - Message deserialization (all message types)
  - Block deserialization
  - Transaction deserialization
  - Script verification
  - Compact size parsing
  - Address parsing (v1 and v2)
- [ ] Set up local fuzzing with cargo-fuzz
- [ ] Run initial 48-hour fuzzing campaign
- [ ] Integrate fuzzing into CI (short runs)

#### 4.2 Fuzzing Harness Examples

**File**: `zebra-network/fuzz/fuzz_targets/message_decode.rs`
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use zebra_network::protocol::external::codec::Codec;
use tokio_util::codec::Decoder;
use bytes::BytesMut;

fuzz_target!(|data: &[u8]| {
    let mut codec = Codec::builder().finish();
    let mut buf = BytesMut::from(data);
    let _ = codec.decode(&mut buf);
});
```

**File**: `zebra-chain/fuzz/fuzz_targets/block_deserialize.rs`
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use zebra_chain::block::Block;
use zebra_chain::serialization::ZcashDeserialize;

fuzz_target!(|data: &[u8]| {
    let _ = Block::zcash_deserialize(&data[..]);
});
```

### 5. FORMAL VERIFICATION PILOT

**Priority**: 🟠 HIGH  
**Timeline**: 2-4 weeks

#### 5.1 Install Kani and Run Initial Verification
**Action Required**:
- [ ] Install Kani: `cargo install --locked kani-verifier`
- [ ] Add kani-verifier to dev-dependencies
- [ ] Write verification harnesses for:
  - Message length bounds
  - Allocation limits in deserialization
  - No panics in codec.rs
- [ ] Run verification and document results

#### 5.2 Example Kani Harness

**File**: `zebra-network/src/protocol/external/codec_verification.rs`
```rust
#[cfg(kani)]
mod verification {
    use super::*;
    
    #[kani::proof]
    fn verify_message_length_bounded() {
        let body_len: usize = kani::any();
        let max_len: usize = MAX_PROTOCOL_MESSAGE_LEN;
        
        if body_len <= max_len {
            // Prove that processing this message cannot panic
            // and cannot allocate more than bounded amount
        }
    }
    
    #[kani::proof]
    fn verify_no_integer_overflow_in_allocation() {
        let count: u64 = kani::any();
        let item_size: usize = kani::any();
        
        // Prove that allocation size check prevents overflow
        kani::assume(count <= T::max_allocation());
        // ... verify no overflow in vec allocation
    }
}
```

### 6. DEPENDENCY SECURITY AUDIT

**Priority**: 🟠 HIGH  
**Timeline**: 1 week

**Action Required**:
- [ ] Run `cargo audit` on all dependencies
- [ ] Review unsafe code in critical dependencies:
  - `tokio`, `bytes`, `byteorder`, `chrono`
- [ ] Check for known CVEs in dependency tree
- [ ] Set up automated daily `cargo audit` in CI
- [ ] Consider vendoring critical dependencies

**Commands**:
```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit

# Generate report
cargo audit --json > audit-report.json

# Check specific advisory database
cargo audit --deny warnings
```

---

## Medium Priority Action Items

### 7. RATE LIMITING VERIFICATION

**Priority**: 🟡 MEDIUM  
**Timeline**: 1-2 weeks

**Action Required**:
- [ ] Review peer connection management in `zebra-network/src/peer_set/`
- [ ] Verify per-peer message rate limits exist
- [ ] Test connection exhaustion resistance
- [ ] Verify max concurrent connections enforced
- [ ] Test behavior under message flood
- [ ] Document rate limiting policies

**Test Cases Needed**:
```rust
#[test]
fn test_message_rate_limiting() {
    // Send MAX_MESSAGES_PER_SECOND + 1 messages
    // Verify extra messages are dropped/throttled
}

#[test]
fn test_connection_limit() {
    // Attempt MAX_CONNECTIONS + 1 connections
    // Verify new connections are rejected
}

#[test]
fn test_large_message_handling() {
    // Send multiple MAX_PROTOCOL_MESSAGE_LEN messages
    // Verify node remains responsive
}
```

### 8. SIDE-CHANNEL ANALYSIS

**Priority**: 🟡 MEDIUM  
**Timeline**: 2-4 weeks

**Action Required**:
- [ ] Set up hardware performance counter monitoring (perf, PAPI)
- [ ] Instrument cryptographic operations
- [ ] Measure timing variance for:
  - Signature verification with valid vs invalid signatures
  - Block validation with different block sizes
  - Transaction verification with different input counts
- [ ] Statistical analysis of timing data
- [ ] Test for cache-timing leaks

**Tools Needed**:
- `perf` (Linux)
- `cachegrind` (Valgrind)
- Statistical analysis framework

### 9. INTEGRATION TESTING EXPANSION

**Priority**: 🟡 MEDIUM  
**Timeline**: Ongoing

**Action Required**:
- [ ] Create adversarial test suite with malformed messages:
  - Invalid magic numbers
  - Incorrect checksums
  - Oversized vectors
  - Negative lengths (as CompactSize)
  - Deeply nested structures
  - Maximum-size messages
  - Zero-length messages
  - Truncated messages
- [ ] Test all message types
- [ ] Measure code coverage of network paths
- [ ] Aim for >95% coverage in codec.rs

---

## Low Priority Action Items

### 10. CODE QUALITY IMPROVEMENTS

**Priority**: 🟢 LOW  
**Timeline**: Ongoing

**Action Required**:
- [ ] Add `#![forbid(unsafe_code)]` to zebra-network
- [ ] Add `#![deny(clippy::unwrap_used)]` to network modules
- [ ] Add `#![deny(clippy::expect_used)]` to network modules
- [ ] Increase documentation coverage
- [ ] Add more examples to critical functions
- [ ] Improve error messages

### 11. MONITORING AND OBSERVABILITY

**Priority**: 🟢 LOW  
**Timeline**: 2-4 weeks

**Action Required**:
- [ ] Add metrics for:
  - Messages rejected due to validation failures
  - Panics (if any occur)
  - Deserialization errors by type
  - Oversized message attempts
  - Unknown message types received
- [ ] Set up alerting for anomalies
- [ ] Create dashboard for network security metrics

---

## Investigation Tasks

### INVESTIGATE-1: Complete Allocation Bounds Review

**Files to examine**:
- All implementations of `TrustedPreallocate` trait
- All uses of `Vec::with_capacity()` in network code
- All uses of `zcash_deserialize_external_count()`

**Command**:
```bash
rg "TrustedPreallocate" --type rust -A 3
rg "with_capacity" --type rust zebra-network/ zebra-chain/
rg "zcash_deserialize_external_count" --type rust
```

**Verify**:
- All bounds are based on protocol limits, not attacker input
- No allocations can exceed memory limits
- All counts are validated before allocation

### INVESTIGATE-2: Error Handling Coverage

**Files to examine**:
- All error types in zebra-chain/src/serialization/error.rs
- All error handling in codec.rs
- All Result types in network code

**Command**:
```bash
rg "Result<" --type rust zebra-network/src/protocol/
rg "SerializationError" --type rust
rg "\?" --type rust zebra-network/src/protocol/external/codec.rs | wc -l
```

**Verify**:
- All errors are properly propagated
- No errors are silently ignored
- All error cases have tests

### INVESTIGATE-3: Unsafe Code Complete Audit

**Command**:
```bash
rg "unsafe" --type rust --stats
rg "unsafe" --type rust -A 10 -B 2 > unsafe-code-audit.txt
```

**Verify**:
- Document every unsafe block
- Justify why unsafe is necessary
- Verify safety invariants
- Add safety comments
- Consider safe alternatives

### INVESTIGATE-4: Transaction/Block Deserialization Deep Dive

**Action Required**:
- Read complete implementation of:
  - `Block::zcash_deserialize()`
  - `Transaction::zcash_deserialize()`
  - All helper deserialization functions
- Map all code paths
- Identify all validation checks
- Verify bounds on all fields
- Check for recursive structures
- Analyze complexity bounds

**Priority**: 🟠 HIGH (not done in initial audit)

---

## Testing Checklist

### Test Coverage Requirements

- [ ] All message types have valid parsing tests
- [ ] All message types have invalid input tests
- [ ] All message types have maximum-size tests
- [ ] All message types have minimum-size tests
- [ ] All error paths have tests
- [ ] All validation checks have tests
- [ ] Fuzzing runs continuously
- [ ] Property tests exist for invariants
- [ ] Integration tests cover network protocol
- [ ] Performance tests exist for DoS scenarios

---

## Documentation Requirements

- [ ] Security policy documented in SECURITY.md
- [ ] Threat model documented
- [ ] Trust boundaries documented
- [ ] All unsafe code has safety comments
- [ ] All panics have justification comments
- [ ] Rate limiting policies documented
- [ ] Incident response plan exists
- [ ] Security audit results published (this document)

---

## Metrics to Track

### Security Metrics
- Fuzzing coverage (%)
- Fuzzing crashes found
- Known vulnerabilities (CVEs) in dependencies
- Time to patch security issues
- Number of unsafe blocks
- Number of unwrap/expect in production code

### Quality Metrics
- Test coverage (%)
- Clippy warnings
- Documentation coverage (%)
- Build warnings
- Lines of code
- Cyclomatic complexity

---

## Timeline Summary

| Priority | Action | Timeline | Status |
|----------|--------|----------|--------|
| 🔴 Critical | Panic Audit | 1 week | ⬜ TODO |
| 🔴 Critical | FFI Security Review | 2 weeks | ⬜ TODO |
| 🟠 High | Fuzzing Setup | 1-2 weeks | ⬜ TODO |
| 🟠 High | Formal Verification | 2-4 weeks | ⬜ TODO |
| 🟠 High | Dependency Audit | 1 week | ⬜ TODO |
| 🟡 Medium | Rate Limiting | 1-2 weeks | ⬜ TODO |
| 🟡 Medium | Side-Channel Analysis | 2-4 weeks | ⬜ TODO |
| 🟢 Low | Code Quality | Ongoing | ⬜ TODO |

---

## Contact and Escalation

For security issues found during this audit:

1. **Do not** open public GitHub issues
2. Contact Zebra security team (see SECURITY.md)
3. Follow responsible disclosure process
4. Allow time for patches before public disclosure

---

**Document Status**: DRAFT  
**Last Updated**: 2026-05-14  
**Next Review**: After completion of critical action items
