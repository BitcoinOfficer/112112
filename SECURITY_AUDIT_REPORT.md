# Zebra Network Attack Surface Security Audit

**Audit Date:** 2026-05-14
**Scope:** Network-facing code, deserialization paths, and consensus-critical logic
**Method:** Manual code review with focus on common vulnerability patterns

## Executive Summary

This audit examined Zebra's network attack surface, focusing on P2P message handling, deserialization logic, and consensus-critical validation. The codebase demonstrates strong security practices with multiple defense-in-depth mechanisms. Several areas for improvement were identified, categorized by severity.

## Attack Surface Overview

### Primary Entry Points

1. **P2P Network Protocol** (`zebra-network/`)
   - Message deserialization via `Codec::decode()` 
   - 18 distinct message types (version, verack, ping, pong, reject, addr, getblocks, inv, getheaders, headers, getdata, block, tx, notfound, mempool, filterload, filteradd, filterclear)
   - Maximum message size: 2MB (`MAX_PROTOCOL_MESSAGE_LEN`)

2. **Block Deserialization** (`zebra-chain/src/block/`)
   - Handled via `Block::zcash_deserialize()`
   - Deserialized on dedicated thread pool (rayon) to prevent DoS

3. **Transaction Deserialization** (`zebra-chain/src/transaction/`)
   - Complex structure with multiple versions (V1-V5)
   - Shielded pool data (Sprout, Sapling, Orchard)
   - Handled on dedicated thread pool

4. **Script Verification** (`zebra-script/`)
   - FFI boundary to zcashd's C++ code
   - Potential for memory safety issues at FFI boundary

5. **RPC Interface** (`zebra-rpc/`)
   - JSON-RPC and gRPC endpoints
   - Authenticated vs unauthenticated endpoints

## Findings by Severity

### CRITICAL

None identified. The codebase employs robust defenses against critical vulnerabilities.

### HIGH

#### H1: Potential Integer Overflow in Difficulty Calculations

**Location:** `zebra-chain/src/work/difficulty.rs:211`

```rust
let exponent = i32::try_from(self.0 >> PRECISION).expect("fits in i32") - OFFSET;
```

**Issue:** While `try_from` is used, the subtraction with `OFFSET` could underflow if the value is smaller than `OFFSET`. The panic message suggests this is an invariant, but untrusted network data flows through this code path.

**Impact:** Node crash via panic if malicious block header triggers the panic.

**Recommendation:**
- Replace `expect()` with proper error handling that returns `SerializationError`
- Add validation before the calculation to ensure the value is within valid range
- Add fuzzing targets specifically for difficulty header parsing

#### H2: Unconstrained Memory Growth in AddrV2 Parsing

**Location:** `zebra-network/src/protocol/external/codec.rs:634-650`

**Issue:** The `read_addrv2()` function filters out unsupported address types after deserialization. If an attacker sends `MAX_ADDRS_IN_MESSAGE` addresses of an unsupported type, memory is allocated then immediately discarded.

**Impact:** Memory pressure attack, though limited by `MAX_ADDRS_IN_MESSAGE` (1000 addresses).

**Recommendation:**
- Implement early filtering during deserialization to avoid allocating memory for unsupported address types
- Add metrics for dropped addresses to detect abuse

### MEDIUM

#### M1: Excessive `.expect()` Usage in Non-Test Code

**Locations:** Multiple, including:
- `zebra-chain/src/work/difficulty.rs:471, 477`
- `zebra-network/src/protocol/internal/response.rs:103`

**Issue:** Several `.expect()` calls exist in production code paths. While many document invariants correctly, they represent potential crash vectors if invariants are violated by edge cases.

**Impact:** Potential node crashes via panic.

**Recommendation:**
- Audit all `.expect()` calls in non-test code
- Convert to proper error propagation where data comes from untrusted sources
- Add fuzzing coverage for these code paths

#### M2: Timestamp Validation Gap in Version Message

**Location:** `zebra-network/src/protocol/external/codec.rs:509-514`

```rust
timestamp: Utc
    .timestamp_opt(reader.read_i64::<LittleEndian>()?, 0)
    .single()
    .ok_or(Error::Parse("version timestamp is out of range for DateTime"))?
```

**Issue:** While out-of-range timestamps are rejected, there's no validation for timestamps far in the future or past. Malicious peers could send timestamps thousands of years in the future.

**Impact:** Potential issues with timestamp-based logic elsewhere in the codebase.

**Recommendation:**
- Add bounds checking: reject timestamps more than 2 hours in the future
- Reject timestamps before 2008-10-31 (Bitcoin genesis)
- Add metrics for timestamp skew

#### M3: Unvalidated String Lengths in Reject Messages

**Location:** `zebra-network/src/protocol/external/codec.rs:559-612`

**Issue:** While `MAX_REJECT_MESSAGE_LENGTH` and `MAX_REJECT_REASON_LENGTH` are enforced, there's no validation of string content (e.g., non-printable characters, control characters).

**Impact:** Log injection attacks if reject messages are logged without sanitization.

**Recommendation:**
- Sanitize reject message strings before logging
- Strip control characters and non-printable bytes
- Consider using `debug_assert!` to validate UTF-8 correctness in test builds

#### M4: No Rate Limiting on FilterLoad Messages

**Location:** `zebra-network/src/protocol/external/codec.rs:733-759`

**Issue:** While Zebra ignores bloom filter messages, it still deserializes them. An attacker could flood the node with large filterload messages (up to 36,000 bytes each) to consume CPU and memory.

**Impact:** CPU and memory exhaustion attack.

**Recommendation:**
- Add per-peer rate limiting for ignored message types
- Consider rejecting these messages entirely during handshake by advertising lack of support
- Add metrics for ignored message frequency

### LOW

#### L1: Extra Bytes in Messages Logged at Debug Level

**Location:** `zebra-network/src/protocol/external/codec.rs:486-489`

**Issue:** Extra bytes at the end of messages are logged at debug level. This is intentional for forward compatibility, but could mask deserialization bugs.

**Impact:** Potential for bugs to go unnoticed.

**Recommendation:**
- Add metrics for extra bytes by message type
- Implement alerting if extra bytes exceed expected patterns
- Document which message types are expected to have extra bytes in which protocol versions

#### L2: Checksum Validation Timing

**Location:** `zebra-network/src/protocol/external/codec.rs:434-438`

**Issue:** Checksum validation happens after full message deserialization, not before. If deserialization is CPU-intensive, this allows DoS before checksum check.

**Impact:** Minor DoS opportunity.

**Recommendation:**
- Move checksum validation to occur before deserialization
- This requires buffering the message body, but prevents wasted CPU on corrupted messages

#### L3: No Input Validation for FilterAdd Data

**Location:** `zebra-network/src/protocol/external/codec.rs:761-769`

**Issue:** The data in `FilterAdd` messages is read but not validated. While the message is ignored, invalid data could expose deserialization bugs.

**Impact:** Potential for bugs if FilterAdd messages are ever used.

**Recommendation:**
- Add validation even for ignored message types
- Reject obviously invalid data patterns

## Defensive Mechanisms Present (Strengths)

### Memory Safety
1. **TrustedPreallocate trait** bounds vector allocation based on message size limits
2. **External count validation** prevents allocation bombs in `zcash_deserialize_external_count()`
3. **Explicit byte count limits** for strings, filters, and data fields
4. **Arc-based sharing** reduces unnecessary clones for large structures

### DoS Prevention
1. **Message size limits** (`MAX_PROTOCOL_MESSAGE_LEN = 2MB`)
2. **Collection size limits** (`MAX_ADDRS_IN_MESSAGE = 1000`, `MAX_HEADERS_PER_MESSAGE = 160`)
3. **CPU-intensive operations** (block/tx deserialization) executed on dedicated thread pools
4. **Network magic validation** rejects messages from wrong network immediately
5. **Checksum validation** prevents processing of corrupted messages

### Input Validation
1. **String length limits** for user agents, reject messages
2. **Version matching** for protocol-dependent messages
3. **Compact size validation** prevents excessive allocations
4. **Unknown message handling** gracefully ignores unknown commands

## Recommended Security Improvements

### 1. Comprehensive Fuzzing Infrastructure

**Priority:** HIGH

Implement continuous fuzzing for:
- All message type deserializers (18 message types)
- Block header parsing
- Transaction parsing (all versions)
- Compact size edge cases
- FFI boundaries in zebra-script

**Implementation:**
```rust
// Example fuzzing harness for message codec
#[cfg(fuzzing)]
pub mod fuzz {
    use super::*;
    
    pub fn fuzz_message_decode(data: &[u8]) {
        let mut codec = Codec::builder()
            .for_network(&Network::Mainnet)
            .finish();
        let mut bytes = BytesMut::from(data);
        let _ = codec.decode(&mut bytes);
    }
}
```

### 2. Property-Based Testing Expansion

**Priority:** MEDIUM

Expand property tests for:
- Round-trip serialization for all message types
- Invariant validation (e.g., timestamps, difficulty values)
- Collection size limits
- String encoding correctness

### 3. Runtime Verification

**Priority:** MEDIUM

Add runtime checks for:
- Message processing time (detect CPU exhaustion)
- Memory usage per connection (detect memory exhaustion)
- Message rate per peer (detect flooding)
- Unusual message patterns (detect scanning)

**Implementation:**
```rust
// Per-peer metrics
struct PeerMetrics {
    messages_per_second: RateLimiter,
    bytes_per_second: RateLimiter,
    last_message_time: Instant,
    suspicious_patterns: Counter,
}
```

### 4. Automated Branch Coverage Analysis

**Priority:** LOW

While 100% branch coverage is infeasible for a project of this scale, implement:
- Coverage tracking in CI for network-facing modules
- Coverage ratcheting (prevent coverage from decreasing)
- Identification of uncovered error paths

**Implementation:**
```bash
# In CI
cargo llvm-cov --html --output-dir coverage \
    --package zebra-network \
    --package zebra-chain \
    --package zebra-script
```

### 5. Formal Verification for Critical Functions

**Priority:** LOW

Apply formal methods to critical invariants:
- Difficulty adjustment calculations
- Compact size bounds
- Collection size limits

Consider using:
- Kani for bounded verification
- MIRAI for abstract interpretation
- Prusti for Rust-specific verification

## Test Coverage Analysis

### Current Coverage Strengths
- Property tests for message serialization (`zebra-network/src/protocol/external/tests/prop.rs`)
- Vector tests for known good/bad inputs (`zebra-network/src/protocol/external/tests/vectors.rs`)
- Preallocate tests for DoS vectors (`zebra-network/src/protocol/external/tests/preallocate.rs`)

### Coverage Gaps
- Limited testing of message sequences (stateful behavior)
- No tests for maximum-size messages
- Insufficient testing of error recovery paths
- No tests for concurrent message processing

## Appendix A: Security-Critical Code Paths

### P2P Message Decode Path
1. `Codec::decode()` reads message header
2. Validates network magic
3. Validates body length
4. Reads body and validates checksum
5. Dispatches to type-specific deserializer
6. Returns parsed `Message` enum

### Block Validation Path
1. `Message::Block` received from peer
2. Deserialized on rayon thread pool
3. Passed to consensus verification
4. Equihash solution verified
5. Difficulty threshold validated
6. Transactions verified
7. Block committed to state

### Transaction Validation Path
1. `Message::Tx` received from peer
2. Deserialized on rayon thread pool
3. Added to mempool pending verification
4. Transparent scripts verified via FFI
5. Shielded proofs verified
6. Added to mempool or rejected

## Appendix B: Threat Model

### In-Scope Threats
- Malicious peers sending crafted P2P messages
- Resource exhaustion attacks (CPU, memory, disk, bandwidth)
- Consensus bugs via edge-case inputs
- Crash-inducing inputs (panics, unwraps)
- Information disclosure via timing or error messages

### Out-of-Scope Threats
- Eclipse attacks (network-layer)
- BGP hijacking
- Physical access to node
- Compromise of dependencies
- Side-channel attacks on cryptographic operations

## Appendix C: Comparison with zcashd

Zebra's security posture compared to zcashd:

**Advantages:**
- Memory safety by default (Rust vs C++)
- Explicit bounds checking via types
- Modern async architecture prevents blocking
- Cleaner separation of concerns

**Potential Concerns:**
- Smaller deployment base (less battle-tested)
- Different FFI boundary for script verification
- Different database format (RocksDB vs LevelDB)

## Conclusion

Zebra demonstrates mature security practices for a consensus-critical cryptocurrency node implementation. The codebase employs defense-in-depth with multiple layers of input validation, resource limits, and error handling. The identified issues are primarily focused on hardening against edge cases and improving observability.

**Recommended Action Items (Priority Order):**
1. Address HIGH findings (H1, H2)
2. Implement fuzzing infrastructure
3. Address MEDIUM findings (M1-M4)
4. Expand property-based testing
5. Implement runtime verification metrics
6. Address LOW findings (L1-L3)

**Overall Risk Assessment:** LOW

The Zebra codebase is suitable for production use with the recommended improvements implemented over time. No critical vulnerabilities requiring immediate remediation were identified.
