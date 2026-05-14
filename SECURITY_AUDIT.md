# Zebra Security Audit Report

**Date:** May 14, 2026  
**Scope:** Full codebase security review of the Zebra Zcash full node implementation  
**Auditor:** Zebra Autonomous Dynamic Audit Engine  

---

## Executive Summary

Zebra is a well-engineered Zcash full node implementation in Rust with strong security foundations. The workspace-level `deny(unsafe_code)` lint (with a single, justified exception in `zebra-script`) eliminates entire classes of memory safety vulnerabilities. The codebase demonstrates consistent application of defense-in-depth principles across network parsing, deserialization, and peer management.

This audit identified **0 critical vulnerabilities**, **3 medium-severity findings**, and **8 low-severity/informational findings**. The medium findings relate to potential denial-of-service vectors and a subtle correctness issue in sigop counting.

---

## Audit Methodology

The audit covered the following attack surfaces:

1. **Network Protocol Parsing** (`zebra-network/src/protocol/external/codec.rs`)
2. **Peer Connection Management** (`zebra-network/src/peer/connection.rs`, `handshake.rs`)
3. **Deserialization & Memory Safety** (`zebra-chain/src/serialization/`)
4. **FFI Boundary** (`zebra-script/src/lib.rs`)
5. **RPC Server** (`zebra-rpc/src/server/`, `methods.rs`)
6. **Consensus Verification** (`zebra-consensus/`)
7. **State Management** (`zebra-state/`)
8. **Integer Arithmetic Safety** (workspace-wide `as` cast audit)
9. **Authentication & Authorization** (`zebra-rpc/src/server/cookie.rs`)
10. **DoS Resistance** (rate limiting, connection management, memory bounds)

---

## Findings

### MEDIUM Severity

#### M-1: `p2sh_sigop_count` Silent Undercount on Length Mismatch

**File:** `zebra-script/src/lib.rs:283-303`  
**Severity:** Medium  
**Category:** Consensus Correctness  

**Description:**  
The `p2sh_sigop_count` function uses `zip()` to pair transaction inputs with spent outputs. If `spent_outputs.len() != tx.inputs().len()` for a non-coinbase transaction, `zip()` silently truncates the longer iterator, producing an **undercount** of P2SH sigops. This could allow a block with more sigops than `MAX_BLOCK_SIGOPS` to pass validation.

The code has a `debug_assert_eq!` that catches this in debug builds, but in release builds the mismatch is silently ignored.

```rust
debug_assert_eq!(
    tx.inputs().len(),
    spent_outputs.len(),
    "spent_outputs must align with transaction inputs for non-coinbase txs"
);

tx.inputs()
    .iter()
    .zip(spent_outputs.iter())  // Silent truncation in release builds
    .map(|(input, spent_output)| p2sh_input_sigop_count(input, spent_output))
    .sum()
```

**Impact:** If a caller passes mismatched lengths, the sigop count will be too low, potentially allowing blocks that exceed the sigop limit. This is a consensus-critical function.

**Recommendation:** Replace `debug_assert_eq!` with a hard error return or `assert_eq!` in release builds. Alternatively, return an error type instead of `u32`:

```rust
pub fn p2sh_sigop_count(
    tx: &Transaction,
    spent_outputs: &[transparent::Output],
) -> Result<u32, Error> {
    if tx.is_coinbase() {
        return Ok(0);
    }
    if tx.inputs().len() != spent_outputs.len() {
        return Err(Error::TxIndex);
    }
    // ...
}
```

---

#### M-2: `filteradd` Message Body Length Not Fully Validated

**File:** `zebra-network/src/protocol/external/codec.rs` (in `read_filteradd`)  
**Severity:** Medium  
**Category:** Protocol Parsing / DoS  

**Description:**  
The `read_filteradd` method uses `min(body_len, MAX_FILTERADD_LENGTH)` to cap the read length, but does **not** reject messages where `body_len > MAX_FILTERADD_LENGTH`. According to BIP 37, data elements larger than 520 bytes should be rejected. Instead, Zebra silently truncates the data to 520 bytes and accepts the message.

```rust
fn read_filteradd<R: Read>(&self, mut reader: R, body_len: usize) -> Result<Message, Error> {
    const MAX_FILTERADD_LENGTH: usize = 520;
    // Memory Denial of Service: limit the untrusted parsed length
    let filter_length: usize = min(body_len, MAX_FILTERADD_LENGTH);
    let filter_bytes = zcash_deserialize_bytes_external_count(filter_length, &mut reader)?;
    Ok(Message::FilterAdd { data: filter_bytes })
}
```

**Impact:** While Zebra ignores filter messages (noted in the code), accepting malformed messages without error could mask protocol violations. The remaining `body_len - 520` bytes are left unconsumed in the body, but since the body was already split off, this is benign. However, the truncation means the `FilterAdd` message contains different data than what the peer sent.

**Recommendation:** Reject `filteradd` messages where `body_len > MAX_FILTERADD_LENGTH`:

```rust
if body_len > MAX_FILTERADD_LENGTH {
    return Err(Error::Parse("filteradd data too long: must be 520 bytes or less"));
}
```

---

#### M-3: Inbound Peer Eclipse via High Inbound-to-Outbound Ratio

**File:** `zebra-network/src/constants.rs:63-67`  
**Severity:** Medium  
**Category:** Network Security / Eclipse Attack  

**Description:**  
The `INBOUND_PEER_LIMIT_MULTIPLIER` is 5x while `OUTBOUND_PEER_LIMIT_MULTIPLIER` is 3x. With the default `peerset_initial_target_size` of 25, this means:
- Outbound limit: 75 peers (chosen by Zebra)
- Inbound limit: 125 peers (chosen by attackers)

An attacker controlling 126+ IP addresses can fill all inbound slots, achieving a **62.5% majority** of the node's peer connections (125 / 200). Combined with the `DEFAULT_MAX_CONNS_PER_IP = 1` limit, this requires 125 distinct IPs, which is feasible for a well-resourced attacker.

The code comments acknowledge this tradeoff explicitly:

> "This means that an attacker can easily become a majority of a node's peers."

**Impact:** An attacker with sufficient IP addresses can eclipse a Zebra node, controlling the majority of its peer connections. This could enable double-spend attacks, transaction censorship, or delayed block propagation.

**Recommendation:** Consider reducing `INBOUND_PEER_LIMIT_MULTIPLIER` to 2x or 3x, or implementing additional eclipse resistance measures such as:
- Anchor connections (persistent outbound connections to trusted peers)
- Subnet diversity requirements for inbound connections
- Eviction of inbound peers that don't provide useful data

---

### LOW Severity / Informational

#### L-1: RPC Cookie Authentication Uses Non-Constant-Time Comparison

**File:** `zebra-rpc/src/server/cookie.rs:26-28`  
**Severity:** Low  
**Category:** Cryptographic Implementation  

**Description:**  
The `authenticate` method uses `==` (derived `PartialEq` on `String`) for cookie comparison, which is not constant-time:

```rust
pub fn authenticate(&self, passwd: String) -> bool {
    *passwd == self.0
}
```

**Impact:** A local attacker with network access to the RPC port could theoretically perform a timing side-channel attack to recover the cookie value byte-by-byte. However, the cookie is 32 random bytes (base64-encoded to 44 characters), and the RPC server defaults to `127.0.0.1`, limiting the attack surface to local processes.

**Recommendation:** Use a constant-time comparison function:

```rust
use subtle::ConstantTimeEq;

pub fn authenticate(&self, passwd: String) -> bool {
    self.0.as_bytes().ct_eq(passwd.as_bytes()).into()
}
```

---

#### L-2: `block_in_place` in Network Codec May Block Tokio Runtime

**File:** `zebra-network/src/protocol/external/codec.rs` (in `deserialize_transaction_spawning` and `deserialize_block_spawning`)  
**Severity:** Low  
**Category:** Performance / Availability  

**Description:**  
Block and transaction deserialization uses `tokio::task::block_in_place()` combined with `rayon::in_place_scope_fifo()`. The `block_in_place` call blocks the current tokio worker thread, which can reduce the runtime's capacity to handle other connections. The code comments acknowledge this:

> "Since we use `block_in_place()`, other futures running on the connection task will be blocked"

**Impact:** Under heavy load with many simultaneous block/transaction messages, this could reduce the responsiveness of other peer connections sharing the same tokio worker thread.

**Recommendation:** Consider using `spawn_blocking` with owned data (by reading the message body into a `Vec<u8>` first), or accept the current tradeoff with documentation.

---

#### L-3: Handshake Nonce Collision Detection Uses Shared Mutex

**File:** `zebra-network/src/peer/handshake.rs:82`  
**Severity:** Low  
**Category:** Concurrency  

**Description:**  
The `nonces` field uses `Arc<futures::lock::Mutex<IndexSet<Nonce>>>` shared across all handshakes. Under high connection rates, this mutex could become a bottleneck. Additionally, the nonce set grows unboundedly if nonces are never removed after handshake completion.

**Impact:** Minor performance impact under high connection rates. The nonce set size is bounded by the number of concurrent handshakes (which is bounded by connection limits), so memory impact is negligible.

**Recommendation:** Ensure nonces are removed after handshake completion. Consider using a `DashSet` or similar concurrent set for better performance under contention.

---

#### L-4: `MAX_PROTOCOL_MESSAGE_LEN` as Defense-in-Depth for CompactSize

**File:** `zebra-chain/src/serialization/compact_size.rs`  
**Severity:** Informational  
**Category:** Defense-in-Depth  

**Description:**  
`CompactSizeMessage` correctly limits values to `MAX_PROTOCOL_MESSAGE_LEN` (2 MiB). This is a strong defense-in-depth measure. However, individual `TrustedPreallocate` implementations provide tighter bounds per type. The two-layer defense is well-designed and correctly implemented.

**Status:** No action needed. This is a positive finding.

---

#### L-5: Unknown Network Messages Are Silently Ignored

**File:** `zebra-network/src/protocol/external/codec.rs` (in `Decoder::decode`)  
**Severity:** Informational  
**Category:** Protocol Compliance  

**Description:**  
Unknown message commands return `Ok(None)` rather than an error. The code includes a security comment explaining this is intentional to prevent DoS/eclipse attacks via connection closure. This is the correct behavior.

```rust
_ => {
    // # Security
    // Zcash connections are not authenticated, so malicious nodes can
    // send fake messages...
    debug!(?command, %command_string, "unknown message command from peer");
    return Ok(None);
}
```

**Status:** No action needed. This is a positive finding demonstrating security awareness.

---

#### L-6: RPC `listen_addr` Security Warning

**File:** `zebra-rpc/src/config/rpc.rs:31-33`  
**Severity:** Informational  
**Category:** Configuration Security  

**Description:**  
The RPC config includes a security warning about binding to public IP addresses. The default is `None` (disabled), and cookie authentication is enabled by default. The symlink check in `cookie::write_to_disk` prevents symlink attacks on the cookie file. File permissions are set to `0o600` on Unix.

**Status:** Well-implemented. The defense-in-depth approach (disabled by default + cookie auth + restrictive permissions + symlink check) is thorough.

---

#### L-7: Overload Protection Probability Calculation

**File:** `zebra-network/src/peer/connection.rs:1640-1670`  
**Severity:** Informational  
**Category:** DoS Resistance  

**Description:**  
The `overload_drop_connection_probability` function uses a quadratic decay model. The probability ranges from `MIN_OVERLOAD_DROP_PROBABILITY` (0.05) to `MAX_OVERLOAD_DROP_PROBABILITY` (0.5). The `OVERLOAD_PROTECTION_INTERVAL` is set to `MIN_INBOUND_PEER_CONNECTION_INTERVAL` (1 second).

This means:
- First overload: 5% chance of disconnection
- Second overload within 1 second: up to 50% chance
- Rapid successive overloads: increasingly likely to disconnect

**Status:** Well-designed. The probabilistic approach prevents both DoS via overload and DoS via excessive disconnection.

---

#### L-8: `as` Cast Safety in Serialization Code

**File:** Various files in `zebra-chain/src/`  
**Severity:** Informational  
**Category:** Integer Safety  

**Description:**  
The workspace lint configuration includes `checked_conversions = "warn"` and `unnecessary_cast = "warn"`, which helps catch unsafe integer conversions. The `as` casts found in the codebase are predominantly in test code or in contexts where the cast is provably safe (e.g., `MAX_BLOCK_SUBSIDY: u64 = ((25 * COIN) / 2) as u64` where the value is a compile-time constant).

The `CompactSize64` serialization uses `as` casts that are safe because they are in match arms that have already validated the range:

```rust
0x00..=0xfc => writer.write_u8(n as u8),        // n <= 0xfc, fits in u8
0x00fd..=0xffff => writer.write_u16::<LE>(n as u16),  // n <= 0xffff, fits in u16
```

**Status:** No action needed. The casts are safe within their match arm contexts.

---

## Positive Security Findings

The following security measures are well-implemented and deserve recognition:

### 1. Memory Safety Architecture
- **`deny(unsafe_code)`** at workspace level eliminates memory corruption vulnerabilities
- Single `allow(unsafe_code)` in `zebra-script` is justified for FFI and well-documented
- `TrustedPreallocate` trait prevents memory DoS via deserialization

### 2. Network Protocol Security
- **Magic number validation** prevents cross-network message injection
- **Checksum verification** (SHA-256d) prevents message corruption
- **Message size limits** (`MAX_PROTOCOL_MESSAGE_LEN = 2 MiB`) prevent memory exhaustion
- **User agent length limit** (256 bytes) prevents per-connection memory abuse
- **Address response limits** prevent peer set takeover
- **Timestamp truncation** (30-minute intervals) prevents timing fingerprinting

### 3. Peer Management Security
- **Connection rate limiting** (inbound: 1s success, 10ms failure; outbound: 100ms)
- **Per-IP connection limits** (default: 1)
- **Peer misbehavior scoring** with disconnection threshold (100)
- **Banned IP tracking** (up to 20,000 IPs)
- **Probabilistic overload disconnection** prevents both DoS and self-DoS
- **Request timeouts** (20 seconds) prevent resource exhaustion

### 4. RPC Security
- **Disabled by default** — requires explicit configuration
- **Cookie-based authentication** enabled by default
- **Restrictive file permissions** (0o600) on cookie file
- **Symlink attack prevention** on cookie file path
- **Content-type validation** prevents CSRF via browser forms
- **Request body size limits** based on `MAX_BLOCK_BYTES`
- **`deny_unknown_fields`** on config structs prevents config injection

### 5. Consensus Safety
- **Sighash callback safety**: When the sighash callback cannot compute a valid hash (invalid hash type, missing output for SIGHASH_SINGLE), it returns a random 32-byte value instead of a fixed sentinel. This prevents an attacker from constructing a signature that verifies against a known sentinel value.
- **Canonical CompactSize enforcement**: Non-canonical CompactSize encodings are rejected
- **Field element validation**: Curve points and scalars are validated on deserialization

### 6. FFI Safety (`zebra-script`)
- The FFI boundary is well-contained in a single crate
- Input validation occurs before FFI calls
- The sighash callback handles edge cases (invalid hash types, missing outputs) safely
- Error types are non-exhaustive, allowing future extension

---

## Architecture Assessment

### Dependency Flow
The crate dependency hierarchy is correctly enforced:
```
zebrad → zebra-consensus → zebra-script
       → zebra-state
       → zebra-network
       → zebra-rpc → zebra-node-services → zebra-chain (sync-only)
```

This prevents circular dependencies and ensures that lower-level crates don't depend on higher-level ones, which is important for security isolation.

### Error Handling
The codebase consistently uses `thiserror` for error types with proper `#[from]` and `#[source]` annotations. The `expect()` messages follow the project convention of explaining **why** the invariant holds, which aids in debugging.

### Async Safety
- CPU-intensive work (crypto, deserialization) is offloaded to `rayon` or `spawn_blocking`
- All external waits have timeouts
- `tokio::sync::watch` is preferred over `Mutex` for shared async state

---

## Conclusion

Zebra demonstrates a mature security posture with well-designed defense-in-depth measures across all attack surfaces. The Rust type system and workspace-level `deny(unsafe_code)` eliminate entire classes of vulnerabilities. The network protocol parsing is robust with proper bounds checking, and the RPC server has appropriate authentication and access controls.

The three medium-severity findings should be addressed:
1. **M-1** (sigop undercount) is a consensus correctness issue that should be fixed by making the length check a hard error
2. **M-2** (filteradd truncation) is a minor protocol compliance issue
3. **M-3** (eclipse attack surface) is an inherent tradeoff that is already documented, but could benefit from additional mitigations

No critical vulnerabilities were identified. The codebase is well-suited for production use as a Zcash full node.
