# Zebra Security Audit Report

**Date:** May 14, 2026  
**Scope:** Full codebase security review of the Zebra Zcash full node implementation  
**Auditor:** Zebra Autonomous Dynamic Audit Engine  
**Revision:** 2 — Exhaustive loop-breaking re-audit with novelty-driven exploration  

---

## Executive Summary

Zebra is a well-engineered Zcash full node implementation in Rust with strong security foundations. The workspace-level `deny(unsafe_code)` lint (with a single, justified exception in `zebra-script`) eliminates entire classes of memory safety vulnerabilities. The codebase demonstrates consistent application of defense-in-depth principles across network parsing, deserialization, and peer management.

This exhaustive re-audit identified **0 critical vulnerabilities**, **5 medium-severity findings**, and **12 low-severity/informational findings**. The medium findings relate to potential denial-of-service vectors, a consensus correctness issue in sigop counting, a timing side-channel in RPC authentication, and subtle protocol compliance gaps.

---

## Audit Methodology

The audit covered the following attack surfaces with novelty-driven exploration to escape the local minimum of repeated findings:

1. **Network Protocol Parsing** (`zebra-network/src/protocol/external/codec.rs`)
2. **Peer Connection Management** (`zebra-network/src/peer/connection.rs`, `handshake.rs`)
3. **Deserialization & Memory Safety** (`zebra-chain/src/serialization/`)
4. **FFI Boundary** (`zebra-script/src/lib.rs`)
5. **RPC Server** (`zebra-rpc/src/server/`, `methods.rs`)
6. **RPC HTTP Middleware** (`zebra-rpc/src/server/http_request_compatibility.rs`)
7. **Consensus Verification** (`zebra-consensus/src/block/`, `transaction/`)
8. **State Management** (`zebra-state/`)
9. **Integer Arithmetic Safety** (workspace-wide `as` cast audit)
10. **Authentication & Authorization** (`zebra-rpc/src/server/cookie.rs`)
11. **DoS Resistance** (rate limiting, connection management, memory bounds)
12. **Address Book Security** (`zebra-network/src/address_book.rs`)
13. **Peer Set & Eclipse Resistance** (`zebra-network/src/constants.rs`, `peer_set/`)
14. **Sighash Callback & Script Verification** (`zebra-script/src/lib.rs`)
15. **Amount Arithmetic** (`zebra-chain/src/amount.rs`)
16. **Block Subsidy & Funding Stream Validation** (`zebra-consensus/src/block/check.rs`, `subsidy.rs`)

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
- Subnet diversity requirements for inbound connections (e.g., limit to N connections per /16 subnet)
- Eviction of inbound peers that don't provide useful data

---

#### M-4: RPC Cookie Authentication Uses Non-Constant-Time Comparison

**File:** `zebra-rpc/src/server/cookie.rs:26-28`  
**Severity:** Medium (upgraded from Low)  
**Category:** Cryptographic Implementation  

**Description:**  
The `authenticate` method uses `==` (derived `PartialEq` on `String`) for cookie comparison, which is not constant-time:

```rust
pub fn authenticate(&self, passwd: String) -> bool {
    *passwd == self.0
}
```

Additionally, the cookie is generated using `rand::thread_rng()` rather than `OsRng`. While `thread_rng()` is cryptographically secure in current implementations, `OsRng` is the recommended choice for security-critical random number generation as it draws directly from the OS entropy source.

```rust
impl Default for Cookie {
    fn default() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(STANDARD.encode(bytes))
    }
}
```

**Impact:** A local attacker with network access to the RPC port could theoretically perform a timing side-channel attack to recover the cookie value byte-by-byte. The RPC server defaults to `127.0.0.1`, limiting the attack surface to local processes. However, if a user binds the RPC to a non-loopback address (which the config allows), the timing attack becomes more feasible over a network.

**Recommendation:**
1. Use a constant-time comparison function:
```rust
use subtle::ConstantTimeEq;

pub fn authenticate(&self, passwd: String) -> bool {
    // Ensure both are the same length before comparing
    if self.0.len() != passwd.len() {
        return false;
    }
    self.0.as_bytes().ct_eq(passwd.as_bytes()).into()
}
```
2. Use `OsRng` instead of `thread_rng()` for cookie generation.

---

#### M-5: `getblocks`/`getheaders` Version Mismatch Causes Hard Rejection

**File:** `zebra-network/src/protocol/external/codec.rs` (in `read_getblocks` and `read_getheaders`)  
**Severity:** Medium  
**Category:** Protocol Compatibility / Availability  

**Description:**  
The `read_getblocks` and `read_getheaders` methods reject messages where the embedded protocol version does not exactly match the negotiated version:

```rust
fn read_getblocks<R: Read>(&self, mut reader: R) -> Result<Message, Error> {
    if self.builder.version == Version(reader.read_u32::<LittleEndian>()?) {
        // ... process message
    } else {
        Err(Error::Parse("getblocks version did not match negotiation"))
    }
}
```

This is stricter than `zcashd`, which ignores the version field in these messages. If a peer sends a `getblocks` or `getheaders` with a slightly different version (e.g., after a network upgrade where versions diverge), the message is rejected as a parse error, which may cause the connection to fail.

**Impact:** During network upgrades or when connecting to peers running slightly different protocol versions, legitimate `getblocks`/`getheaders` messages could be rejected, causing sync failures. The `zcashd` implementation does not check this field, so Zebra is more restrictive than the reference implementation.

**Recommendation:** Consider logging a warning instead of returning an error when the version doesn't match, or removing the version check entirely to match `zcashd` behavior:

```rust
fn read_getblocks<R: Read>(&self, mut reader: R) -> Result<Message, Error> {
    let _version = reader.read_u32::<LittleEndian>()?;
    // zcashd ignores this field; we log but don't reject
    let known_blocks = Vec::zcash_deserialize(&mut reader)?;
    let stop_hash = block::Hash::zcash_deserialize(&mut reader)?;
    let stop = if stop_hash != block::Hash([0; 32]) {
        Some(stop_hash)
    } else {
        None
    };
    Ok(Message::GetBlocks { known_blocks, stop })
}
```

---

### LOW Severity / Informational

#### L-1: `block_in_place` in Network Codec May Block Tokio Runtime

**File:** `zebra-network/src/protocol/external/codec.rs` (in `deserialize_transaction_spawning` and `deserialize_block_spawning`)  
**Severity:** Low  
**Category:** Performance / Availability  

**Description:**  
Block and transaction deserialization uses `tokio::task::block_in_place()` combined with `rayon::in_place_scope_fifo()`. The `block_in_place` call blocks the current tokio worker thread, which can reduce the runtime's capacity to handle other connections. The code comments acknowledge this:

> "Since we use `block_in_place()`, other futures running on the connection task will be blocked"

**Impact:** Under heavy load with many simultaneous block/transaction messages, this could reduce the responsiveness of other peer connections sharing the same tokio worker thread.

**Recommendation:** Consider using `spawn_blocking` with owned data (by reading the message body into a `Vec<u8>` first), or accept the current tradeoff with documentation.

---

#### L-2: Handshake Nonce Set May Grow Unboundedly

**File:** `zebra-network/src/peer/handshake.rs:82`  
**Severity:** Low  
**Category:** Resource Management  

**Description:**  
The `nonces` field uses `Arc<futures::lock::Mutex<IndexSet<Nonce>>>` shared across all handshakes. The nonce set is used to detect self-connections. If nonces are not removed after handshake completion (either success or failure), the set grows unboundedly over the lifetime of the node.

Each `Nonce` is 8 bytes, and the `IndexSet` has per-entry overhead. Over days of operation with many connection attempts, this could accumulate significant memory.

**Impact:** Minor memory leak over long-running node operation. The nonce set size is bounded by the total number of handshake attempts over the node's lifetime.

**Recommendation:** Ensure nonces are removed from the set after handshake completion (success or failure). Consider using a time-bounded cache (e.g., entries expire after `HANDSHAKE_TIMEOUT`).

---

#### L-3: Connection State Machine Panics on Invalid State Transitions

**File:** `zebra-network/src/peer/connection.rs:1016-1025`  
**Severity:** Low  
**Category:** Robustness  

**Description:**  
The `handle_client_request` method panics on two invalid state transitions:

```rust
(Failed, request) => panic!(
    "failed connection cannot handle new request: {:?}, client_receiver: {:?}",
    request, self.client_rx
),
(pending @ AwaitingResponse { .. }, request) => panic!(
    "tried to process new request: {:?} while awaiting a response: {:?}, client_receiver: {:?}",
    request, pending, self.client_rx
),
```

While these states should be unreachable in correct code, a panic in a connection task will cause that connection to drop, which is the desired behavior. However, panics can be caught by `catch_unwind` in some contexts, and they produce noisy stack traces.

**Impact:** If these states are ever reached due to a bug, the connection will panic and drop. This is the correct behavior, but could be handled more gracefully.

**Recommendation:** Consider replacing panics with `error!` logging and returning an error, or keep the panics as they serve as strong invariant checks during development.

---

#### L-4: `MAX_PROTOCOL_MESSAGE_LEN` as Defense-in-Depth for CompactSize

**File:** `zebra-chain/src/serialization/compact_size.rs`  
**Severity:** Informational  
**Category:** Defense-in-Depth (Positive Finding)  

**Description:**  
`CompactSizeMessage` correctly limits values to `MAX_PROTOCOL_MESSAGE_LEN` (2 MiB). This is a strong defense-in-depth measure. Individual `TrustedPreallocate` implementations provide tighter bounds per type. The two-layer defense is well-designed and correctly implemented.

**Status:** No action needed. This is a positive finding.

---

#### L-5: Unknown Network Messages Are Silently Ignored

**File:** `zebra-network/src/protocol/external/codec.rs` (in `Decoder::decode`)  
**Severity:** Informational  
**Category:** Protocol Compliance (Positive Finding)  

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

#### L-6: Extra Bytes After Message Body Are Silently Accepted

**File:** `zebra-network/src/protocol/external/codec.rs` (in `Decoder::decode`)  
**Severity:** Low  
**Category:** Protocol Compliance  

**Description:**  
After decoding a message body, the codec checks for extra bytes but only logs them:

```rust
let extra_bytes = body.len() as u64 - body_reader.position();
if extra_bytes == 0 {
    trace!(?extra_bytes, %msg, "finished message decoding");
} else {
    debug!(?extra_bytes, %msg, "extra data after decoding message");
}
```

This follows the Bitcoin protocol convention of allowing extra data for forward compatibility. However, it means that a peer could append arbitrary data to messages without detection beyond a debug log.

**Impact:** Minimal. This is standard Bitcoin/Zcash protocol behavior for forward compatibility. The extra bytes are already split off from the stream and discarded.

**Recommendation:** No action needed. This is intentional for protocol compatibility.

---

#### L-7: Overload Protection Probability Calculation

**File:** `zebra-network/src/peer/connection.rs:1640-1670`  
**Severity:** Informational  
**Category:** DoS Resistance (Positive Finding)  

**Description:**  
The `overload_drop_connection_probability` function uses a quadratic decay model. The probability ranges from `MIN_OVERLOAD_DROP_PROBABILITY` (0.05) to `MAX_OVERLOAD_DROP_PROBABILITY` (0.5). The `OVERLOAD_PROTECTION_INTERVAL` is set to `MIN_INBOUND_PEER_CONNECTION_INTERVAL` (1 second).

This means:
- First overload: 5% chance of disconnection
- Second overload within 1 second: up to 50% chance
- Rapid successive overloads: increasingly likely to disconnect

**Status:** Well-designed. The probabilistic approach prevents both DoS via overload and DoS via excessive disconnection.

---

#### L-8: `as` Cast Safety in Serialization Code

**File:** Various files in `zebra-chain/src/serialization/`  
**Severity:** Informational  
**Category:** Integer Safety (Positive Finding)  

**Description:**  
The workspace lint configuration includes `checked_conversions = "warn"` and `unnecessary_cast = "warn"`, which helps catch unsafe integer conversions. The `as` casts found in the codebase are predominantly in test code or in contexts where the cast is provably safe.

The `CompactSize64` serialization uses `as` casts that are safe because they are in match arms that have already validated the range:

```rust
0x00..=0xfc => writer.write_u8(n as u8),        // n <= 0xfc, fits in u8
0x00fd..=0xffff => writer.write_u16::<LE>(n as u16),  // n <= 0xffff, fits in u16
0x0001_0000..=0xffff_ffff => writer.write_u32::<LE>(n as u32),  // fits in u32
```

**Status:** No action needed. The casts are safe within their match arm contexts.

---

#### L-9: RPC `content-type` Header Replacement May Mask Protocol Errors

**File:** `zebra-rpc/src/server/http_request_compatibility.rs:110-130`  
**Severity:** Low  
**Category:** RPC Security  

**Description:**  
The `insert_or_replace_content_type_header` method replaces missing or `text/plain` content-type headers with `application/json`. While this is necessary for compatibility with some RPC clients, it means that requests sent with no content-type (which could be from browser forms or other non-RPC sources) are accepted.

The code correctly rejects `application/x-www-form-urlencoded` (by not replacing it), which prevents CSRF attacks via browser forms. However, requests with no content-type at all are accepted, which could allow some CSRF vectors in older browsers that don't send content-type headers.

**Impact:** Minimal. Modern browsers always send content-type headers for POST requests. The cookie authentication provides a strong secondary defense.

**Recommendation:** Consider requiring a content-type header to be present (even if it's `text/plain`), rather than accepting requests with no content-type at all.

---

#### L-10: Address Book Does Not Enforce Subnet Diversity

**File:** `zebra-network/src/address_book.rs`  
**Severity:** Low  
**Category:** Eclipse Resistance  

**Description:**  
The address book limits connections per IP (`DEFAULT_MAX_CONNS_PER_IP = 1`) but does not enforce subnet diversity. An attacker controlling a /16 subnet (65,536 IPs) could fill the address book with addresses from the same subnet, reducing the diversity of Zebra's peer connections.

**Impact:** Reduces the effectiveness of eclipse attack resistance. An attacker with a large IP range could dominate the address book.

**Recommendation:** Consider implementing subnet diversity limits, such as limiting the number of addresses per /16 subnet in the address book. Bitcoin Core implements this as "netgroup" diversity.

---

#### L-11: Sighash Callback Returns Random Bytes on Failure

**File:** `zebra-script/src/lib.rs:230-250`  
**Severity:** Informational  
**Category:** Cryptographic Safety (Positive Finding)  

**Description:**  
When the sighash callback cannot compute a valid hash (invalid hash type, missing output for SIGHASH_SINGLE), it returns a random 32-byte value instead of a fixed sentinel:

```rust
Some(computed.unwrap_or_else(|| {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}))
```

The code includes an excellent security comment explaining why a fixed sentinel would be unsafe:

> "a fixed sentinel value would be unsafe: an attacker who knows it can construct an ECDSA signature that verifies against any 32-byte value under a chosen pubkey."

**Status:** This is a well-designed security measure. The use of `OsRng` (not `thread_rng`) for the random bytes is correct for this security-critical context.

---

#### L-12: Amount Arithmetic Uses `expect` for Overflow in `Add`/`Sub`

**File:** `zebra-chain/src/amount.rs:130-140`  
**Severity:** Informational  
**Category:** Arithmetic Safety  

**Description:**  
The `Add` and `Sub` implementations for `Amount` use `checked_add`/`checked_sub` with `expect`:

```rust
fn add(self, rhs: Amount<C>) -> Self::Output {
    let value = self.0
        .checked_add(rhs.0)
        .expect("adding two constrained Amounts is always within an i64");
    value.try_into()
}
```

The `expect` message is correct: since both operands are constrained to `[-MAX_MONEY, MAX_MONEY]` where `MAX_MONEY = 21_000_000 * 100_000_000 = 2.1e15`, the sum is at most `4.2e15`, which is well within `i64::MAX ≈ 9.2e18`. The result is then validated against the constraint via `try_into()`.

**Status:** No action needed. The arithmetic is provably safe, and the `expect` message correctly explains the invariant.

---

## Positive Security Findings

The following security measures are well-implemented and deserve recognition:

### 1. Memory Safety Architecture
- **`deny(unsafe_code)`** at workspace level eliminates memory corruption vulnerabilities
- Single `allow(unsafe_code)` in `zebra-script` is justified for FFI and well-documented
- `TrustedPreallocate` trait prevents memory DoS via deserialization
- `CompactSizeMessage` provides a hard cap at `MAX_PROTOCOL_MESSAGE_LEN` (2 MiB)

### 2. Network Protocol Security
- **Magic number validation** prevents cross-network message injection
- **Checksum verification** (SHA-256d) prevents message corruption
- **Message size limits** (`MAX_PROTOCOL_MESSAGE_LEN = 2 MiB`) prevent memory exhaustion
- **User agent length limit** (256 bytes) prevents per-connection memory abuse
- **Address response limits** (`PEER_ADDR_RESPONSE_LIMIT`) prevent peer set takeover
- **Timestamp truncation** (30-minute intervals) prevents timing fingerprinting
- **Non-canonical CompactSize rejection** prevents encoding ambiguity attacks
- **Headers message limit** (160 per message) matches protocol specification

### 3. Peer Management Security
- **Connection rate limiting** (inbound: 1s success, 10ms failure; outbound: 100ms)
- **Per-IP connection limits** (default: 1)
- **Peer misbehavior scoring** with disconnection threshold (100)
- **Banned IP tracking** (up to 20,000 IPs)
- **Probabilistic overload disconnection** prevents both DoS and self-DoS
- **Request timeouts** (20 seconds) prevent resource exhaustion
- **Handshake timeouts** (3 seconds) prevent slow-peer attacks
- **Nonce-based self-connection detection** prevents routing loops
- **Address cache randomization** prevents peer selection manipulation

### 4. RPC Security
- **Disabled by default** — requires explicit configuration
- **Cookie-based authentication** enabled by default
- **Restrictive file permissions** (0o600) on cookie file
- **Symlink attack prevention** on cookie file path
- **Content-type validation** prevents CSRF via browser forms
- **Request body size limits** based on `MAX_BLOCK_BYTES`
- **`deny_unknown_fields`** on config structs prevents config injection
- **JSON-RPC version compatibility** layer handles 1.0/2.0 differences

### 5. Consensus Safety
- **Sighash callback safety**: Random bytes on failure, not a fixed sentinel
- **Canonical CompactSize enforcement**: Non-canonical encodings are rejected
- **Equihash solution verification** before other checks (raises attack cost)
- **Difficulty validation** before other checks (raises attack cost)
- **Merkle root validation** binds header to transactions
- **Block time validation** prevents future-dated blocks
- **Coinbase position enforcement** (must be first, and only, coinbase)
- **Transaction expiry validation** prevents expired transactions
- **Lock time validation** prevents premature inclusion
- **Sigop counting** (legacy + P2SH) with `MAX_BLOCK_SIGOPS = 20,000` limit
- **Miner fee validation** ensures coinbase doesn't exceed subsidy + fees
- **Deferred pool balance tracking** for ZIP-1015 compliance

### 6. FFI Safety (`zebra-script`)
- The FFI boundary is well-contained in a single crate
- Input validation occurs before FFI calls
- The sighash callback handles edge cases safely
- Error types are `#[non_exhaustive]`, allowing future extension
- P2SH redeem script extraction mirrors `zcashd` behavior exactly
- Coinbase sigop counting includes coinbase scriptSig (matching `zcashd`)

### 7. Amount Safety (`zebra-chain/src/amount.rs`)
- **Constraint-based type system** prevents invalid amounts at compile time
- **`MAX_MONEY` enforcement** on all amount operations
- **Checked arithmetic** throughout (no silent overflow)
- **Separate constraint types** (`NonNegative`, `NegativeAllowed`, `NegativeOrZero`) for different contexts
- **`try_into()` validation** on all arithmetic results

### 8. Serialization Safety
- **Two-layer preallocation defense**: `CompactSizeMessage` + `TrustedPreallocate`
- **`MAX_U8_ALLOCATION`** limits raw byte vector deserialization
- **UTF-8 validation** on deserialized strings
- **External count deserialization** for V5 transaction arrays
- **`FakeWriter`** for size calculation without allocation

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

This prevents circular dependencies and ensures that lower-level crates don't depend on higher-level ones, which is important for security isolation. The `zebra-chain` crate is correctly kept sync-only (no async, no tokio, no Tower services).

### Error Handling
The codebase consistently uses `thiserror` for error types with proper `#[from]` and `#[source]` annotations. The `expect()` messages follow the project convention of explaining **why** the invariant holds, which aids in debugging. Error types are `#[non_exhaustive]` where appropriate.

### Async Safety
- CPU-intensive work (crypto, deserialization) is offloaded to `rayon` or `block_in_place`
- All external waits have timeouts
- `tokio::sync::watch` is preferred over `Mutex` for shared async state
- `yield_now()` is used to prevent starvation in the connection event loop

### Lint Configuration
The workspace lint configuration is comprehensive:
- `unsafe_code = "deny"` — eliminates memory safety issues
- `non_ascii_idents = "deny"` — prevents homoglyph attacks in identifiers
- `await_holding_lock = "warn"` — prevents async deadlocks
- `checked_conversions = "warn"` — catches unsafe integer conversions
- `print_stdout = "warn"` / `print_stderr = "warn"` — prevents accidental debug output
- `dbg_macro = "warn"` / `todo = "warn"` — catches incomplete code
- `fallible_impl_from = "warn"` / `unwrap_in_result = "warn"` — catches panic-prone patterns

---

## Conclusion

Zebra demonstrates a mature security posture with well-designed defense-in-depth measures across all attack surfaces. The Rust type system and workspace-level `deny(unsafe_code)` eliminate entire classes of vulnerabilities. The network protocol parsing is robust with proper bounds checking, and the RPC server has appropriate authentication and access controls.

The five medium-severity findings should be addressed:
1. **M-1** (sigop undercount) is a consensus correctness issue that should be fixed by making the length check a hard error
2. **M-2** (filteradd truncation) is a minor protocol compliance issue
3. **M-3** (eclipse attack surface) is an inherent tradeoff that is already documented, but could benefit from additional mitigations
4. **M-4** (RPC cookie timing) should use constant-time comparison and `OsRng`
5. **M-5** (getblocks/getheaders version check) is stricter than `zcashd` and could cause sync issues during network upgrades

No critical vulnerabilities were identified. The codebase is well-suited for production use as a Zcash full node.

---

## Appendix: Coverage Summary

| Attack Surface | Files Reviewed | Findings |
|---|---|---|
| Network Protocol Parsing | `codec.rs`, `message.rs`, `compact_size.rs` | M-2, M-5, L-5, L-6 |
| Peer Connection Management | `connection.rs`, `handshake.rs`, `constants.rs` | M-3, L-1, L-2, L-3, L-7 |
| Deserialization | `zcash_deserialize.rs`, `zcash_serialize.rs`, `compact_size.rs` | L-4, L-8 |
| FFI Boundary | `zebra-script/src/lib.rs` | M-1, L-11 |
| RPC Server | `server.rs`, `cookie.rs`, `http_request_compatibility.rs`, `methods.rs` | M-4, L-9 |
| Consensus Verification | `block.rs`, `block/check.rs`, `transaction.rs`, `transaction/check.rs` | (positive findings) |
| State Management | `service.rs` | (positive findings) |
| Amount Arithmetic | `amount.rs` | L-12 |
| Address Book | `address_book.rs` | L-10 |
| Workspace Lints | `Cargo.toml`, `clippy.toml` | (positive findings) |
