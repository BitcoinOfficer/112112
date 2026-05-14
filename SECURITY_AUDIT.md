# Zebra Security Audit Report

**Date:** 2026-05-14  
**Scope:** Full codebase — network protocol, serialization, consensus, RPC, FFI, state, peer management  
**Methodology:** Manual static analysis of all attack-surface code paths

---

## Executive Summary

Zebra demonstrates strong security engineering overall. The codebase uses Rust's type system effectively, denies `unsafe_code` workspace-wide (except the necessary FFI in `zebra-script`), and implements defense-in-depth patterns including `TrustedPreallocate`, `CompactSizeMessage` bounds, connection rate-limiting, and misbehavior scoring. The audit identified **no critical exploitable vulnerabilities** but found several areas of concern ranging from medium to informational severity.

---

## Findings

### FINDING 1 — `filteradd` Message Silently Truncates Oversized Data (Low)

**File:** `zebra-network/src/protocol/external/codec.rs` (line ~560)

**Description:**  
The `read_filteradd` method silently truncates the body to `MAX_FILTERADD_LENGTH` (520 bytes) using `min(body_len, MAX_FILTERADD_LENGTH)` rather than rejecting oversized messages with an error. While Zebra ignores BIP37 filter messages entirely (they are consumed as `Consumed` in the connection handler), this silent truncation deviates from the BIP37 specification which states that data elements larger than 520 bytes should be rejected.

```rust
fn read_filteradd<R: Read>(&self, mut reader: R, body_len: usize) -> Result<Message, Error> {
    const MAX_FILTERADD_LENGTH: usize = 520;
    // Silent truncation instead of rejection:
    let filter_length: usize = min(body_len, MAX_FILTERADD_LENGTH);
    let filter_bytes = zcash_deserialize_bytes_external_count(filter_length, &mut reader)?;
    Ok(Message::FilterAdd { data: filter_bytes })
}
```

**Impact:** Low. Zebra ignores filter messages, so this is defense-in-depth only. However, if filter support is ever added, this would become a protocol compliance issue.

**Recommendation:** Reject messages where `body_len > MAX_FILTERADD_LENGTH` with a parse error, consistent with `filterload` handling.

---

### FINDING 2 — Handshake Loops on Non-Version/Non-Verack Messages Without Bound (Medium)

**File:** `zebra-network/src/peer/handshake.rs` (lines ~430-445, ~480-495)

**Description:**  
During the handshake, `negotiate_version` waits for a `Version` message and then a `Verack` message. If the remote peer sends non-Version (or non-Verack) messages, the code loops indefinitely, reading and discarding messages:

```rust
let mut remote_msg = peer_conn.next().await.ok_or(HandshakeError::ConnectionClosed)??;
// Wait for next message if the one we got is not Version
let remote: VersionMessage = loop {
    match remote_msg {
        Message::Version(version_message) => { break version_message; }
        _ => {
            remote_msg = peer_conn.next().await.ok_or(HandshakeError::ConnectionClosed)??;
            debug!(?remote_msg, "ignoring non-version message from remote peer");
        }
    }
};
```

While the outer `Handshake::call` wraps the entire handshake in a `HANDSHAKE_TIMEOUT` (3 seconds), a malicious peer could send a stream of valid non-Version messages (e.g., `Ping` messages) to keep the handshake task alive for the full timeout duration, consuming resources (a task slot, a TCP connection, memory for decoded messages).

**Impact:** Medium. An attacker can hold handshake resources for up to 3 seconds per connection. Combined with the inbound connection rate limit (1 per second), this limits the attack to ~3 concurrent stalled handshakes, which is manageable. However, the unbounded loop is architecturally concerning.

**Recommendation:** Add a counter to limit the number of non-Version/non-Verack messages accepted during handshake (e.g., max 3), and disconnect peers that exceed it.

---

### FINDING 3 — Misbehavior Score Not Incremented for Many Consensus Violations (Low-Medium)

**File:** `zebra-consensus/src/error.rs` (lines ~263-310, ~401-414)

**Description:**  
The `TransactionError::mempool_misbehavior_score()` and `BlockError::misbehavior_score()` methods return `0` for many error variants via the `_other => 0` catch-all. This means peers that send transactions or blocks with the following errors receive no misbehavior penalty:

- `TransactionError::LockedUntilAfterBlockHeight` / `LockedUntilAfterBlockTime`
- `TransactionError::ExpiredTransaction`
- `TransactionError::MaximumExpiryHeight`
- `TransactionError::NotCoinbase`
- `TransactionError::InternalDowncastError`
- `BlockError::NoTransactions`
- `BlockError::BadMerkleRoot`
- `BlockError::DuplicateTransaction`
- `BlockError::WrongTransactionConsensusBranchId`
- `BlockError::TooManyTransparentSignatureOperations`

Some of these (e.g., `BadMerkleRoot`, `DuplicateTransaction`, `TooManyTransparentSignatureOperations`) are clear indicators of malicious or broken peers and should carry a non-zero misbehavior score.

**Impact:** Low-Medium. Malicious peers can repeatedly send invalid blocks/transactions without being banned, wasting verification resources. The existing connection timeout and overload protection partially mitigate this.

**Recommendation:** Assign non-zero misbehavior scores to clearly invalid block/transaction errors. The TODO comment at line 267 (`// TODO: Adjust these values based on zcashd (#9258)`) confirms this is a known gap.

---

### FINDING 4 — `body_len` Cast from `u32` to `usize` in Codec Decoder (Informational)

**File:** `zebra-network/src/protocol/external/codec.rs` (line ~377)

**Description:**  
```rust
let body_len = header_reader.read_u32::<LittleEndian>()? as usize;
```

This `as usize` cast is safe on all current platforms (where `usize >= 32 bits`), and the value is immediately checked against `self.builder.max_len` (which is `MAX_PROTOCOL_MESSAGE_LEN = 2MB`). However, per the project's own coding standards, `as` casts should have a comment explaining why the cast is safe.

**Impact:** Informational. No actual vulnerability.

**Recommendation:** Add a safety comment: `// Safe: u32 always fits in usize on supported platforms`.

---

### FINDING 5 — `p2sh_sigop_count` Uses `zip()` Which Silently Truncates Mismatched Lengths (Low)

**File:** `zebra-script/src/lib.rs` (lines ~370-390)

**Description:**  
The `p2sh_sigop_count` function uses `tx.inputs().iter().zip(spent_outputs.iter())` to pair inputs with their spent outputs. If the lengths don't match, `zip()` silently truncates the longer iterator, potentially undercounting sigops. While there is a `debug_assert_eq!` that catches this in debug builds, it is a no-op in release builds.

```rust
debug_assert_eq!(
    tx.inputs().len(),
    spent_outputs.len(),
    "spent_outputs must align with transaction inputs for non-coinbase txs"
);

tx.inputs()
    .iter()
    .zip(spent_outputs.iter())
    .map(|(input, spent_output)| p2sh_input_sigop_count(input, spent_output))
    .sum()
```

**Impact:** Low. The callers in `zebra-consensus` are expected to always provide correctly-sized `spent_outputs`. An undercount would allow a block with too many sigops to pass validation, but this requires a bug in the calling code, not an external attack.

**Recommendation:** Consider using `assert_eq!` instead of `debug_assert_eq!`, or return an error when lengths don't match, to make this a hard invariant in release builds.

---

### FINDING 6 — Sighash Callback Returns Random Bytes on Failure Instead of Propagating Error (Low)

**File:** `zebra-script/src/lib.rs` (lines ~240-260)

**Description:**  
When the sighash computation fails (e.g., invalid hash type for v5 transactions, or SIGHASH_SINGLE without a corresponding output), the callback returns a randomly-generated 32-byte value instead of propagating the error:

```rust
Some(computed.unwrap_or_else(|| {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}))
```

The code comment explains this is a workaround because `libzcash_script`'s callback API doesn't propagate failure. While the random value makes signature verification fail with overwhelming probability, this is a probabilistic defense rather than a deterministic one.

**Impact:** Low. The probability of a random 32-byte value matching a valid sighash is negligible (2^-256). The code correctly documents this as a workaround.

**Recommendation:** Track the upstream `libzcash_script` fix to propagate callback failures, and remove this workaround when available.

---

### FINDING 7 — Inbound Peer Limit Multiplier Creates Eclipse Attack Surface (Informational — Documented)

**File:** `zebra-network/src/constants.rs` (lines ~40-60)

**Description:**  
The `INBOUND_PEER_LIMIT_MULTIPLIER` (5x) is significantly higher than `OUTBOUND_PEER_LIMIT_MULTIPLIER` (3x). With a default target of 25 peers, this means up to 125 inbound connections vs 75 outbound. An attacker controlling many IP addresses could become a majority of a node's peers through inbound connections.

**Impact:** Informational. This is a documented security tradeoff (the code comments explicitly discuss this). The `DEFAULT_MAX_CONNS_PER_IP` (1) and the misbehavior banning system partially mitigate this.

**Recommendation:** Already documented. Consider adding monitoring/alerting when inbound connections significantly outnumber outbound connections.

---

### FINDING 8 — `Addr` Message Deserialization Checks Count After Full Deserialization (Low)

**File:** `zebra-network/src/protocol/external/codec.rs` (lines ~440-455)

**Description:**  
In `read_addr` and `read_addrv2`, the address count limit check happens *after* the full vector has been deserialized:

```rust
fn read_addr<R: Read>(&self, reader: R) -> Result<Message, Error> {
    let addrs: Vec<AddrV1> = reader.zcash_deserialize_into()?;
    if addrs.len() > constants::MAX_ADDRS_IN_MESSAGE {
        return Err(Error::Parse("more than MAX_ADDRS_IN_MESSAGE in addr message"));
    }
    // ...
}
```

The `TrustedPreallocate` implementation for `AddrV1` already limits allocation to `MAX_ADDRS_IN_MESSAGE`, so the post-deserialization check is redundant defense-in-depth. However, the deserialization still allocates and processes all addresses before the check.

**Impact:** Low. The `TrustedPreallocate` bound prevents excessive allocation. The post-check is defense-in-depth.

**Recommendation:** No change needed — the layered defense is appropriate.

---

### FINDING 9 — `assert!` in `Addr` Message Encoding Could Panic on Malformed Internal State (Low)

**File:** `zebra-network/src/protocol/external/codec.rs` (line ~195)

**Description:**  
The `write_body` method for `Message::Addr` uses `assert!` to check the address count:

```rust
Message::Addr(addrs) => {
    assert!(
        addrs.len() <= constants::MAX_ADDRS_IN_MESSAGE,
        "unexpectedly large Addr message: greater than MAX_ADDRS_IN_MESSAGE addresses"
    );
    // ...
}
```

If internal code ever constructs an `Addr` message with too many addresses, this will panic and crash the node. While this should never happen in correct code, a `return Err(...)` would be more resilient.

**Impact:** Low. This is an internal invariant check. The `Addr` response path in `connection.rs` doesn't enforce this limit before constructing the message, but the `update_addr_cache` method limits responses to `PEER_ADDR_RESPONSE_LIMIT`.

**Recommendation:** Consider replacing the `assert!` with `return Err(Error::Parse(...))` for resilience.

---

### FINDING 10 — RPC Cookie Authentication is Optional and Disabled by Default (Informational)

**File:** `zebra-rpc/src/server.rs` (lines ~120-130)

**Description:**  
The RPC server's cookie-based authentication (`enable_cookie_auth`) is optional and defaults to disabled. When disabled, any process that can reach the RPC port can execute all RPC methods, including `submitblock` and `sendrawtransaction`.

**Impact:** Informational. The RPC server defaults to `http_only()` and typically listens on localhost. However, in containerized or cloud environments, localhost binding may not provide sufficient isolation.

**Recommendation:** Document the security implications of running without cookie auth, especially in production environments. Consider making cookie auth the default.

---

## Positive Security Observations

1. **`unsafe_code = "deny"` workspace-wide** — Only `zebra-script` allows unsafe code for FFI, and it's well-contained.

2. **`TrustedPreallocate` pattern** — All deserialized vectors from network data use bounded preallocation, preventing memory DoS.

3. **`CompactSizeMessage` bounded to `MAX_PROTOCOL_MESSAGE_LEN`** — Prevents oversized allocations at the serialization layer.

4. **Connection rate limiting** — Both inbound and outbound connections are rate-limited with configurable intervals.

5. **Misbehavior scoring and IP banning** — Peers exceeding `MAX_PEER_MISBEHAVIOR_SCORE` (100) are banned, with a bounded ban list (`MAX_BANNED_IPS = 20,000`).

6. **Timestamp truncation** — Outbound address timestamps are truncated to 30-minute intervals to prevent timing attacks.

7. **Nonce-based self-connection detection** — The handshake uses random nonces to detect and reject self-connections.

8. **Overload protection with probabilistic disconnection** — The `handle_inbound_overload` method uses a quadratic probability curve to disconnect peers that repeatedly trigger overload, making sustained DoS harder.

9. **Address book security** — Address book updates are based on outbound connections only, preventing malicious peers from poisoning the address book via inbound connections.

10. **Checksum verification** — All network messages are verified against SHA256d checksums before processing.

---

## Summary Table

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | `filteradd` silent truncation | Low | New |
| 2 | Handshake unbounded non-Version loop | Medium | New |
| 3 | Missing misbehavior scores for many errors | Low-Medium | Known (TODO) |
| 4 | Missing safety comment on `as usize` cast | Informational | New |
| 5 | `p2sh_sigop_count` silent truncation via `zip()` | Low | New |
| 6 | Random sighash on callback failure | Low | Known (workaround) |
| 7 | Inbound peer limit eclipse surface | Informational | Documented |
| 8 | Post-deserialization addr count check | Low | Defense-in-depth |
| 9 | `assert!` in Addr encoding | Low | New |
| 10 | RPC cookie auth disabled by default | Informational | By design |

---

*End of audit report.*
