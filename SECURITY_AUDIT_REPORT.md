# Zebra Security Audit Report

**Date:** May 14, 2026  
**Scope:** Full codebase static analysis of the Zebra Zcash node implementation  
**Crates Audited:** `zebra-network`, `zebra-chain`, `zebra-rpc`, `zebra-script`, `zebra-consensus`, `zebra-state`, `zebrad`  
**Methodology:** Manual source code review of all network-facing entry points, deserialization paths, FFI boundaries, RPC handlers, peer connection management, and consensus-critical code paths.

---

## Executive Summary

Zebra demonstrates a **mature, defense-in-depth security posture**. The codebase employs multiple layers of protection against common attack vectors in cryptocurrency node implementations. The workspace-level `unsafe_code = "deny"` lint eliminates direct memory corruption risks in Rust code. The `TrustedPreallocate` trait provides systematic protection against memory denial-of-service via deserialization. The P2P codec enforces message size limits, checksum validation, and magic number verification. The RPC layer implements cookie-based authentication with proper file permissions and CSRF protections.

The audit identified **no critical vulnerabilities** that would allow remote code execution, consensus splits, or monetary base corruption. Several **low-severity observations** and **informational findings** are documented below, along with **positive security patterns** worth preserving.

---

## 1. Attack Surface Analysis

### 1.1 Network Protocol (P2P) — `zebra-network`

**Entry Point:** `zebra-network/src/protocol/external/codec.rs` — Tokio `Decoder`/`Encoder` implementation

#### Positive Findings

| Finding | Location | Assessment |
|---------|----------|------------|
| **Magic number validation** | `codec.rs:383-385` | Network magic is validated before any body parsing. Mismatched magic causes immediate rejection. **Correct.** |
| **Body length limit** | `codec.rs:386-388` | `body_len` is checked against `max_len` (= `MAX_PROTOCOL_MESSAGE_LEN` = 2 MiB) before any allocation. **Correct.** |
| **Checksum verification** | `codec.rs:420-424` | SHA-256d checksum is verified before body parsing. Corrupted messages are rejected. **Correct.** |
| **Unknown command handling** | `codec.rs:455-463` | Unknown commands are silently ignored (`Ok(None)`) rather than closing the connection. This prevents denial-of-service via fake messages with spoofed IP headers. **Correct and security-critical.** |
| **Extra bytes tolerance** | `codec.rs:468-480` | Extra trailing bytes after message parsing are logged but tolerated, matching Bitcoin protocol forward-compatibility. **Correct.** |

#### Observations

| ID | Severity | Finding | Details |
|----|----------|---------|---------|
| NET-01 | **Info** | `body_len` cast from `u32` to `usize` | `codec.rs:377`: `read_u32::<LittleEndian>()? as usize`. This is safe because `usize` is ≥ 32 bits on all supported platforms, and the value is immediately bounds-checked against `max_len`. No issue. |
| NET-02 | **Info** | `body_length as u32` cast in encoder | `codec.rs:169`: The body length is computed from `FakeWriter` and cast to `u32`. This is safe because `body_length` is checked against `max_len` (2 MiB < u32::MAX) on line 127-129 before the cast. No issue. |
| NET-03 | **Low** | `block_in_place` for deserialization | `codec.rs:530-545`: `tokio::task::block_in_place()` is used for block/transaction deserialization. While documented, this blocks the current tokio worker thread. Under heavy load with many simultaneous block messages, this could reduce connection throughput. The comment acknowledges this tradeoff. **Acceptable for current architecture.** |
| NET-04 | **Info** | `filteradd` length clamping | `codec.rs:517`: `min(body_len, MAX_FILTERADD_LENGTH)` silently truncates oversized filteradd data rather than rejecting it. If `body_len > 520`, the remaining bytes are silently ignored. This is benign because BIP 111 filter messages are already ignored at the connection layer (line 1247-1256). |

### 1.2 Peer Connection Management — `zebra-network/src/peer/`

#### Positive Findings

| Finding | Location | Assessment |
|---------|----------|------------|
| **Nonce-based self-connection detection** | `handshake.rs:731-737` | Nonces are checked in a mutex-protected set. Self-connections are rejected. Nonces are not removed on rejection to prevent malicious nonce-removal attacks. **Correct.** |
| **Minimum peer version enforcement** | `handshake.rs:745-780` | Peers on obsolete protocol versions are rejected during handshake. **Correct.** |
| **Duplicate handshake rejection** | `connection.rs:1201-1208` | Version/Verack messages received outside handshake cause connection failure. **Correct.** |
| **Overload protection with probabilistic disconnection** | `connection.rs:1590-1650` | Inbound overload uses a quadratic probability function to disconnect peers, preventing both DoS and excessive disconnection. **Well-designed.** |
| **Address book isolation** | `connection.rs:1261-1275` | Unsolicited `addr` messages are cached but not added to the address book. Zebra only adds addresses from its own proactive crawling. This prevents address book poisoning / eclipse attacks. **Excellent security design.** |
| **Transaction inventory limits** | `connection.rs:1098-1112` | `AdvertiseTransactionIds` is capped at `MAX_TX_INV_IN_SENT_MESSAGE` to prevent network amplification. **Correct.** |
| **Request timeouts** | `connection.rs:1076` | All outbound requests have `REQUEST_TIMEOUT`. Ping timeouts fail the connection; other timeouts fail only the request. **Correct.** |
| **Addr response limiting** | `connection.rs:175-178` | `PEER_ADDR_RESPONSE_LIMIT` caps the number of addresses returned per request, preventing peer set takeover. **Correct.** |

#### Observations

| ID | Severity | Finding | Details |
|----|----------|---------|---------|
| PEER-01 | **Low** | Handshake ignores non-Version messages | `handshake.rs:701-710`: During version negotiation, non-Version messages are silently ignored in a loop. A peer could send many garbage messages before the Version, consuming resources. However, the handshake has an external timeout (documented at line 1000), so this is bounded. **Acceptable.** |
| PEER-02 | **Info** | `INBOUND_PEER_LIMIT_MULTIPLIER = 5` | `constants.rs:67`: Inbound connections are allowed at 5× the outbound target. The security comment (lines 44-66) correctly documents the tradeoff: this prevents connection exhaustion but allows an attacker to become a majority of inbound peers. This is mitigated by Zebra's proactive address book crawling. **Documented and acceptable.** |
| PEER-03 | **Info** | `assert!` in `Addr` encoding | `codec.rs:195-198`: The encoder uses `assert!` for addr count validation. This is correct because it validates Zebra's own internal data (not untrusted input). A panic here would indicate a Zebra bug, not an attack. |

### 1.3 Deserialization — `zebra-chain/src/serialization/`

#### Positive Findings

| Finding | Location | Assessment |
|---------|----------|------------|
| **`TrustedPreallocate` trait** | `zcash_deserialize.rs:179-190` | All `Vec<T>` deserialization requires `T: TrustedPreallocate`, which provides a `max_allocation()` bound. This systematically prevents memory DoS via oversized allocations. **Excellent defense-in-depth.** |
| **`CompactSizeMessage` bounded to `MAX_PROTOCOL_MESSAGE_LEN`** | `compact_size.rs:162-175` | Message-scoped compact sizes are capped at 2 MiB. Values exceeding this are rejected during deserialization. **Correct.** |
| **Non-canonical CompactSize rejection** | `compact_size.rs:268-280` | Non-canonical encodings (e.g., encoding `0x42` as a 3-byte value) are rejected. This prevents ambiguity in consensus-critical parsing. **Correct.** |
| **`MAX_U8_ALLOCATION` for byte vectors** | `zcash_deserialize.rs:207-210` | Raw byte vector allocation is capped at `MAX_PROTOCOL_MESSAGE_LEN - 5`. **Correct.** |
| **User agent length limit** | `codec.rs:310-316` | User agent strings are limited to `MAX_USER_AGENT_LENGTH` (256 bytes) during deserialization, preventing memory DoS from `Arc<VersionMessage>` stored per peer. **Correct.** |
| **Reject message field limits** | `codec.rs:337-340, 355-358` | Reject message and reason fields are bounded to prevent log-based disk DoS. **Correct.** |

#### Observations

| ID | Severity | Finding | Details |
|----|----------|---------|---------|
| DESER-01 | **Info** | `CompactSize64` is unbounded | `compact_size.rs:148-155`: `CompactSize64` accepts the full `u64` range. This is by design — it's used for flags and cross-block counts, not for in-message allocations. All allocation paths use `CompactSizeMessage` instead. **Correct separation of concerns.** |

### 1.4 RPC Server — `zebra-rpc`

#### Positive Findings

| Finding | Location | Assessment |
|---------|----------|------------|
| **Cookie-based authentication** | `cookie.rs`: 32 random bytes, base64-encoded. Written with `0o600` permissions on Unix. Symlink check before write. **Correct.** |
| **CSRF protection via content-type** | `http_request_compatibility.rs:107-120`: `application/x-www-form-urlencoded` is rejected (only `application/json` and `text/plain` are accepted). The security comment explicitly references CSRF via browser forms. **Correct.** |
| **Request body size limit** | `http_request_compatibility.rs:143`: `Limited::new(body, max_request_body_size)` caps request body parsing. **Correct.** |
| **Hex input validation** | `methods.rs:1168-1170`: `send_raw_transaction` validates hex encoding before deserialization. **Correct.** |
| **Transaction deserialization validation** | `methods.rs:1171-1172`: Raw bytes are deserialized through `Transaction::zcash_deserialize`, which applies all consensus-critical validation. **Correct.** |

#### Observations

| ID | Severity | Finding | Details |
|----|----------|---------|---------|
| RPC-01 | **Low** | Cookie authentication uses constant-time comparison? | `cookie.rs:27`: `*passwd == self.0` uses `String` equality, which may not be constant-time. However, the cookie is a 32-byte random value, so timing attacks are impractical (the attacker would need to guess the correct prefix to observe timing differences). **Very low risk.** |
| RPC-02 | **Info** | `_allow_high_fees` parameter ignored | `methods.rs:1164`: The `allow_high_fees` parameter is accepted but ignored, matching the documented behavior. This is a compatibility parameter from zcashd. **By design.** |

### 1.5 Script Verification (FFI) — `zebra-script`

#### Positive Findings

| Finding | Location | Assessment |
|---------|----------|------------|
| **`#![allow(unsafe_code)]` scoped to crate** | `lib.rs:5`: Unsafe code is only allowed in `zebra-script`, which wraps the `libzcash_script` FFI. All other crates deny unsafe code at the workspace level. **Correct isolation.** |
| **Sighash callback safety** | `lib.rs:155-200`: The sighash callback validates hash types for v5+ transactions, rejecting undefined values. For `SIGHASH_SINGLE` without a corresponding output, it returns a random dummy hash instead of a sentinel value. The comment (lines 195-200) correctly explains why a fixed sentinel would be unsafe (attacker could forge ECDSA signatures). **Excellent security reasoning.** |
| **Input index bounds checking** | `lib.rs:130-134`: `all_previous_outputs.get(input_index)` with a length check prevents out-of-bounds access. **Correct.** |
| **Coinbase rejection** | `lib.rs:147`: Coinbase inputs are explicitly rejected from script verification. **Correct.** |
| **P2SH sigop counting** | `lib.rs:230-280`: `extract_p2sh_redeem_script` correctly mirrors zcashd's behavior, returning `None` for non-push-only scriptSigs. **Correct consensus compatibility.** |

#### Observations

| ID | Severity | Finding | Details |
|----|----------|---------|---------|
| SCRIPT-01 | **Info** | Random sighash workaround | `lib.rs:195-200`: The random dummy sighash is a workaround for `libzcash_script` not propagating callback failures. The comment notes this can be removed once the upstream library is fixed. This is a correct and safe workaround. |
| SCRIPT-02 | **Info** | `p2sh_sigop_count` zip truncation | `lib.rs:296-298`: `tx.inputs().iter().zip(spent_outputs.iter())` silently truncates if lengths differ. The `debug_assert_eq!` on line 290 catches this in debug builds. For non-coinbase transactions, the caller (`CachedFfiTransaction`) ensures lengths match via the constructor. **Acceptable.** |

### 1.6 Consensus — `zebra-consensus`

| Finding | Assessment |
|---------|------------|
| **Workspace lint `unsafe_code = "deny"`** | `Cargo.toml` workspace lints deny all unsafe code except in `zebra-script`. This eliminates memory corruption in pure Rust code. **Excellent.** |
| **`non_ascii_idents = "deny"`** | Prevents homoglyph attacks in identifiers. **Good practice.** |
| **Clippy lints for numeric safety** | `checked_conversions`, `invalid_upcast_comparisons`, `unnecessary_cast` are all warned. **Good practice.** |
| **`await_holding_lock` and `await_holding_refcell_ref`** | Prevents deadlocks from holding locks across await points. **Good practice.** |
| **`panic = "abort"` in dev and release** | Prevents unwinding-based attacks and simplifies error handling. **Correct.** |

---

## 2. Threat Model Coverage

| Threat | Mitigation | Status |
|--------|-----------|--------|
| **Memory DoS via deserialization** | `TrustedPreallocate`, `CompactSizeMessage` bounds, `MAX_PROTOCOL_MESSAGE_LEN` | ✅ Mitigated |
| **CPU DoS via expensive operations** | `block_in_place` + rayon for block/tx deserialization, request timeouts | ✅ Mitigated |
| **Eclipse attacks** | Proactive address book crawling, addr response limits, address book isolation from unsolicited messages | ✅ Mitigated |
| **Connection exhaustion** | Per-IP connection limits, inbound/outbound multipliers, probabilistic overload disconnection | ✅ Mitigated |
| **Self-connection** | Nonce-based detection with mutex-protected nonce set | ✅ Mitigated |
| **Protocol downgrade** | Minimum peer version enforcement during handshake | ✅ Mitigated |
| **RPC CSRF** | Content-type validation, cookie authentication | ✅ Mitigated |
| **RPC unauthorized access** | Cookie-based auth with 0600 file permissions, symlink check | ✅ Mitigated |
| **Consensus split via script verification** | FFI to `libzcash_script` with proper sighash computation, v5 hash type validation | ✅ Mitigated |
| **Network amplification** | Transaction inventory limits, addr response limits | ✅ Mitigated |
| **Log injection / disk DoS** | Reject message field length limits | ✅ Mitigated |
| **Memory corruption** | Workspace-wide `unsafe_code = "deny"`, scoped `allow` only in FFI crate | ✅ Mitigated |

---

## 3. Summary of Findings

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 0 | — |
| **High** | 0 | — |
| **Medium** | 0 | — |
| **Low** | 4 | NET-03, PEER-01, NET-04, RPC-01 |
| **Informational** | 8 | NET-01, NET-02, PEER-02, PEER-03, DESER-01, RPC-02, SCRIPT-01, SCRIPT-02 |

---

## 4. Recommendations

1. **RPC-01 (Low):** Consider using a constant-time comparison for cookie authentication (`subtle::ConstantTimeEq` or equivalent). While the current risk is very low due to the 256-bit random cookie, constant-time comparison is a best practice for authentication tokens.

2. **NET-03 (Low):** Monitor the impact of `block_in_place` under high connection counts. If profiling shows worker thread starvation, consider switching to `spawn_blocking` with a bounded semaphore for deserialization tasks.

3. **General:** The `libzcash_script` random-sighash workaround (SCRIPT-01) should be tracked for removal once the upstream library propagates callback failures.

4. **General:** Continue maintaining the `TrustedPreallocate` bounds as new message types or data structures are added. The existing property tests (`preallocate.rs` files) provide good regression coverage for this.

---

## 5. Conclusion

The Zebra codebase demonstrates **strong security engineering practices** across all audited components. The defense-in-depth approach — combining Rust's memory safety guarantees, workspace-level lint enforcement, systematic deserialization bounds, protocol-level validation, and well-documented security comments — provides robust protection against the attack vectors relevant to a cryptocurrency full node.

No vulnerabilities requiring immediate remediation were identified. The four low-severity findings are minor hardening opportunities that do not represent exploitable weaknesses in the current implementation.

---

*This report was generated through static analysis of the Zebra source code. It does not include dynamic testing, fuzzing, or formal verification.*
