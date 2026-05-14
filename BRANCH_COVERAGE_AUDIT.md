# Zebra Network Attack Surface - Branch Coverage Audit

**Audit Objective**: Achieve 100% branch coverage of all network-facing code paths

**Status**: IN PROGRESS
**Started**: 2026-05-14
**Coverage Target**: 100% branch coverage (not line coverage)

## Executive Summary

This audit systematically enumerates and exercises every control-flow branch reachable from unauthenticated network input in the Zebra Zcash validator node. The goal is to prove that no unexplored branch remains in:

1. P2P message deserialization (zebra-network)
2. Block and transaction parsing (zebra-chain)
3. RPC handling (zebra-rpc)
4. Script execution (zebra-script)
5. Consensus verification (zebra-consensus)
6. State storage (zebra-state)

## Methodology

### 1. Network Entry Point Enumeration

All network-facing entry points where untrusted data enters the system:

#### A. P2P Protocol Messages (zebra-network)
- Location: `zebra-network/src/protocol/external/codec.rs`
- Entry method: `Codec::decode()`
- Message types (18 total):
  1. `Version` - Connection handshake
  2. `Verack` - Handshake acknowledgment
  3. `Ping` - Keepalive request
  4. `Pong` - Keepalive response
  5. `Reject` - Error notification
  6. `GetAddr` - Request peer addresses
  7. `Addr` - Peer address list (v1)
  8. `AddrV2` - Peer address list (v2, ZIP-155)
  9. `GetBlocks` - Request block inventory
  10. `Inv` - Inventory advertisement
  11. `GetHeaders` - Request block headers
  12. `Headers` - Block header list
  13. `GetData` - Request specific data
  14. `Block` - Block data
  15. `Tx` - Transaction data
  16. `NotFound` - Missing data response
  17. `Mempool` - Request mempool transactions
  18. `FilterLoad` - BIP37 bloom filter
  19. `FilterAdd` - BIP37 filter addition
  20. `FilterClear` - BIP37 filter clear

#### B. Block Deserialization (zebra-chain)
- Location: `zebra-chain/src/block/serialize.rs`
- Entry: `Block::zcash_deserialize()`
- Components:
  - Block headers (multiple versions)
  - Transaction lists
  - Commitment data

#### C. Transaction Deserialization (zebra-chain)
- Location: `zebra-chain/src/transaction/`
- Entry: `Transaction::zcash_deserialize()`
- Variants:
  - V1, V2, V3 (Overwinter), V4 (Sapling), V5 (NU5)
  - Each with different shielded pools

#### D. RPC Endpoints (zebra-rpc)
- Location: `zebra-rpc/src/`
- Entry: JSON-RPC request handlers
- Both authenticated and unauthenticated endpoints

### 2. Branch Identification Strategy

For each entry point, we extract branches using multiple techniques:

#### Static Analysis Tools
1. **cargo-llvm-cov**: LLVM-based coverage instrumentation
2. **cargo-tarpaulin**: Code coverage with branch tracking
3. **cargo-kcov**: Branch coverage via kcov
4. **Manual CFG extraction**: For critical paths

#### Branch Categories

**Category 1: Explicit Conditionals**
- `if/else` statements
- `match` arms
- `while/for` loop entry/exit
- Boolean short-circuit evaluation (`&&`, `||`)

**Category 2: Implicit Branches**
- `Result::?` operator (Ok/Err branches)
- `Option` matching (Some/None)
- Iterator exhaustion checks
- Panic/unwrap paths

**Category 3: Dynamic Dispatch**
- Trait object calls
- Function pointer invocations
- Enum variant dispatching

**Category 4: State-Dependent Branches**
- Connection state (pre-handshake, post-handshake)
- Chain height dependent logic
- Network upgrade activation
- Feature flag conditions

### 3. Branch Coverage Matrix

## Critical Path Analysis: P2P Message Codec

### File: `zebra-network/src/protocol/external/codec.rs`

#### Function: `Codec::decode()` (Lines 354-494)

**Branch Inventory**:

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| DEC-001 | 364 | `src.len() < HEADER_LEN` | ⬜ | Partial header | Need: <24 byte buffer |
| DEC-002 | 393 | `magic != self.builder.network.magic()` | ⬜ | Wrong network | Need: Invalid magic |
| DEC-003 | 396 | `body_len > self.builder.max_len` | ⬜ | Oversized | Need: body_len > 2MB |
| DEC-004 | 422 | `src.len() < body_len` | ⬜ | Partial body | Need: Incomplete message |
| DEC-005 | 434 | Checksum mismatch | ⬜ | Corrupted | Need: Invalid checksum |
| DEC-006 | 442 | Command: `version` | ⬜ | Version msg | Standard test |
| DEC-007 | 443 | Command: `verack` | ⬜ | Verack msg | Standard test |
| DEC-008 | 444 | Command: `ping` | ⬜ | Ping msg | Standard test |
| DEC-009 | 445 | Command: `pong` | ⬜ | Pong msg | Standard test |
| DEC-010 | 446 | Command: `reject` | ⬜ | Reject msg | Error case |
| DEC-011 | 447 | Command: `addr` | ⬜ | Addr msg | Address exchange |
| DEC-012 | 448 | Command: `addrv2` | ⬜ | AddrV2 msg | ZIP-155 addresses |
| DEC-013 | 449 | Command: `getaddr` | ⬜ | GetAddr msg | Request peers |
| DEC-014 | 450 | Command: `block` | ⬜ | Block msg | Block data |
| DEC-015 | 451 | Command: `getblocks` | ⬜ | GetBlocks msg | Request inventory |
| DEC-016 | 452 | Command: `headers` | ⬜ | Headers msg | Header data |
| DEC-017 | 453 | Command: `getheaders` | ⬜ | GetHeaders msg | Request headers |
| DEC-018 | 454 | Command: `inv` | ⬜ | Inv msg | Inventory ad |
| DEC-019 | 455 | Command: `getdata` | ⬜ | GetData msg | Data request |
| DEC-020 | 456 | Command: `notfound` | ⬜ | NotFound msg | Missing data |
| DEC-021 | 457 | Command: `tx` | ⬜ | Tx msg | Transaction |
| DEC-022 | 458 | Command: `mempool` | ⬜ | Mempool msg | Mempool request |
| DEC-023 | 459 | Command: `filterload` | ⬜ | FilterLoad msg | BIP37 |
| DEC-024 | 460 | Command: `filteradd` | ⬜ | FilterAdd msg | BIP37 |
| DEC-025 | 461 | Command: `filterclear` | ⬜ | FilterClear msg | BIP37 |
| DEC-026 | 462-473 | Unknown command | ⬜ | Invalid cmd | Security test |
| DEC-027 | 482 | `extra_bytes == 0` | ⬜ | Exact size | Normal case |
| DEC-028 | 485 | `extra_bytes > 0` | ⬜ | Extra data | Protocol compat |

#### Function: `Codec::read_version()` (Lines 504-545)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| VER-001 | 509-514 | Timestamp out of range | ⬜ | Invalid ts | Need: i64 out of DateTime range |
| VER-002 | 528-532 | User agent too long | ⬜ | Long UA | Need: >256 byte user agent |
| VER-003 | 537-542 | Relay field values | ⬜ | relay=0,1,>1,EOF | All relay branches |

#### Function: `Codec::read_reject()` (Lines 559-613)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| REJ-001 | 568-572 | Message too long | ⬜ | Long msg | Need: >12 byte reject message |
| REJ-002 | 576-586 | RejectReason variants | ⬜ | All ccodes | 9 different reject codes |
| REJ-003 | 595-599 | Reason too long | ⬜ | Long reason | Need: >111 byte reason |
| REJ-004 | 611 | Optional data present/absent | ⬜ | Both cases | With/without 32-byte data |

#### Function: `Codec::read_addr()` (Lines 616-628)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| ADDR-001 | 619-623 | Too many addresses | ⬜ | >MAX_ADDRS | Need: >1000 addresses |

#### Function: `Codec::read_addrv2()` (Lines 634-650)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| ADDR2-001 | 637-641 | Too many addresses | ⬜ | >MAX_ADDRS | Need: >1000 addresses |
| ADDR2-002 | 645-648 | Filter unsupported types | ⬜ | Various addr types | ZIP-155 network IDs |

#### Function: `Codec::read_getblocks()` (Lines 661-674)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| GETBLK-001 | 662 | Version mismatch | ⬜ | Wrong version | Protocol version check |
| GETBLK-002 | 665-669 | Stop hash zero/non-zero | ⬜ | Both cases | Optional stop parameter |

#### Function: `Codec::read_headers()` (Lines 681-695)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| HDR-001 | 686-690 | Too many headers | ⬜ | >160 headers | Protocol limit |

#### Function: `Codec::read_getheaders()` (Lines 697-710)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| GETHDR-001 | 698 | Version mismatch | ⬜ | Wrong version | Protocol version check |
| GETHDR-002 | 701-705 | Stop hash zero/non-zero | ⬜ | Both cases | Optional stop parameter |

#### Function: `Codec::read_filterload()` (Lines 733-759)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| FLTLD-001 | 745-747 | Invalid body length | ⬜ | Bad length | <9 or >36009 bytes |

#### Function: `Codec::read_filteradd()` (Lines 761-769)

| Branch ID | Line | Condition | Covered | Input | Notes |
|-----------|------|-----------|---------|-------|-------|
| FLTAD-001 | 765 | Length clamping | ⬜ | Length >520 | DoS protection |

### Total Codec Branches: 50+

## Coverage Generation Plan

### Phase 1: Instrumentation Setup

1. **Install Coverage Tools**
```bash
cargo install cargo-llvm-cov cargo-tarpaulin
rustup component add llvm-tools-preview
```

2. **Configure Branch Coverage**
```bash
# Use LLVM coverage with branch tracking
export RUSTFLAGS="-C instrument-coverage"
export LLVM_PROFILE_FILE="zebra-%p-%m.profraw"
```

3. **Generate Baseline Coverage**
```bash
cargo llvm-cov --all-features --workspace --branch --ignore-filename-regex '(tests|benches)' --html
```

### Phase 2: Targeted Input Generation

For each uncovered branch, generate specific test inputs:

#### Example: Branch DEC-002 (Wrong Network Magic)

**Target**: Trigger magic number mismatch
**Location**: `codec.rs:393`
**Constraint**: `magic != self.builder.network.magic()`

**Test Input**:
```rust
#[test]
fn test_wrong_network_magic() {
    let mainnet_codec = Codec::builder().for_network(&Network::Mainnet).finish();
    let mut buffer = BytesMut::new();
    
    // Create message with testnet magic on mainnet codec
    buffer.extend_from_slice(&[0xfa, 0x1a, 0xf9, 0xbf]); // Testnet magic
    buffer.extend_from_slice(b"version\0\0\0\0\0"); // Command
    buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Length
    buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Checksum
    
    let result = mainnet_codec.decode(&mut buffer);
    assert!(matches!(result, Err(Error::Parse(_))));
}
```

#### Example: Branch VER-001 (Timestamp Out of Range)

**Target**: Trigger invalid timestamp in version message
**Location**: `codec.rs:509-514`
**Constraint**: Timestamp outside `DateTime<Utc>` range

**Test Input**:
```rust
#[test]
fn test_version_invalid_timestamp() {
    let codec = Codec::builder().finish();
    let mut buffer = BytesMut::new();
    
    // Construct version message with i64::MAX timestamp (invalid for DateTime)
    let mut writer = std::io::Cursor::new(&mut buffer);
    
    // Magic + command + length + checksum (header)
    writer.write_all(&Network::Mainnet.magic().0).unwrap();
    writer.write_all(b"version\0\0\0\0\0").unwrap();
    writer.write_u32::<LittleEndian>(85).unwrap(); // Body length
    writer.write_u32::<LittleEndian>(0).unwrap(); // Temp checksum
    
    // Version message body
    writer.write_u32::<LittleEndian>(170100).unwrap(); // Version
    writer.write_u64::<LittleEndian>(1).unwrap(); // Services
    writer.write_i64::<LittleEndian>(i64::MAX).unwrap(); // INVALID TIMESTAMP
    // ... rest of version message
    
    let result = codec.decode(&mut buffer);
    assert!(matches!(result, Err(Error::Parse(_))));
}
```

### Phase 3: Property-Based Testing

Use `proptest` to generate random inputs exploring edge cases:

```rust
proptest! {
    #[test]
    fn prop_codec_never_panics(data in prop::collection::vec(any::<u8>(), 0..10_000)) {
        let mut codec = Codec::builder().finish();
        let mut buffer = BytesMut::from(&data[..]);
        
        // Should never panic, only return Ok or Err
        let _ = codec.decode(&mut buffer);
    }
    
    #[test]
    fn prop_version_message_all_fields(
        version in any::<u32>(),
        services in any::<u64>(),
        timestamp in any::<i64>(),
        user_agent_len in 0usize..=300,
        start_height in any::<u32>(),
        relay in any::<u8>()
    ) {
        // Test version message with all field combinations
        // This will explore branches for:
        // - Valid/invalid timestamps
        // - Valid/invalid user agent lengths
        // - Valid/invalid relay values
    }
}
```

### Phase 4: State-Space Exploration

Multi-message sequences for stateful branches:

```rust
#[test]
fn test_message_sequence_branches() {
    // Branch coverage requires sequences like:
    // 1. Connect -> Version -> Verack (normal handshake)
    // 2. Connect -> GetAddr (before handshake complete)
    // 3. Connect -> Version -> Version (duplicate)
    // 4. Connect -> Block (before handshake)
    // etc.
}
```

## Branch Coverage Targets by Module

### Module: zebra-network/protocol/external/codec.rs
- **Total Branches**: ~50
- **Covered**: 0
- **Target**: 100%
- **Priority**: CRITICAL (network entry point)

### Module: zebra-chain/serialization
- **Total Branches**: TBD (analyze next)
- **Covered**: 0
- **Target**: 100%
- **Priority**: CRITICAL (data parsing)

### Module: zebra-chain/block
- **Total Branches**: TBD
- **Covered**: 0
- **Target**: 100%
- **Priority**: CRITICAL

### Module: zebra-chain/transaction
- **Total Branches**: TBD
- **Covered**: 0
- **Target**: 100%
- **Priority**: CRITICAL

### Module: zebra-consensus
- **Total Branches**: TBD
- **Covered**: 0
- **Target**: 100%
- **Priority**: HIGH

### Module: zebra-state
- **Total Branches**: TBD
- **Covered**: 0
- **Target**: 100%
- **Priority**: HIGH

### Module: zebra-rpc
- **Total Branches**: TBD
- **Covered**: 0
- **Target**: 100%
- **Priority**: MEDIUM (authenticated)

## Unreachable Branch Proofs

For branches proven unreachable from network input:

| Branch | Module | Reason Unreachable | Proof |
|--------|--------|-------------------|-------|
| TBD | TBD | TBD | TBD |

## Infinite Loop Analysis

Loops that require bounded model checking:

| Loop | Module | Max Iterations | Proof Method |
|------|--------|----------------|--------------|
| TBD | TBD | TBD | TBD |

## Progress Tracking

**Branches Identified**: 50+
**Branches Covered**: 0
**Branches Proven Unreachable**: 0
**Coverage Percentage**: 0%

**Next Actions**:
1. ✅ Enumerate codec branches
2. ⬜ Install coverage tooling
3. ⬜ Generate baseline coverage report
4. ⬜ Create test inputs for each branch
5. ⬜ Run coverage and verify 100%
6. ⬜ Analyze zebra-chain serialization
7. ⬜ Continue with block deserialization
8. ⬜ Continue with transaction deserialization
9. ⬜ Analyze consensus verification
10. ⬜ Analyze state storage

## Completion Certificate

**NOT YET COMPLETE**

The audit will produce a certificate when:
- ✅ All branches enumerated
- ✅ All branches covered with test inputs
- ✅ All unreachable branches formally proven
- ✅ Coverage report shows 100% branch coverage

---

**Audit Log**

2026-05-14: Audit initiated. Identified 50+ branches in codec.rs.
