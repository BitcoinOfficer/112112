# Serialization Layer Branch Coverage Analysis

## Module: `zebra-chain/src/serialization/zcash_deserialize.rs`

### Critical Functions

#### 1. `zcash_deserialize_external_count()` (Lines 80-101)

This function is called for every array deserialization in the protocol. It contains multiple security-critical branches:

| Branch ID | Line | Condition | Security Impact | Test Input Needed |
|-----------|------|-----------|-----------------|-------------------|
| SER-001 | 85 | `external_count > T::max_allocation()` | **CRITICAL** DoS protection | Need: count > max_allocation for each type T |
| SER-002 | 90 | `external_count` within bounds | Normal path | Standard vectors |
| SER-003 | 94 | `external_count` conversion to u64 fails | Future-proofing for 128-bit | Need: usize > u64::MAX (impossible on current platforms) |
| SER-004 | 97-99 | Loop iterations (0 to external_count) | Each iteration is a branch | Need: 0, 1, 2, 10, 100, max items |
| SER-005 | 98 | `T::zcash_deserialize()` error propagation | Error handling | Need: malformed T at each position |

**Branch Analysis**:

```rust
// Line 84-95: Multiple branch points
match u64::try_from(external_count) {
    Ok(external_count) if external_count > T::max_allocation() => {
        // BRANCH SER-001: Oversized allocation attempt
        // Attack: Cause OOM by requesting huge allocation
        return Err(SerializationError::Parse(
            "Vector longer than max_allocation",
        ))
    }
    Ok(_) => {}  // BRANCH SER-002: Valid size
    Err(_) => {  // BRANCH SER-003: Impossible on 64-bit systems
        return Err(SerializationError::Parse("Vector longer than u64::MAX"))
    }
}

// Lines 96-100: Loop branches
let mut vec = Vec::with_capacity(external_count);
for _ in 0..external_count {  // BRANCH SER-004: 0..N iterations
    vec.push(T::zcash_deserialize(&mut reader)?);  // BRANCH SER-005: ? operator
}
```

**Test Coverage Requirements**:

1. **SER-001**: For every type T implementing `TrustedPreallocate`:
   - Create input with count = `T::max_allocation() + 1`
   - Verify error is returned
   - No allocation should occur

2. **SER-002**: Standard case tests with counts: 0, 1, 10, 100

3. **SER-003**: Document as unreachable on current platforms (< 128-bit)

4. **SER-004**: Loop iteration coverage:
   - 0 iterations (empty vector)
   - 1 iteration (single element)
   - N iterations where N is typical (10-100)
   - Max iterations (up to max_allocation for small types)

5. **SER-005**: Error propagation:
   - Malformed element at position 0
   - Malformed element at position N/2
   - Malformed element at position N-1
   - Valid elements followed by EOF

#### 2. `zcash_deserialize_bytes_external_count()` (Lines 110-122)

Raw byte vector deserialization (no per-element parsing).

| Branch ID | Line | Condition | Security Impact | Test Input Needed |
|-----------|------|-----------|-----------------|-------------------|
| SER-006 | 114 | `external_count > MAX_U8_ALLOCATION` | **CRITICAL** DoS protection | Need: count > MAX_U8_ALLOCATION |
| SER-007 | 120 | `read_exact()` success/failure | EOF or read error | Need: truncated data |

**Attack Surface**: This is called for:
- User agent strings in version messages
- Script data in transactions  
- Memo fields in shielded transactions
- Block header extra data

**Test Coverage**:

```rust
#[test]
fn test_bytes_oversized_allocation() {
    let mut reader = Cursor::new(vec![]);
    let result = zcash_deserialize_bytes_external_count(
        MAX_U8_ALLOCATION + 1,
        &mut reader
    );
    assert!(result.is_err());
}

#[test]
fn test_bytes_truncated_data() {
    let data = vec![0x42; 100];
    let mut reader = Cursor::new(data);
    
    // Request 200 bytes but only 100 available
    let result = zcash_deserialize_bytes_external_count(200, &mut reader);
    assert!(matches!(result, Err(SerializationError::Io(_))));
}

#[test]
fn test_bytes_exact_allocation_limit() {
    let mut reader = Cursor::new(vec![0x42; MAX_U8_ALLOCATION]);
    let result = zcash_deserialize_bytes_external_count(
        MAX_U8_ALLOCATION,
        &mut reader
    );
    assert!(result.is_ok());
}
```

#### 3. `zcash_deserialize_string_external_count()` (Lines 132-139)

String deserialization with UTF-8 validation.

| Branch ID | Line | Condition | Security Impact | Test Input Needed |
|-----------|------|-----------|-----------------|-------------------|
| SER-008 | 136 | Bytes within allocation limit | Calls SER-006 branch | Inherited from bytes |
| SER-009 | 138 | UTF-8 validation success | Valid string path | Valid UTF-8 sequences |
| SER-010 | 138 | UTF-8 validation failure | **SECURITY** Invalid UTF-8 rejection | Invalid UTF-8 sequences |

**Attack Vectors**:
- Overlong UTF-8 encodings (security)
- Invalid continuation bytes
- Truncated multi-byte sequences
- Non-shortest form encodings
- Surrogate pairs in UTF-8

**Test Coverage**:

```rust
#[test]
fn test_string_invalid_utf8_sequences() {
    let test_cases = vec![
        // Invalid continuation byte
        vec![0xC0, 0x00],
        // Overlong encoding of '/'
        vec![0xC0, 0xAF],
        // Truncated 2-byte sequence
        vec![0xC2],
        // Truncated 3-byte sequence  
        vec![0xE0, 0xA0],
        // Truncated 4-byte sequence
        vec![0xF0, 0x90, 0x80],
        // Surrogate half
        vec![0xED, 0xA0, 0x80],
        // Invalid start byte
        vec![0xFF],
        // Overlong ASCII
        vec![0xC0, 0x80],
    ];
    
    for (i, invalid_utf8) in test_cases.iter().enumerate() {
        let len = invalid_utf8.len();
        let mut reader = Cursor::new(invalid_utf8);
        let result = zcash_deserialize_string_external_count(len, &mut reader);
        assert!(
            result.is_err(),
            "Test case {} should fail UTF-8 validation",
            i
        );
    }
}

#[test]
fn test_string_valid_utf8() {
    let test_cases = vec![
        "ASCII",
        "Ñoño",  // Latin extended
        "日本語",  // Japanese
        "🦓",     // Emoji (4-byte UTF-8)
        "",       // Empty string
        "a\nb\tc", // Control characters
    ];
    
    for valid_str in test_cases {
        let bytes = valid_str.as_bytes();
        let mut reader = Cursor::new(bytes);
        let result = zcash_deserialize_string_external_count(bytes.len(), &mut reader);
        assert!(result.is_ok(), "Valid UTF-8 '{}' should succeed", valid_str);
        assert_eq!(result.unwrap(), valid_str);
    }
}
```

### TrustedPreallocate Implementation Analysis

Each type implementing `TrustedPreallocate` defines `max_allocation()`. These limits are DoS protection boundaries.

**Types requiring branch coverage**:

| Type | Max Allocation | Location | Critical? |
|------|---------------|----------|-----------|
| `Transaction` | Network-dependent | `zebra-chain/src/transaction/` | **YES** |
| `block::Header` | 160 | `zebra-chain/src/block/` | **YES** |
| `InventoryHash` | Network-dependent | `zebra-network/src/protocol/external/inv.rs` | **YES** |
| `MetaAddr` | 1000 | `zebra-network/src/meta_addr.rs` | **YES** |
| `Input` | 253 | `zebra-chain/src/transaction/` | **YES** |
| `Output` | 253 | `zebra-chain/src/transaction/` | **YES** |
| `JoinSplit<Groth16>` | 5 | `zebra-chain/src/sapling/` | **YES** |

**Required Tests**: For each type:

```rust
#[test]
fn test_TYPE_allocation_limit() {
    // Attempt to deserialize count = max_allocation() + 1
    // Should fail before allocation
}

#[test]
fn test_TYPE_max_allocation_succeeds() {
    // Deserialize exactly max_allocation() items
    // Should succeed (if reader has enough valid data)
}
```

### CompactSize Branch Analysis

CompactSize (variable-length integer) has implicit branches:

| Value Range | Encoding | Bytes | Branch |
|-------------|----------|-------|--------|
| 0..=252 | Direct | 1 | CS-001 |
| 253..=0xFFFF | 0xFD + u16 | 3 | CS-002 |
| 0x10000..=0xFFFFFFFF | 0xFE + u32 | 5 | CS-003 |
| 0x100000000..=u64::MAX | 0xFF + u64 | 9 | CS-004 |

**Non-canonical encoding detection** (security-critical):

CompactSize MUST reject non-canonical encodings:
- 252 encoded as 0xFD00FC (should be 0xFC)
- 0x100 encoded as 0x00000100 (should be 0xFD0001)

**Test Coverage Needed**:

```rust
#[test]
fn test_compact_size_all_ranges() {
    let test_cases = vec![
        (0u64, vec![0x00]),
        (252u64, vec![0xFC]),
        (253u64, vec![0xFD, 0xFD, 0x00]),
        (0xFFFF, vec![0xFD, 0xFF, 0xFF]),
        (0x10000, vec![0xFE, 0x00, 0x00, 0x01, 0x00]),
        (0xFFFFFFFF, vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
        (0x100000000, vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
    ];
    
    for (value, encoding) in test_cases {
        let mut reader = Cursor::new(&encoding);
        let decoded: CompactSizeMessage = reader.zcash_deserialize_into().unwrap();
        assert_eq!(u64::from(decoded), value);
    }
}

#[test]
fn test_compact_size_non_canonical_encodings() {
    let non_canonical = vec![
        // 252 encoded with 0xFD prefix (should be direct)
        vec![0xFD, 0xFC, 0x00],
        // 0xFFFF encoded with 0xFE prefix
        vec![0xFE, 0xFF, 0xFF, 0x00, 0x00],
        // Small number with 0xFF prefix
        vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    ];
    
    for invalid in non_canonical {
        let mut reader = Cursor::new(&invalid);
        let result: Result<CompactSizeMessage, _> = reader.zcash_deserialize_into();
        assert!(result.is_err(), "Non-canonical encoding should be rejected");
    }
}
```

## Summary: Serialization Branch Coverage Goals

### Total Identified Branches: ~50+

1. **Memory allocation limits**: 10+ types × 2 branches (within/exceeds limit)
2. **Loop iterations**: 10+ types × 4 test cases (0, 1, N, max)
3. **Error propagation**: 10+ types × 3 positions (start, middle, end)
4. **CompactSize encoding**: 4 ranges + non-canonical rejection
5. **UTF-8 validation**: 8+ invalid sequences + valid cases
6. **Read errors**: Truncated data for each deserialization path

### Coverage Strategy:

1. **Unit tests**: Test each function independently
2. **Integration tests**: Test full message deserialization
3. **Property tests**: Random inputs, all must either succeed or error gracefully
4. **Fuzzing**: AFL/libFuzzer for discovering edge cases

### Next Module: Transaction Deserialization

Transaction deserialization contains the most complex branching:
- Version-dependent parsing (V1, V2, V3, V4, V5)
- Optional shielded pools (Sprout, Sapling, Orchard)
- Conditional fields based on flags
- Witness data parsing

This will be analyzed next.
