# Zebra Security Testing Guide

**Comprehensive Testing Strategy for Security-Critical Code**

---

## Table of Contents

1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Testing Categories](#testing-categories)
4. [Automated Testing](#automated-testing)
5. [Manual Testing](#manual-testing)
6. [Continuous Security](#continuous-security)
7. [Incident Response](#incident-response)

---

## Overview

This guide provides a comprehensive security testing strategy for Zebra, covering:
- **Input validation** on all external boundaries
- **Memory safety** in unsafe code and FFI
- **Concurrency safety** in async/parallel code
- **Cryptographic correctness** in signature verification
- **DoS resistance** against resource exhaustion

**Testing Philosophy:**
- Defense in depth: Multiple layers of validation
- Fail safely: Errors should not cause crashes
- Assume hostile input: All external data is untrusted

---

## Threat Model

### Attack Surfaces

1. **Network Protocol** (HIGH RISK)
   - P2P message parsing
   - Block/transaction deserialization
   - Address book handling
   - Threat: Malformed messages → crash, memory exhaustion, code execution

2. **RPC Interface** (MEDIUM RISK)
   - JSON-RPC endpoints
   - Parameter validation
   - Threat: Malicious RPC calls → DoS, information disclosure

3. **State Database** (MEDIUM RISK)
   - RocksDB interaction
   - State deserialization
   - Threat: Corrupted DB → crash, consensus failure

4. **Script Verification** (HIGH RISK)
   - FFI to C++ zcash_script
   - Signature validation
   - Threat: Bypass verification, consensus failure

5. **Concurrent Operations** (MEDIUM RISK)
   - Mempool management
   - Chain state updates
   - Threat: Race conditions → inconsistent state

### Attacker Capabilities

- **Network Attacker:** Can send arbitrary messages, control timing
- **RPC Attacker:** Can send crafted RPC requests (if exposed)
- **Eclipse Attacker:** Can isolate node from honest peers
- **Consensus Attacker:** Can create invalid blocks/transactions

---

## Testing Categories

### 1. Input Validation Testing

**Objective:** Ensure all external input is validated before processing

#### Network Messages

**Test Cases:**
```rust
#[test]
fn test_oversized_message() {
    // Message larger than MAX_PROTOCOL_MESSAGE_LEN
    let huge_message = vec![0u8; 10_000_000];
    let result = decode_message(&huge_message);
    assert!(result.is_err());
    // Must not panic or allocate 10MB
}

#[test]
fn test_negative_length() {
    // CompactSize with invalid encoding
    let invalid_compact = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let result = decode_compact_size(&invalid_compact);
    assert!(result.is_err());
}

#[test]
fn test_invalid_magic() {
    // Wrong network magic
    let wrong_magic = b"\x24\xe9\x27\x64"; // Bitcoin magic instead of Zcash
    let result = parse_header(wrong_magic);
    assert!(result.is_err());
}
```

#### Cryptographic Data

**Test Cases:**
```rust
#[test]
fn test_invalid_point_encoding() {
    // All possible invalid point encodings
    let test_cases = vec![
        [0u8; 32],                    // All zeros
        [255u8; 32],                  // All ones
        [1, 0, 0, /* ... */, 0],      // Not on curve
        // Add more based on curve properties
    ];
    
    for bytes in test_cases {
        let result = jubjub::AffinePoint::from_bytes(bytes);
        assert!(result.is_none(), "Should reject invalid point");
    }
}

#[test]
fn test_invalid_signature() {
    // Signature with invalid encoding
    let invalid_sig = [0xFF; 64];
    let result = verify_signature(invalid_sig, msg, pubkey);
    assert!(result.is_err());
    // Must not panic
}
```

#### String Fields

**Test Cases:**
```rust
#[test]
fn test_user_agent_too_long() {
    let long_agent = "A".repeat(300);
    let result = parse_version_message_with_agent(&long_agent);
    assert!(result.is_err());
}

#[test]
fn test_reject_reason_too_long() {
    let long_reason = "B".repeat(200);
    let result = create_reject_message(long_reason);
    assert!(result.is_err());
}

#[test]
fn test_non_utf8_string() {
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let result = parse_string_field(&invalid_utf8);
    // Should either succeed with replacement chars or fail gracefully
    assert!(!std::panic::catch_unwind(|| parse_string_field(&invalid_utf8)).is_err());
}
```

### 2. Memory Safety Testing

**Objective:** Ensure no buffer overflows, use-after-free, or memory leaks

#### Sanitizer Testing

**Setup:**
```bash
# Address Sanitizer (use-after-free, buffer overflow)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly test

# Memory Sanitizer (uninitialized memory)
RUSTFLAGS="-Z sanitizer=memory" cargo +nightly test

# Thread Sanitizer (data races)
RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test

# Undefined Behavior Sanitizer
RUSTFLAGS="-Z sanitizer=undefined" cargo +nightly test
```

**Test Cases:**
```rust
#[test]
fn test_bounded_allocation() {
    // Ensure collections are bounded
    let large_count = u32::MAX;
    let result = Vec::<u8>::with_capacity(large_count as usize);
    // Should fail allocation, not panic or OOM
}

#[test]
fn test_no_memory_leak() {
    let initial = get_memory_usage();
    
    for _ in 0..1000 {
        // Perform operation that might leak
        process_large_message();
    }
    
    let final_mem = get_memory_usage();
    assert!(final_mem - initial < 10_000_000); // 10MB tolerance
}
```

#### Valgrind Testing

```bash
# Install valgrind
sudo apt-get install valgrind

# Run tests under valgrind
cargo build --tests
valgrind --leak-check=full \
         --show-leak-kinds=all \
         --track-origins=yes \
         target/debug/deps/zebra_network-*
```

### 3. Concurrency Safety Testing

**Objective:** Find data races and deadlocks

#### TSAN Testing

```rust
#[tokio::test]
async fn test_concurrent_mempool_updates() {
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    
    // Spawn 200 tasks that all update mempool
    let tasks: Vec<_> = (0..200)
        .map(|i| {
            let mp = mempool.clone();
            tokio::spawn(async move {
                mp.lock().await.insert_transaction(create_tx(i));
            })
        })
        .collect();
    
    for task in tasks {
        task.await.unwrap();
    }
    
    // Verify consistency
    // Run with: RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test
}
```

#### Loom Testing (Model Checking)

```rust
use loom::sync::Arc;
use loom::thread;

#[test]
fn test_concurrent_state_update() {
    loom::model(|| {
        let state = Arc::new(AtomicState::new());
        
        let t1 = thread::spawn({
            let state = state.clone();
            move || state.update_tip(block1)
        });
        
        let t2 = thread::spawn({
            let state = state.clone();
            move || state.update_tip(block2)
        });
        
        t1.join().unwrap();
        t2.join().unwrap();
        
        // Verify state is consistent
        assert!(state.is_consistent());
    });
}
```

### 4. Cryptographic Correctness Testing

**Objective:** Verify signature validation and proof verification

#### Test Vectors

```rust
#[test]
fn test_known_good_signatures() {
    // Use test vectors from zcashd or spec
    let test_vectors = load_test_vectors("signature_vectors.json");
    
    for vector in test_vectors {
        let result = verify_signature(
            &vector.signature,
            &vector.message,
            &vector.public_key
        );
        assert_eq!(result.is_ok(), vector.expected_valid);
    }
}

#[test]
fn test_signature_malleability() {
    // Ensure signature verification rejects malleable signatures
    let (sig, msg, pk) = create_valid_signature();
    assert!(verify_signature(&sig, &msg, &pk).is_ok());
    
    // Try to maul the signature
    let mauled = maul_signature(&sig);
    assert!(verify_signature(&mauled, &msg, &pk).is_err());
}
```

#### Differential Testing

```rust
#[test]
fn test_script_verification_matches_zcashd() {
    // For every transaction, verify that Zebra and zcashd agree
    let test_txs = load_test_transactions();
    
    for tx in test_txs {
        let zebra_result = zebra_verify_script(&tx);
        let zcashd_result = zcashd_verify_script(&tx);
        
        assert_eq!(zebra_result.is_ok(), zcashd_result.is_ok(),
                   "Zebra and zcashd disagree on tx verification");
    }
}
```

### 5. DoS Resistance Testing

**Objective:** Ensure node cannot be crashed or resource-exhausted

#### Resource Limits

**Test Cases:**
```rust
#[test]
fn test_max_connections() {
    // Try to open 10000 connections
    let mut connections = vec![];
    for _ in 0..10000 {
        match open_connection() {
            Ok(conn) => connections.push(conn),
            Err(_) => break, // Hit limit, this is expected
        }
    }
    
    // Should have hit limit before 10000
    assert!(connections.len() < 10000);
    
    // Existing connections should still work
    assert!(connections[0].send_ping().is_ok());
}

#[test]
fn test_message_rate_limiting() {
    let peer = connect_to_peer();
    
    // Send 10000 messages rapidly
    for _ in 0..10000 {
        peer.send_message(create_inv_message());
    }
    
    // Peer should be disconnected or rate limited
    // Node should not crash or use excessive CPU
}

#[test]
fn test_large_mempool() {
    // Fill mempool with 100000 transactions
    for i in 0..100000 {
        mempool.insert(create_transaction(i));
    }
    
    // Memory usage should be bounded
    assert!(get_memory_usage() < 1_000_000_000); // 1GB limit
    
    // Mempool should have evicted old/low-fee transactions
    assert!(mempool.len() <= MAX_MEMPOOL_SIZE);
}
```

#### Slow Attack Testing

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_slowloris_attack() {
    // Attacker sends header bytes very slowly
    let mut stream = connect_to_node();
    
    // Send one byte every second
    for byte in message_header {
        stream.write_all(&[byte]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    
    // Connection should timeout before completing header
    // Node should not accumulate many half-open connections
}
```

---

## Automated Testing

### Continuous Fuzzing (OSS-Fuzz)

**Setup OSS-Fuzz Integration:**

```yaml
# .github/workflows/oss-fuzz.yml
name: OSS-Fuzz Integration
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  oss-fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build fuzzers
        run: |
          cargo +nightly fuzz build --release
      - name: Run fuzzers (short test)
        run: |
          FUZZ_TIME=300 ./run_fuzzing.sh
```

### Property-Based Testing (PropTest)

**Example:**

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_message_encode_decode_roundtrip(
        version in any::<u32>(),
        nonce in any::<u64>()
    ) {
        let original = Message::Ping(Nonce(nonce));
        let encoded = encode_message(&original)?;
        let decoded = decode_message(&encoded)?;
        prop_assert_eq!(original, decoded);
    }
    
    #[test]
    fn test_transaction_serialize_deserialize(
        tx in arb_transaction()
    ) {
        let serialized = tx.zcash_serialize_to_vec()?;
        let deserialized = Transaction::zcash_deserialize(&serialized[..])?;
        prop_assert_eq!(tx, deserialized);
    }
}
```

### Mutation Testing (cargo-mutants)

**Check test quality:**

```bash
# Install
cargo install cargo-mutants

# Run mutation testing
cargo mutants --package zebra-network

# Expect: >95% of mutants caught by tests
```

---

## Manual Testing

### Penetration Testing Checklist

- [ ] **Network Fuzzing:** Send malformed messages to running node
- [ ] **RPC Fuzzing:** Send malformed JSON-RPC requests
- [ ] **Eclipse Attack:** Connect node only to malicious peers
- [ ] **Selfish Mining:** Withhold blocks and reorg chain
- [ ] **Long Chain:** Send very deep reorg
- [ ] **Resource Exhaustion:** Fill mempool, open max connections
- [ ] **Timing Attacks:** Measure response times for different inputs
- [ ] **State Corruption:** Modify database files and restart

### Attack Scripts

**Network Message Fuzzing:**

```python
#!/usr/bin/env python3
import socket
import random
import struct

def send_malformed_message(host, port):
    """Send random bytes to node"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    # Send random garbage
    garbage = random.randbytes(10000)
    sock.sendall(garbage)
    
    # Node should not crash
    sock.close()

def send_oversized_message(host, port):
    """Send message larger than 2MB limit"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    # Create message header with huge body length
    magic = b"\x24\xe9\x27\x64"  # Zcash mainnet magic
    command = b"block\x00\x00\x00\x00\x00\x00\x00"
    body_len = struct.pack("<I", 100_000_000)  # 100MB - way over limit
    checksum = b"\x00\x00\x00\x00"
    
    header = magic + command + body_len + checksum
    sock.sendall(header)
    
    # Node should reject without allocating 100MB
    sock.close()

if __name__ == "__main__":
    send_malformed_message("127.0.0.1", 8233)
    send_oversized_message("127.0.0.1", 8233)
    print("✅ Node survived fuzzing")
```

**RPC Fuzzing:**

```bash
#!/bin/bash
# Fuzz JSON-RPC endpoints

# Invalid JSON
curl -X POST http://localhost:8232 -H "Content-Type: application/json" \
  -d '{"method": "getinfo", "params": ['

# Huge parameters
curl -X POST http://localhost:8232 -H "Content-Type: application/json" \
  -d "{\"method\": \"sendrawtransaction\", \"params\": [\"$(head -c 10000000 /dev/zero | base64)\"]}"

# Invalid types
curl -X POST http://localhost:8232 -H "Content-Type: application/json" \
  -d '{"method": "getblock", "params": [123456789]}'  # Should be string

echo "✅ RPC fuzzing complete"
```

---

## Continuous Security

### Security CI/CD Pipeline

```yaml
# .github/workflows/security.yml
name: Security Testing

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Security Audit
        run: |
          cargo install cargo-audit
          cargo audit
      
      - name: Dependency Check
        run: |
          cargo install cargo-deny
          cargo deny check
      
      - name: SAST (Clippy)
        run: |
          cargo clippy --all-targets -- -D warnings
      
      - name: Fuzzing (Quick)
        run: |
          cargo +nightly install cargo-fuzz
          FUZZ_TIME=300 ./run_fuzzing.sh
      
      - name: ASAN Build
        run: |
          RUSTFLAGS="-Z sanitizer=address" cargo +nightly test
      
      - name: UBSAN Build
        run: |
          RUSTFLAGS="-Z sanitizer=undefined" cargo +nightly test
```

### Security Monitoring

**Metrics to Track:**
- Panic rate in production
- Memory usage trends
- Connection failure rate
- Verification error rate
- RPC error rate
- Database corruption incidents

**Alerting:**
```yaml
# Grafana alert rules
- name: High Panic Rate
  condition: rate(panics[5m]) > 1
  action: PagerDuty

- name: Memory Leak
  condition: memory_usage > 8GB for 1h
  action: Email

- name: Verification Failures
  condition: rate(verification_errors[5m]) > 10
  action: Slack
```

---

## Incident Response

### When a Security Issue is Found

1. **Triage (< 1 hour):**
   - Confirm the issue is exploitable
   - Assess severity (CVSS score)
   - Determine affected versions

2. **Containment (< 24 hours):**
   - Private disclosure to maintainers
   - Develop patch
   - Test patch thoroughly

3. **Fix (< 1 week):**
   - Implement fix
   - Security review
   - Create backports for supported versions

4. **Disclosure (coordinated):**
   - Notify users (release notes, security advisory)
   - Publish CVE
   - Release patched versions

### Security Contact

Report security issues to: `security@zfnd.org`

**DO NOT** open public GitHub issues for security vulnerabilities.

---

## Appendix: Tool Installation

```bash
#!/bin/bash
# Install all security testing tools

# Rust toolchains
rustup install nightly
rustup component add clippy

# Fuzzing
cargo install cargo-fuzz

# Auditing
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-outdated

# Mutation testing
cargo install cargo-mutants

# Coverage
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov

# Sanitizers (already included in nightly)

# Optional: valgrind, gdb, etc.
sudo apt-get install -y valgrind gdb

echo "✅ All tools installed"
```

---

## Summary Checklist

**Before Every Release:**

- [ ] Run full test suite (unit + integration)
- [ ] Run fuzzing campaign (24+ hours per target)
- [ ] Run all sanitizers (ASAN, MSAN, TSAN, UBSAN)
- [ ] Security audit of changes
- [ ] Dependency audit (`cargo audit`)
- [ ] Check for known vulnerabilities
- [ ] Review new `unsafe` code
- [ ] Performance testing (no DoS regressions)
- [ ] Manual penetration testing
- [ ] Update SECURITY.md with supported versions

**Continuous Monitoring:**

- [ ] OSS-Fuzz running daily
- [ ] Security alerts configured
- [ ] Metrics dashboard monitoring
- [ ] Incident response plan tested

---

**Document Version:** 1.0  
**Last Updated:** 2026-05-14  
**Next Review:** Quarterly
