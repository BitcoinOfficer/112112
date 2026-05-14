# Zebra Fuzzing Infrastructure

This directory contains fuzzing harnesses for Zebra's network attack surface.

## Overview

Fuzzing is critical for finding edge cases in deserialization, validation, and consensus logic that could lead to:
- Crashes (panics, unwraps on untrusted data)
- Consensus failures
- Memory exhaustion
- CPU exhaustion

## Setup

### Install cargo-fuzz

```bash
cargo install cargo-fuzz
```

### Install AFL++ (alternative fuzzer)

```bash
cargo install cargo-afl
```

## Running Fuzzers

### Using cargo-fuzz (libFuzzer)

```bash
# Fuzz message codec
cargo fuzz run fuzz_message_codec

# Fuzz with custom corpus
cargo fuzz run fuzz_message_codec fuzz/corpus/message_codec

# Run all fuzzers in parallel
cargo fuzz run --jobs 8 fuzz_message_codec
```

### Using AFL++

```bash
# Build instrumented binary
cargo afl build --release

# Run fuzzer
cargo afl fuzz -i fuzz/corpus/message_codec -o fuzz/findings target/release/fuzz_message_codec
```

## Fuzzing Targets

### Network Message Deserialization

- **fuzz_message_codec**: Fuzzes the main message codec decode path
- **fuzz_version_message**: Specifically targets version message parsing
- **fuzz_addr_message**: Fuzzes addr/addrv2 message parsing
- **fuzz_block_header**: Fuzzes block header deserialization
- **fuzz_transaction**: Fuzzes transaction deserialization (all versions)

### Consensus-Critical Logic

- **fuzz_difficulty**: Fuzzes compact difficulty calculations
- **fuzz_equihash**: Fuzzes Equihash solution verification
- **fuzz_script_verify**: Fuzzes transparent script verification

### Collection Bounds

- **fuzz_compact_size**: Fuzzes CompactSize parsing edge cases
- **fuzz_trusted_preallocate**: Tests allocation bounds

## Corpus Management

### Initial Corpus

Seed the corpus with:
1. Real mainnet messages captured from the network
2. Testnet messages
3. Manually constructed edge cases
4. Existing test vectors

### Minimizing Corpus

```bash
# Minimize corpus to remove redundant inputs
cargo fuzz cmin fuzz_message_codec
```

### Merging Corpora

```bash
# Merge findings from multiple runs
cargo fuzz cmin -M fuzz_message_codec \
    fuzz/corpus/message_codec \
    fuzz/findings/message_codec/queue
```

## CI Integration

Fuzzing should run continuously in CI:

```yaml
name: Continuous Fuzzing

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours

jobs:
  fuzz:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        target:
          - fuzz_message_codec
          - fuzz_block_header
          - fuzz_transaction
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run ${{ matrix.target }} -- -max_total_time=3600
```

## Coverage-Guided Fuzzing

Track code coverage to identify unexplored branches:

```bash
# Generate coverage report
cargo fuzz coverage fuzz_message_codec
cargo cov -- show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_message_codec \
    --format=html \
    --output-dir=coverage \
    --instr-profile=fuzz/coverage/fuzz_message_codec/coverage.profdata
```

## Crash Triage

When fuzzing finds a crash:

1. Reproduce the crash:
   ```bash
   cargo fuzz run fuzz_message_codec fuzz/findings/crash-abc123
   ```

2. Minimize the crashing input:
   ```bash
   cargo fuzz tmin fuzz_message_codec fuzz/findings/crash-abc123
   ```

3. Convert to a regression test:
   ```bash
   # Add to zebra-network/src/protocol/external/codec/tests/vectors.rs
   ```

## Best Practices

1. **Run fuzzing continuously**: Don't just run once - fuzzing improves over time
2. **Seed with real data**: Start with real network captures and test vectors
3. **Minimize findings**: Reduce crashing inputs to minimal reproducers
4. **Add regression tests**: Every crash should become a test case
5. **Track coverage**: Monitor branch coverage to find under-tested code
6. **Parallelize**: Run multiple fuzzer instances in parallel
7. **Set dictionaries**: Provide magic constants (network magic, command strings) to guide fuzzing

## Security Response

If fuzzing discovers a security vulnerability:

1. **Do not commit crashing input** to public repository
2. Follow the security disclosure policy in SECURITY.md
3. Coordinate with the Zebra security team
4. Add regression test after fix is deployed
