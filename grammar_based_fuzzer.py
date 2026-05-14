#!/usr/bin/env python3
"""
Grammar-Based Fuzzer for Zebra Protocol Messages
Generates syntactically valid and invalid variants of P2P messages, transactions, and blocks
Forces diversity injection to escape local minima
"""

import struct
import random
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)


class MessageType(Enum):
    """Zcash P2P message types"""
    VERSION = b"version\x00\x00\x00\x00\x00"
    VERACK = b"verack\x00\x00\x00\x00\x00\x00"
    ADDR = b"addr\x00\x00\x00\x00\x00\x00\x00\x00"
    INV = b"inv\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    GETDATA = b"getdata\x00\x00\x00\x00\x00"
    GETBLOCKS = b"getblocks\x00\x00\x00"
    GETHEADERS = b"getheaders\x00\x00"
    TX = b"tx\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    BLOCK = b"block\x00\x00\x00\x00\x00\x00\x00"
    HEADERS = b"headers\x00\x00\x00\x00\x00"
    PING = b"ping\x00\x00\x00\x00\x00\x00\x00\x00"
    PONG = b"pong\x00\x00\x00\x00\x00\x00\x00\x00"
    REJECT = b"reject\x00\x00\x00\x00\x00\x00"
    MEMPOOL = b"mempool\x00\x00\x00\x00\x00"


@dataclass
class ProtocolGrammar:
    """Defines protocol grammar rules for generation"""
    name: str
    required_fields: List[str]
    optional_fields: List[str]
    constraints: Dict[str, Any]


class GrammarBasedFuzzer:
    """Generates diverse protocol messages based on grammar"""
    
    MAGIC_MAINNET = 0x6427e924
    MAGIC_TESTNET = 0xbff91afa
    MAGIC_REGTEST = 0x5f3fe8aa
    
    def __init__(self, output_dir: Path, network: str = "mainnet"):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if network == "mainnet":
            self.magic = self.MAGIC_MAINNET
        elif network == "testnet":
            self.magic = self.MAGIC_TESTNET
        else:
            self.magic = self.MAGIC_REGTEST
        
        self.seed_counter = 0
    
    def generate_message_header(self, command: bytes, payload: bytes) -> bytes:
        """Generate Zcash P2P message header"""
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        header = struct.pack(
            '<I12sI4s',
            self.magic,
            command,
            len(payload),
            checksum
        )
        
        return header + payload
    
    def generate_version_message(self, corrupt: bool = False) -> bytes:
        """Generate version message with optional corruption"""
        version = 170002 if not corrupt else random.randint(0, 0xFFFFFFFF)
        services = 1
        timestamp = random.randint(1600000000, 1700000000)
        
        addr_recv = b'\x00' * 26
        addr_from = b'\x00' * 26
        nonce = random.randint(0, 0xFFFFFFFFFFFFFFFF)
        user_agent = b'\x0F/Zebra:1.0.0/'
        start_height = random.randint(0, 2000000)
        relay = 1
        
        payload = struct.pack(
            '<IQQ',
            version,
            services,
            timestamp
        )
        payload += addr_recv
        payload += addr_from
        payload += struct.pack('<Q', nonce)
        payload += user_agent
        payload += struct.pack('<I?', start_height, relay)
        
        if corrupt:
            payload = self.corrupt_payload(payload)
        
        return self.generate_message_header(MessageType.VERSION.value, payload)
    
    def generate_tx_message(self, tx_version: int = 4, corrupt: bool = False) -> bytes:
        """Generate transaction message"""
        header = struct.pack('<I', tx_version if not corrupt else random.randint(1, 10))
        
        num_inputs = random.randint(0, 5) if not corrupt else random.randint(0, 1000)
        num_outputs = random.randint(0, 5) if not corrupt else random.randint(0, 1000)
        
        inputs = self.generate_compact_size(num_inputs)
        for _ in range(min(num_inputs, 10)):
            inputs += self.generate_tx_input(corrupt)
        
        outputs = self.generate_compact_size(num_outputs)
        for _ in range(min(num_outputs, 10)):
            outputs += self.generate_tx_output(corrupt)
        
        lock_time = struct.pack('<I', 0)
        
        payload = header + inputs + outputs + lock_time
        
        if corrupt:
            payload = self.corrupt_payload(payload)
        
        return self.generate_message_header(MessageType.TX.value, payload)
    
    def generate_block_message(self, corrupt: bool = False) -> bytes:
        """Generate block message"""
        version = 4 if not corrupt else random.randint(1, 10)
        prev_block = random.randbytes(32)
        merkle_root = random.randbytes(32)
        timestamp = random.randint(1600000000, 1700000000)
        bits = 0x1d00ffff
        nonce = random.randbytes(32)
        
        header = struct.pack('<I', version)
        header += prev_block
        header += merkle_root
        header += merkle_root
        header += struct.pack('<II', timestamp, bits)
        header += nonce
        
        solution = b'\x00' * 100
        
        num_txs = random.randint(1, 3) if not corrupt else random.randint(0, 10000)
        txs = self.generate_compact_size(num_txs)
        
        for _ in range(min(num_txs, 5)):
            txs += self.generate_tx_message(corrupt=corrupt)[24:]
        
        payload = header + solution + txs
        
        if corrupt:
            payload = self.corrupt_payload(payload)
        
        return self.generate_message_header(MessageType.BLOCK.value, payload)
    
    def generate_tx_input(self, corrupt: bool = False) -> bytes:
        """Generate transaction input"""
        prev_hash = random.randbytes(32)
        prev_index = struct.pack('<I', random.randint(0, 10))
        
        script_len = random.randint(0, 100) if not corrupt else random.randint(0, 10000)
        script = random.randbytes(min(script_len, 200))
        
        sequence = struct.pack('<I', 0xFFFFFFFF)
        
        return prev_hash + prev_index + self.generate_compact_size(len(script)) + script + sequence
    
    def generate_tx_output(self, corrupt: bool = False) -> bytes:
        """Generate transaction output"""
        value = struct.pack('<Q', random.randint(1000, 100000000))
        
        script_len = random.randint(25, 100) if not corrupt else random.randint(0, 10000)
        script = random.randbytes(min(script_len, 200))
        
        return value + self.generate_compact_size(len(script)) + script
    
    def generate_compact_size(self, n: int) -> bytes:
        """Generate Bitcoin-style compact size encoding"""
        if n < 0xFD:
            return struct.pack('<B', n)
        elif n <= 0xFFFF:
            return struct.pack('<BH', 0xFD, n)
        elif n <= 0xFFFFFFFF:
            return struct.pack('<BI', 0xFE, n)
        else:
            return struct.pack('<BQ', 0xFF, n)
    
    def corrupt_payload(self, payload: bytes) -> bytes:
        """Apply random corruption to payload"""
        corruption_type = random.choice([
            'flip_bits',
            'truncate',
            'extend',
            'replace_bytes',
            'swap_chunks'
        ])
        
        if corruption_type == 'flip_bits':
            pos = random.randint(0, len(payload) - 1)
            payload = bytearray(payload)
            payload[pos] ^= random.randint(1, 255)
            return bytes(payload)
        
        elif corruption_type == 'truncate':
            cut = random.randint(0, len(payload))
            return payload[:cut]
        
        elif corruption_type == 'extend':
            return payload + random.randbytes(random.randint(1, 100))
        
        elif corruption_type == 'replace_bytes':
            if len(payload) > 4:
                pos = random.randint(0, len(payload) - 4)
                payload = bytearray(payload)
                payload[pos:pos+4] = random.randbytes(4)
                return bytes(payload)
        
        elif corruption_type == 'swap_chunks':
            if len(payload) > 8:
                a = random.randint(0, len(payload) // 2)
                b = random.randint(len(payload) // 2, len(payload) - 1)
                payload = bytearray(payload)
                payload[a], payload[b] = payload[b], payload[a]
                return bytes(payload)
        
        return payload
    
    def generate_seed_corpus(self, num_seeds: int = 1000):
        """Generate complete seed corpus with diversity"""
        log.info(f"Generating {num_seeds} diverse seed inputs...")
        
        message_generators = [
            ('version', lambda c: self.generate_version_message(corrupt=c)),
            ('tx_v4', lambda c: self.generate_tx_message(tx_version=4, corrupt=c)),
            ('tx_v5', lambda c: self.generate_tx_message(tx_version=5, corrupt=c)),
            ('block', lambda c: self.generate_block_message(corrupt=c)),
        ]
        
        for i in range(num_seeds):
            msg_type, generator = random.choice(message_generators)
            
            corrupt = i > num_seeds // 2
            
            try:
                message = generator(corrupt=corrupt)
                
                filename = f"{msg_type}_{i:06d}{'_corrupt' if corrupt else ''}"
                output_file = self.output_dir / filename
                
                with open(output_file, 'wb') as f:
                    f.write(message)
                
                if i % 100 == 0:
                    log.info(f"Generated {i}/{num_seeds} seeds...")
            
            except Exception as e:
                log.error(f"Failed to generate seed {i}: {e}")
        
        log.info(f"✓ Generated {num_seeds} seeds in {self.output_dir}")
    
    def generate_semantic_mutations(self):
        """Generate semantically interesting mutations"""
        log.info("Generating semantic mutation seeds...")
        
        mutations = [
            ('version_mismatch', self.version_mismatch_seed),
            ('oversized_vector', self.oversized_vector_seed),
            ('negative_value', self.negative_value_seed),
            ('invalid_script', self.invalid_script_seed),
            ('malformed_header', self.malformed_header_seed),
        ]
        
        for name, mutation_func in mutations:
            try:
                seed = mutation_func()
                output_file = self.output_dir / f"semantic_{name}"
                with open(output_file, 'wb') as f:
                    f.write(seed)
                log.info(f"  ✓ {name}")
            except Exception as e:
                log.error(f"  ✗ {name}: {e}")
    
    def version_mismatch_seed(self) -> bytes:
        """Transaction with version field mismatch"""
        return self.generate_tx_message(tx_version=999, corrupt=False)
    
    def oversized_vector_seed(self) -> bytes:
        """Message with oversized vector length"""
        header = struct.pack('<I', 4)
        num_inputs = self.generate_compact_size(0xFFFFFFF)
        return self.generate_message_header(MessageType.TX.value, header + num_inputs)
    
    def negative_value_seed(self) -> bytes:
        """Transaction output with negative value"""
        tx = bytearray(self.generate_tx_message())
        if len(tx) > 100:
            tx[80:88] = struct.pack('<q', -1000000)
        return bytes(tx)
    
    def invalid_script_seed(self) -> bytes:
        """Transaction with malformed script"""
        header = struct.pack('<I', 4)
        num_inputs = self.generate_compact_size(1)
        
        prev_hash = random.randbytes(32)
        prev_index = struct.pack('<I', 0)
        
        script = b'\xFF' * 200
        script_len = self.generate_compact_size(len(script))
        sequence = struct.pack('<I', 0xFFFFFFFF)
        
        tx_input = prev_hash + prev_index + script_len + script + sequence
        
        num_outputs = self.generate_compact_size(0)
        lock_time = struct.pack('<I', 0)
        
        payload = header + num_inputs + tx_input + num_outputs + lock_time
        return self.generate_message_header(MessageType.TX.value, payload)
    
    def malformed_header_seed(self) -> bytes:
        """Block with malformed header"""
        header = random.randbytes(100)
        return self.generate_message_header(MessageType.BLOCK.value, header)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Grammar-based protocol fuzzer')
    parser.add_argument('--output', type=Path, default=Path('grammar_seeds'),
                       help='Output directory for generated seeds')
    parser.add_argument('--num-seeds', type=int, default=1000,
                       help='Number of seeds to generate')
    parser.add_argument('--network', choices=['mainnet', 'testnet', 'regtest'],
                       default='mainnet', help='Network type')
    
    args = parser.parse_args()
    
    fuzzer = GrammarBasedFuzzer(args.output, args.network)
    fuzzer.generate_seed_corpus(args.num_seeds)
    fuzzer.generate_semantic_mutations()
    
    log.info("✓ Grammar-based seed generation complete")


if __name__ == "__main__":
    main()
