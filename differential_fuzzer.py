#!/usr/bin/env python3
"""
Structure-Aware Differential Fuzzer for Zebra vs zcashd
Finds semantic consensus bugs that don't crash but cause divergence
"""

import subprocess
import json
import time
import socket
import struct
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)


class MutationType(Enum):
    """Types of semantic mutations"""
    VERSION_MISMATCH = "version_mismatch"
    OUTPUT_COUNT_MISMATCH = "output_count_mismatch"
    NETWORK_KEY_SWAP = "network_key_swap"
    DOUBLE_SPEND = "double_spend"
    TIMELOCK_BOUNDARY = "timelock_boundary"
    MALFORMED_PROOF = "malformed_proof"
    SCRIPT_SEMANTIC = "script_semantic"
    AMOUNT_OVERFLOW = "amount_overflow"


@dataclass
class Transaction:
    """Simplified transaction representation"""
    version: int
    inputs: List[bytes]
    outputs: List[bytes]
    locktime: int
    raw_bytes: bytes
    
    @classmethod
    def parse(cls, raw: bytes) -> 'Transaction':
        """Parse raw transaction bytes"""
        # Simplified parsing - in production would use proper parser
        if len(raw) < 10:
            raise ValueError("Transaction too short")
        
        version = struct.unpack('<I', raw[0:4])[0]
        locktime = struct.unpack('<I', raw[-4:])[0] if len(raw) >= 4 else 0
        
        return cls(
            version=version,
            inputs=[],
            outputs=[],
            locktime=locktime,
            raw_bytes=raw
        )
    
    def serialize(self) -> bytes:
        """Serialize transaction"""
        return self.raw_bytes
    
    def txid(self) -> str:
        """Calculate transaction ID"""
        return hashlib.sha256(hashlib.sha256(self.raw_bytes).digest()).hexdigest()


@dataclass
class Block:
    """Simplified block representation"""
    version: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    transactions: List[Transaction]
    raw_bytes: bytes
    
    @classmethod
    def parse(cls, raw: bytes) -> 'Block':
        """Parse raw block bytes"""
        if len(raw) < 80:
            raise ValueError("Block header too short")
        
        version = struct.unpack('<I', raw[0:4])[0]
        prev_hash = raw[4:36]
        merkle_root = raw[36:68]
        timestamp = struct.unpack('<I', raw[68:72])[0]
        bits = struct.unpack('<I', raw[72:76])[0]
        nonce = struct.unpack('<I', raw[76:80])[0]
        
        return cls(
            version=version,
            prev_hash=prev_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            bits=bits,
            nonce=nonce,
            transactions=[],
            raw_bytes=raw
        )
    
    def serialize(self) -> bytes:
        """Serialize block"""
        return self.raw_bytes


class SemanticMutator:
    """Applies semantic mutations to transactions/blocks"""
    
    def __init__(self):
        self.mutation_count = 0
    
    def mutate_version_mismatch(self, tx: Transaction) -> Transaction:
        """Change version but keep structure of old version"""
        log.debug(f"Mutating tx version: {tx.version} -> 5")
        
        # Modify version bytes
        raw = bytearray(tx.raw_bytes)
        struct.pack_into('<I', raw, 0, 5)
        
        tx.version = 5
        tx.raw_bytes = bytes(raw)
        self.mutation_count += 1
        return tx
    
    def mutate_output_count_mismatch(self, tx: Transaction) -> Transaction:
        """Change output count but keep proof size"""
        log.debug("Mutating output count")
        
        # This would require deeper parsing
        # Placeholder for now
        self.mutation_count += 1
        return tx
    
    def mutate_network_key_swap(self, tx: Transaction) -> Transaction:
        """Swap testnet/mainnet keys"""
        log.debug("Swapping network keys")
        
        raw = bytearray(tx.raw_bytes)
        # Find and swap network magic bytes
        # Mainnet: 0x24e92764, Testnet: 0xfa1af9bf
        mainnet = b'\x24\xe9\x27\x64'
        testnet = b'\xfa\x1a\xf9\xbf'
        
        raw_bytes = bytes(raw)
        if mainnet in raw_bytes:
            raw_bytes = raw_bytes.replace(mainnet, testnet)
            log.debug("Swapped mainnet -> testnet")
        elif testnet in raw_bytes:
            raw_bytes = raw_bytes.replace(testnet, mainnet)
            log.debug("Swapped testnet -> mainnet")
        
        tx.raw_bytes = raw_bytes
        self.mutation_count += 1
        return tx
    
    def mutate_timelock_boundary(self, tx: Transaction, skew: int) -> Transaction:
        """Modify timelock near boundary"""
        log.debug(f"Mutating timelock with skew {skew}")
        
        raw = bytearray(tx.raw_bytes)
        # Modify locktime
        new_locktime = max(0, tx.locktime + skew)
        struct.pack_into('<I', raw, len(raw) - 4, new_locktime)
        
        tx.locktime = new_locktime
        tx.raw_bytes = bytes(raw)
        self.mutation_count += 1
        return tx
    
    def mutate_amount_overflow(self, tx: Transaction) -> Transaction:
        """Create amount near overflow boundary"""
        log.debug("Mutating amount to near-overflow")
        
        # This requires parsing output amounts
        # Placeholder
        self.mutation_count += 1
        return tx
    
    def apply_mutation(self, tx: Transaction, mutation_type: MutationType) -> Transaction:
        """Apply specified mutation"""
        mutation_map = {
            MutationType.VERSION_MISMATCH: lambda: self.mutate_version_mismatch(tx),
            MutationType.NETWORK_KEY_SWAP: lambda: self.mutate_network_key_swap(tx),
            MutationType.TIMELOCK_BOUNDARY: lambda: self.mutate_timelock_boundary(tx, 1000),
            MutationType.OUTPUT_COUNT_MISMATCH: lambda: self.mutate_output_count_mismatch(tx),
            MutationType.AMOUNT_OVERFLOW: lambda: self.mutate_amount_overflow(tx),
        }
        
        mutator = mutation_map.get(mutation_type)
        if mutator:
            return mutator()
        return tx


class NodeInterface:
    """Interface to Zebra/zcashd nodes"""
    
    def __init__(self, node_type: str, host: str = "localhost", port: int = 8233, rpc_port: int = 8232):
        self.node_type = node_type
        self.host = host
        self.port = port
        self.rpc_port = rpc_port
    
    def send_transaction(self, tx: Transaction) -> Dict:
        """Send transaction to node via RPC"""
        try:
            cmd = [
                "bitcoin-cli" if self.node_type == "zcashd" else "bitcoin-cli",
                f"-rpcport={self.rpc_port}",
                "sendrawtransaction",
                tx.serialize().hex()
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout.strip(),
                'error': result.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_chain_tip(self) -> Dict:
        """Get current chain tip"""
        try:
            cmd = [
                "bitcoin-cli" if self.node_type == "zcashd" else "bitcoin-cli",
                f"-rpcport={self.rpc_port}",
                "getblockchaininfo"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return json.loads(result.stdout)
            return {}
        except Exception as e:
            log.error(f"Failed to get chain tip: {e}")
            return {}
    
    def get_mempool(self) -> List[str]:
        """Get mempool contents"""
        try:
            cmd = [
                "bitcoin-cli" if self.node_type == "zcashd" else "bitcoin-cli",
                f"-rpcport={self.rpc_port}",
                "getrawmempool"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return json.loads(result.stdout)
            return []
        except Exception as e:
            log.error(f"Failed to get mempool: {e}")
            return []


@dataclass
class DivergenceReport:
    """Report of divergence between nodes"""
    mutation_type: MutationType
    tx_id: str
    zebra_response: Dict
    zcashd_response: Dict
    severity: str
    description: str
    timestamp: float
    
    def to_dict(self) -> Dict:
        return {
            'mutation_type': self.mutation_type.value,
            'tx_id': self.tx_id,
            'zebra': self.zebra_response,
            'zcashd': self.zcashd_response,
            'severity': self.severity,
            'description': self.description,
            'timestamp': self.timestamp
        }


class DifferentialOracle:
    """Compares Zebra and zcashd responses"""
    
    def __init__(self, zebra: NodeInterface, zcashd: NodeInterface):
        self.zebra = zebra
        self.zcashd = zcashd
        self.divergences: List[DivergenceReport] = []
    
    def compare_transaction_acceptance(
        self,
        tx: Transaction,
        mutation_type: MutationType
    ) -> Optional[DivergenceReport]:
        """Send transaction to both nodes and compare"""
        
        log.info(f"Testing transaction {tx.txid()[:16]}... with {mutation_type.value}")
        
        # Send to both nodes
        zebra_result = self.zebra.send_transaction(tx)
        time.sleep(0.5)  # Brief delay
        zcashd_result = self.zcashd.send_transaction(tx)
        
        # Compare results
        zebra_accepted = zebra_result['success']
        zcashd_accepted = zcashd_result['success']
        
        if zebra_accepted != zcashd_accepted:
            # DIVERGENCE FOUND!
            severity = "CRITICAL" if zebra_accepted and not zcashd_accepted else "HIGH"
            
            description = f"Zebra {'accepted' if zebra_accepted else 'rejected'}, "
            description += f"zcashd {'accepted' if zcashd_accepted else 'rejected'}"
            
            report = DivergenceReport(
                mutation_type=mutation_type,
                tx_id=tx.txid(),
                zebra_response=zebra_result,
                zcashd_response=zcashd_result,
                severity=severity,
                description=description,
                timestamp=time.time()
            )
            
            self.divergences.append(report)
            log.error(f"🚨 DIVERGENCE FOUND: {description}")
            return report
        
        log.debug(f"Both nodes: {'accepted' if zebra_accepted else 'rejected'}")
        return None
    
    def compare_chain_state(self) -> Optional[DivergenceReport]:
        """Compare chain tips"""
        zebra_tip = self.zebra.get_chain_tip()
        zcashd_tip = self.zcashd.get_chain_tip()
        
        zebra_height = zebra_tip.get('blocks', 0)
        zcashd_height = zcashd_tip.get('blocks', 0)
        
        zebra_hash = zebra_tip.get('bestblockhash', '')
        zcashd_hash = zcashd_tip.get('bestblockhash', '')
        
        if zebra_height == zcashd_height and zebra_hash != zcashd_hash:
            # Same height, different hash = CONSENSUS SPLIT!
            report = DivergenceReport(
                mutation_type=MutationType.DOUBLE_SPEND,
                tx_id="N/A",
                zebra_response={'tip': zebra_hash, 'height': zebra_height},
                zcashd_response={'tip': zcashd_hash, 'height': zcashd_height},
                severity="CRITICAL",
                description="CONSENSUS SPLIT: Same height, different best block",
                timestamp=time.time()
            )
            
            self.divergences.append(report)
            log.error(f"🚨🚨🚨 CONSENSUS SPLIT DETECTED 🚨🚨🚨")
            return report
        
        return None


class DifferentialFuzzingCampaign:
    """Main differential fuzzing orchestrator"""
    
    def __init__(self, workspace: Path, seed_corpus: Path):
        self.workspace = workspace
        self.seed_corpus = seed_corpus
        self.mutator = SemanticMutator()
        
        # Node interfaces
        self.zebra = NodeInterface("zebra", port=8233, rpc_port=8232)
        self.zcashd = NodeInterface("zcashd", port=8333, rpc_port=8332)
        
        self.oracle = DifferentialOracle(self.zebra, self.zcashd)
        
        # Results
        self.results_dir = workspace / "differential_results"
        self.results_dir.mkdir(exist_ok=True)
        
        self.stats = {
            'transactions_tested': 0,
            'mutations_applied': 0,
            'divergences_found': 0,
            'consensus_splits': 0
        }
    
    def load_seed_transactions(self) -> List[Transaction]:
        """Load seed transactions from corpus"""
        transactions = []
        
        if not self.seed_corpus.exists():
            log.warning(f"Seed corpus not found: {self.seed_corpus}")
            return transactions
        
        for seed_file in self.seed_corpus.iterdir():
            if seed_file.is_file():
                try:
                    with open(seed_file, 'rb') as f:
                        raw = f.read()
                    
                    # Try to parse as transaction
                    tx = Transaction.parse(raw)
                    transactions.append(tx)
                except Exception as e:
                    log.debug(f"Failed to parse {seed_file.name}: {e}")
        
        log.info(f"Loaded {len(transactions)} seed transactions")
        return transactions
    
    def run_campaign(self, iterations: int = 1000):
        """Run differential fuzzing campaign"""
        log.info("Starting differential fuzzing campaign")
        log.info(f"Iterations: {iterations}")
        
        # Load seeds
        seed_txs = self.load_seed_transactions()
        
        if not seed_txs:
            log.warning("No seed transactions - generating synthetic ones")
            seed_txs = self.generate_synthetic_seeds(10)
        
        # Main fuzzing loop
        for iteration in range(iterations):
            log.info(f"\n{'='*60}")
            log.info(f"ITERATION {iteration + 1}/{iterations}")
            log.info(f"{'='*60}\n")
            
            # Pick random seed
            import random
            seed_tx = random.choice(seed_txs)
            
            # Apply all mutation types
            for mutation_type in MutationType:
                # Clone transaction
                mutated_tx = Transaction(
                    version=seed_tx.version,
                    inputs=seed_tx.inputs.copy(),
                    outputs=seed_tx.outputs.copy(),
                    locktime=seed_tx.locktime,
                    raw_bytes=seed_tx.raw_bytes
                )
                
                # Apply mutation
                try:
                    mutated_tx = self.mutator.apply_mutation(mutated_tx, mutation_type)
                    self.stats['mutations_applied'] += 1
                except Exception as e:
                    log.debug(f"Mutation failed: {e}")
                    continue
                
                # Test differential behavior
                divergence = self.oracle.compare_transaction_acceptance(
                    mutated_tx,
                    mutation_type
                )
                
                self.stats['transactions_tested'] += 1
                
                if divergence:
                    self.stats['divergences_found'] += 1
                    self.save_divergence(divergence)
                
                # Brief pause
                time.sleep(0.1)
            
            # Check for chain divergence every 10 iterations
            if iteration % 10 == 0:
                split = self.oracle.compare_chain_state()
                if split:
                    self.stats['consensus_splits'] += 1
                    self.save_divergence(split)
            
            # Save stats
            if iteration % 100 == 0:
                self.save_stats()
        
        # Final report
        self.generate_report()
    
    def generate_synthetic_seeds(self, count: int) -> List[Transaction]:
        """Generate synthetic seed transactions"""
        log.info(f"Generating {count} synthetic seed transactions")
        seeds = []
        
        for i in range(count):
            # Create minimal valid transaction structure
            raw = struct.pack('<I', 4)  # version
            raw += b'\x00' * 100  # dummy data
            raw += struct.pack('<I', 0)  # locktime
            
            try:
                tx = Transaction.parse(raw)
                seeds.append(tx)
            except:
                pass
        
        return seeds
    
    def save_divergence(self, divergence: DivergenceReport):
        """Save divergence to disk"""
        filename = f"divergence_{int(divergence.timestamp)}_{divergence.mutation_type.value}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(divergence.to_dict(), f, indent=2)
        
        log.info(f"Divergence saved: {filepath}")
    
    def save_stats(self):
        """Save statistics"""
        stats_file = self.workspace / "differential_stats.json"
        with open(stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
    
    def generate_report(self):
        """Generate final report"""
        report_file = self.workspace / "differential_fuzzing_report.md"
        
        with open(report_file, 'w') as f:
            f.write("# Differential Fuzzing Report: Zebra vs zcashd\n\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Statistics\n\n")
            f.write(f"- Transactions tested: {self.stats['transactions_tested']}\n")
            f.write(f"- Mutations applied: {self.stats['mutations_applied']}\n")
            f.write(f"- Divergences found: {self.stats['divergences_found']}\n")
            f.write(f"- Consensus splits: {self.stats['consensus_splits']}\n\n")
            
            f.write("## Divergences\n\n")
            
            if self.oracle.divergences:
                for div in self.oracle.divergences:
                    f.write(f"### {div.severity}: {div.mutation_type.value}\n\n")
                    f.write(f"- TX ID: `{div.tx_id}`\n")
                    f.write(f"- Description: {div.description}\n")
                    f.write(f"- Zebra: {div.zebra_response}\n")
                    f.write(f"- zcashd: {div.zcashd_response}\n\n")
            else:
                f.write("✅ No divergences found. Zebra and zcashd are consistent.\n\n")
        
        log.info(f"Report generated: {report_file}")


def main():
    workspace = Path.cwd()
    seed_corpus = workspace / "fuzz" / "corpus" / "network_codec"
    
    campaign = DifferentialFuzzingCampaign(workspace, seed_corpus)
    campaign.run_campaign(iterations=1000)


if __name__ == "__main__":
    main()
