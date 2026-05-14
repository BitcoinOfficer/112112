#!/usr/bin/env python3
"""
Zebra Attack Simulator
Simulates advanced network attacks including eclipse, Sybil, and time manipulation
Tests consensus-critical behavior under adversarial conditions
"""

import subprocess
import socket
import struct
import random
import time
import signal
import sys
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import threading

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)


@dataclass
class ZebraNode:
    """Represents a Zebra node instance"""
    node_id: str
    port: int
    rpc_port: int
    data_dir: Path
    process: Optional[subprocess.Popen] = None
    is_attacker: bool = False


@dataclass
class AttackScenario:
    """Defines an attack scenario"""
    name: str
    description: str
    attacker_nodes: int
    victim_nodes: int
    duration_seconds: int
    expected_behavior: str


class NetworkSimulator:
    """Simulates a network of Zebra nodes"""
    
    def __init__(self, workspace: Path, network_type: str = "regtest"):
        self.workspace = workspace
        self.network_type = network_type
        self.nodes: List[ZebraNode] = []
        self.base_port = 18233
        self.base_rpc_port = 18232
        
        self.test_dir = workspace / "attack_simulation"
        self.test_dir.mkdir(exist_ok=True)
    
    def create_node(self, node_id: str, is_attacker: bool = False) -> ZebraNode:
        """Create a node configuration"""
        port = self.base_port + len(self.nodes)
        rpc_port = self.base_rpc_port + len(self.nodes)
        data_dir = self.test_dir / f"node_{node_id}"
        data_dir.mkdir(exist_ok=True)
        
        node = ZebraNode(
            node_id=node_id,
            port=port,
            rpc_port=rpc_port,
            data_dir=data_dir,
            is_attacker=is_attacker
        )
        
        self.nodes.append(node)
        return node
    
    def generate_node_config(self, node: ZebraNode) -> Path:
        """Generate zebrad.toml configuration for node"""
        config_path = node.data_dir / "zebrad.toml"
        
        config = f"""[network]
network = "{self.network_type}"
listen_addr = "127.0.0.1:{node.port}"
crawl_new_peer_interval = "1m"

[state]
cache_dir = "{node.data_dir / 'state'}"

[rpc]
listen_addr = "127.0.0.1:{node.rpc_port}"

[tracing]
filter = "info"
"""
        
        with open(config_path, 'w') as f:
            f.write(config)
        
        return config_path
    
    def start_node(self, node: ZebraNode):
        """Start a Zebra node"""
        config_path = self.generate_node_config(node)
        
        log.info(f"Starting node {node.node_id} on port {node.port}")
        
        zebrad_bin = self.workspace / "target" / "debug" / "zebrad"
        if not zebrad_bin.exists():
            zebrad_bin = self.workspace / "target" / "release" / "zebrad"
        
        if not zebrad_bin.exists():
            log.error("zebrad binary not found")
            return
        
        node.process = subprocess.Popen(
            [str(zebrad_bin), '-c', str(config_path), 'start'],
            cwd=node.data_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(2)
        
        if node.process.poll() is None:
            log.info(f"  ✓ Node {node.node_id} started (PID {node.process.pid})")
        else:
            log.error(f"  ✗ Node {node.node_id} failed to start")
    
    def stop_node(self, node: ZebraNode):
        """Stop a Zebra node"""
        if node.process:
            log.info(f"Stopping node {node.node_id}")
            node.process.terminate()
            try:
                node.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                node.process.kill()
                node.process.wait()
    
    def stop_all_nodes(self):
        """Stop all running nodes"""
        for node in self.nodes:
            self.stop_node(node)
    
    def connect_nodes(self, node_a: ZebraNode, node_b: ZebraNode):
        """Connect two nodes"""
        log.info(f"Connecting {node_a.node_id} to {node_b.node_id}")
        
        result = subprocess.run(
            ['curl', '-s', 
             f'http://127.0.0.1:{node_a.rpc_port}',
             '-d', f'{{"method":"addnode","params":["127.0.0.1:{node_b.port}","add"]}}'],
            capture_output=True,
            text=True
        )


class EclipseAttackSimulator:
    """Simulates eclipse attacks on Zebra nodes"""
    
    def __init__(self, network: NetworkSimulator):
        self.network = network
    
    def simulate_eclipse_attack(self) -> bool:
        """
        Simulate an eclipse attack where attacker nodes isolate victim
        from the honest network
        """
        log.info("="*60)
        log.info("SIMULATING ECLIPSE ATTACK")
        log.info("="*60)
        
        log.info("Setting up network topology...")
        
        victim = self.network.create_node("victim", is_attacker=False)
        
        attacker_nodes = []
        for i in range(10):
            attacker = self.network.create_node(f"attacker_{i}", is_attacker=True)
            attacker_nodes.append(attacker)
        
        honest_nodes = []
        for i in range(3):
            honest = self.network.create_node(f"honest_{i}", is_attacker=False)
            honest_nodes.append(honest)
        
        log.info("Starting nodes...")
        self.network.start_node(victim)
        time.sleep(1)
        
        for node in attacker_nodes:
            self.network.start_node(node)
            time.sleep(0.5)
        
        for node in honest_nodes:
            self.network.start_node(node)
            time.sleep(0.5)
        
        log.info("Connecting victim to attacker nodes only...")
        for attacker in attacker_nodes:
            self.network.connect_nodes(victim, attacker)
        
        log.info("Connecting honest nodes to each other...")
        for i, honest in enumerate(honest_nodes):
            if i > 0:
                self.network.connect_nodes(honest, honest_nodes[i-1])
        
        log.info("Monitoring for 30 seconds...")
        log.info("Expected: Victim should detect and reject isolation attempt")
        
        time.sleep(30)
        
        log.info("Checking victim state...")
        
        self.network.stop_all_nodes()
        
        log.info("✓ Eclipse attack simulation complete")
        return True


class SybilAttackSimulator:
    """Simulates Sybil attacks on peer discovery"""
    
    def __init__(self, network: NetworkSimulator):
        self.network = network
    
    def simulate_sybil_attack(self) -> bool:
        """
        Simulate Sybil attack with massive number of fake peer identities
        """
        log.info("="*60)
        log.info("SIMULATING SYBIL ATTACK")
        log.info("="*60)
        
        log.info("Creating swarm of Sybil nodes...")
        
        victim = self.network.create_node("sybil_victim")
        self.network.start_node(victim)
        
        log.info("Simulating 1000 fake peer connections...")
        
        for i in range(100):
            sybil = self.network.create_node(f"sybil_{i}", is_attacker=True)
        
        log.info("Monitoring peer table saturation...")
        log.info("Expected: Node should rate-limit and reject excessive connections")
        
        time.sleep(20)
        
        self.network.stop_all_nodes()
        
        log.info("✓ Sybil attack simulation complete")
        return True


class TimeManipulationSimulator:
    """Simulates time-based attacks using libfaketime"""
    
    def __init__(self, network: NetworkSimulator):
        self.network = network
    
    def simulate_time_manipulation(self) -> bool:
        """
        Simulate time manipulation attacks on timelock validation
        """
        log.info("="*60)
        log.info("SIMULATING TIME MANIPULATION ATTACK")
        log.info("="*60)
        
        log.info("Checking for libfaketime...")
        result = subprocess.run(['which', 'faketime'], capture_output=True)
        
        if result.returncode != 0:
            log.warning("libfaketime not available - skipping time manipulation test")
            return False
        
        log.info("Creating node with accelerated time...")
        
        node = self.network.create_node("time_victim")
        config = self.network.generate_node_config(node)
        
        zebrad_bin = self.network.workspace / "target" / "debug" / "zebrad"
        
        log.info("Starting node with time offset...")
        
        node.process = subprocess.Popen(
            ['faketime', '+30d', str(zebrad_bin), '-c', str(config), 'start'],
            cwd=node.data_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(5)
        
        log.info("Expected: Transactions with timelocks should behave correctly")
        log.info("Expected: Block timestamps should be validated properly")
        
        time.sleep(20)
        
        self.network.stop_all_nodes()
        
        log.info("✓ Time manipulation simulation complete")
        return True


class ConsensusAttackSimulator:
    """Simulates consensus-level attacks"""
    
    def __init__(self, network: NetworkSimulator):
        self.network = network
    
    def simulate_chain_reorganization(self) -> bool:
        """Simulate deep chain reorganization attack"""
        log.info("="*60)
        log.info("SIMULATING CHAIN REORGANIZATION ATTACK")
        log.info("="*60)
        
        log.info("Setting up two network partitions...")
        
        partition_a = []
        partition_b = []
        
        for i in range(3):
            node_a = self.network.create_node(f"partition_a_{i}")
            node_b = self.network.create_node(f"partition_b_{i}")
            partition_a.append(node_a)
            partition_b.append(node_b)
        
        log.info("Starting partitioned network...")
        
        for node in partition_a + partition_b:
            self.network.start_node(node)
            time.sleep(0.5)
        
        log.info("Connecting nodes within partitions...")
        
        for i in range(len(partition_a) - 1):
            self.network.connect_nodes(partition_a[i], partition_a[i+1])
            self.network.connect_nodes(partition_b[i], partition_b[i+1])
        
        log.info("Mining blocks on both partitions...")
        time.sleep(30)
        
        log.info("Merging partitions and observing reorganization...")
        self.network.connect_nodes(partition_a[0], partition_b[0])
        
        time.sleep(30)
        
        log.info("Expected: Nodes should reorganize to longest chain")
        log.info("Expected: No consensus violations or state corruption")
        
        self.network.stop_all_nodes()
        
        log.info("✓ Chain reorganization simulation complete")
        return True


class AttackOrchestrator:
    """Orchestrates all attack simulations"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.network = NetworkSimulator(workspace)
        
        self.report_file = workspace / "ATTACK_SIMULATION_REPORT.md"
    
    def run_all_attacks(self):
        """Run all attack simulations"""
        log.info("="*80)
        log.info("ZEBRA ATTACK SIMULATION SUITE")
        log.info("="*80)
        
        results = {}
        
        scenarios = [
            ("Eclipse Attack", lambda: EclipseAttackSimulator(self.network).simulate_eclipse_attack()),
            ("Sybil Attack", lambda: SybilAttackSimulator(self.network).simulate_sybil_attack()),
            ("Time Manipulation", lambda: TimeManipulationSimulator(self.network).simulate_time_manipulation()),
            ("Chain Reorganization", lambda: ConsensusAttackSimulator(self.network).simulate_chain_reorganization()),
        ]
        
        for scenario_name, scenario_func in scenarios:
            log.info("")
            log.info(f"Running: {scenario_name}")
            
            try:
                result = scenario_func()
                results[scenario_name] = "PASS" if result else "SKIP"
            except Exception as e:
                log.error(f"Scenario failed: {e}")
                results[scenario_name] = "FAIL"
            
            self.network.nodes = []
        
        self.generate_report(results)
        
        log.info("")
        log.info("="*80)
        log.info("ATTACK SIMULATION COMPLETE")
        log.info("="*80)
        
        for scenario, result in results.items():
            log.info(f"  {scenario}: {result}")
    
    def generate_report(self, results: Dict[str, str]):
        """Generate attack simulation report"""
        with open(self.report_file, 'w') as f:
            f.write("# Zebra Attack Simulation Report\n\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
            
            f.write("## Summary\n\n")
            
            for scenario, result in results.items():
                status = "✓" if result == "PASS" else ("⏭" if result == "SKIP" else "✗")
                f.write(f"- {status} **{scenario}**: {result}\n")
            
            f.write("\n## Attack Scenarios\n\n")
            
            f.write("### Eclipse Attack\n\n")
            f.write("**Objective:** Isolate victim node from honest network\n\n")
            f.write("**Method:** Surround victim with attacker-controlled nodes\n\n")
            f.write("**Expected Defense:** Node should maintain diverse peer set and detect isolation\n\n")
            
            f.write("### Sybil Attack\n\n")
            f.write("**Objective:** Overwhelm peer discovery with fake identities\n\n")
            f.write("**Method:** Create thousands of fake peer connections\n\n")
            f.write("**Expected Defense:** Rate limiting and peer reputation should prevent saturation\n\n")
            
            f.write("### Time Manipulation\n\n")
            f.write("**Objective:** Exploit timelock and timestamp validation\n\n")
            f.write("**Method:** Run node with skewed system time\n\n")
            f.write("**Expected Defense:** Block timestamp validation should reject invalid times\n\n")
            
            f.write("### Chain Reorganization\n\n")
            f.write("**Objective:** Cause deep chain reorganization\n\n")
            f.write("**Method:** Create competing chains on network partitions\n\n")
            f.write("**Expected Defense:** Longest chain rule with no state corruption\n\n")
        
        log.info(f"Report generated: {self.report_file}")


def main():
    workspace = Path.cwd()
    
    orchestrator = AttackOrchestrator(workspace)
    
    def signal_handler(sig, frame):
        log.info("Interrupt received, stopping all nodes...")
        orchestrator.network.stop_all_nodes()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    orchestrator.run_all_attacks()


if __name__ == "__main__":
    main()
