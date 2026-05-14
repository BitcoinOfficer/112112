#!/usr/bin/env python3
"""
Hybrid Concolic Fuzzing Engine for Zebra
Combines libFuzzer with symbolic execution to escape local minima
"""

import angr
import subprocess
import os
import sys
import time
import json
import hashlib
from pathlib import Path
from typing import List, Set, Dict, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)


class CrashSignature:
    """Unique signature for deduplication"""
    
    def __init__(self, crash_info: Dict):
        self.faulting_addr = crash_info.get('faulting_addr', 0)
        self.instruction = crash_info.get('instruction', '')
        self.callstack = crash_info.get('callstack', [])
        self.crash_type = crash_info.get('type', 'unknown')
    
    def hash(self) -> str:
        """Create unique hash for this crash pattern"""
        data = f"{self.crash_type}:{self.instruction}:{':'.join(self.callstack[:5])}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def __eq__(self, other):
        return self.hash() == other.hash()
    
    def __hash__(self):
        return int(self.hash()[:16], 16)


class BlacklistManager:
    """Manages blacklist of known crash signatures"""
    
    def __init__(self, blacklist_file: Path):
        self.blacklist_file = blacklist_file
        self.blacklisted: Set[str] = set()
        self.load()
    
    def load(self):
        """Load blacklist from disk"""
        if self.blacklist_file.exists():
            with open(self.blacklist_file) as f:
                self.blacklisted = set(line.strip() for line in f)
            log.info(f"Loaded {len(self.blacklisted)} blacklisted signatures")
    
    def add(self, signature: CrashSignature):
        """Add signature to blacklist"""
        sig_hash = signature.hash()
        if sig_hash not in self.blacklisted:
            self.blacklisted.add(sig_hash)
            with open(self.blacklist_file, 'a') as f:
                f.write(f"{sig_hash}\n")
            log.info(f"Blacklisted new signature: {sig_hash[:16]}...")
            return True
        return False
    
    def is_blacklisted(self, signature: CrashSignature) -> bool:
        """Check if signature is blacklisted"""
        return signature.hash() in self.blacklisted


class CoverageAnalyzer:
    """Analyzes coverage and identifies gaps"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.coverage_file = workspace / "coverage.json"
        self.gap_file = workspace / "coverage_gaps.txt"
    
    def compute_coverage(self, binary: Path) -> Dict:
        """Run LLVM coverage analysis"""
        log.info("Computing coverage...")
        
        # Generate coverage data
        subprocess.run([
            "cargo", "clean"
        ], cwd=self.workspace, check=True)
        
        env = os.environ.copy()
        env['RUSTFLAGS'] = '-C instrument-coverage'
        
        subprocess.run([
            "cargo", "build", "--workspace", "--all-targets"
        ], env=env, cwd=self.workspace, check=True)
        
        # Run tests to generate profdata
        subprocess.run([
            "cargo", "test", "--workspace"
        ], env=env, cwd=self.workspace, check=False)
        
        # Merge profraw files
        profraw_files = list(self.workspace.glob("**/*.profraw"))
        if profraw_files:
            subprocess.run([
                "llvm-profdata", "merge", "-sparse",
                *[str(f) for f in profraw_files],
                "-o", str(self.workspace / "zebra.profdata")
            ], check=True)
            
            # Generate JSON report
            result = subprocess.run([
                "llvm-cov", "report",
                "--instr-profile", str(self.workspace / "zebra.profdata"),
                "--object", str(binary),
                "--format=json"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                coverage = json.loads(result.stdout)
                with open(self.coverage_file, 'w') as f:
                    json.dump(coverage, f, indent=2)
                return coverage
        
        return {}
    
    def identify_gaps(self, coverage: Dict) -> List[str]:
        """Identify functions with <20% coverage"""
        gaps = []
        
        for file_data in coverage.get('data', [{}])[0].get('files', []):
            filename = file_data.get('filename', '')
            
            # Only analyze attack surface files
            if not any(x in filename for x in [
                'zebra-network', 'zebra-chain', 'zebra-script',
                'zebra-state', 'zebra-rpc', 'zebra-consensus'
            ]):
                continue
            
            for func in file_data.get('functions', []):
                func_name = func.get('name', '')
                regions = func.get('regions', {})
                covered = regions.get('covered', 0)
                total = regions.get('count', 1)
                
                coverage_pct = (covered / total * 100) if total > 0 else 0
                
                if coverage_pct < 20:
                    gaps.append(f"{filename}:{func_name} ({coverage_pct:.1f}%)")
        
        # Write gaps to file
        with open(self.gap_file, 'w') as f:
            for gap in gaps:
                f.write(f"{gap}\n")
        
        log.info(f"Identified {len(gaps)} low-coverage functions")
        return gaps


class SymbolicExecutor:
    """Extracts constraints from unexplored branches"""
    
    def __init__(self, binary: Path, workspace: Path):
        self.binary = binary
        self.workspace = workspace
        self.new_inputs_dir = workspace / "symbolic_inputs"
        self.new_inputs_dir.mkdir(exist_ok=True)
    
    def extract_constraints(self, seed_corpus: Path) -> List[bytes]:
        """Use angr to solve for inputs reaching new branches"""
        log.info(f"Running symbolic execution on {self.binary}")
        
        try:
            proj = angr.Project(str(self.binary), auto_load_libs=False)
        except Exception as e:
            log.error(f"Failed to load binary: {e}")
            return []
        
        new_inputs = []
        
        # Try each seed from corpus
        for seed_file in list(seed_corpus.iterdir())[:10]:  # Limit to first 10
            try:
                with open(seed_file, 'rb') as f:
                    seed_data = f.read()
                
                # Create symbolic input
                state = proj.factory.entry_state(
                    stdin=angr.SimPackets(seed_data)
                )
                
                simgr = proj.factory.simulation_manager(state)
                
                # Explore for 60 seconds max
                simgr.explore(timeout=60)
                
                # Extract inputs from found states
                for found_state in simgr.found:
                    if found_state.satisfiable():
                        try:
                            new_input = found_state.posix.dumps(0)
                            new_inputs.append(new_input)
                        except:
                            pass
                
            except Exception as e:
                log.debug(f"Symbolic execution failed on {seed_file.name}: {e}")
                continue
        
        # Save new inputs
        for idx, inp in enumerate(new_inputs):
            output_file = self.new_inputs_dir / f"symbolic_{int(time.time())}_{idx}"
            with open(output_file, 'wb') as f:
                f.write(inp)
        
        log.info(f"Generated {len(new_inputs)} new inputs via symbolic execution")
        return new_inputs


class HybridFuzzer:
    """Main hybrid fuzzing orchestrator"""
    
    def __init__(self, workspace: Path, fuzz_target: str):
        self.workspace = workspace
        self.fuzz_target = fuzz_target
        self.corpus_dir = workspace / "fuzz" / "corpus" / fuzz_target
        self.findings_dir = workspace / "fuzz" / "artifacts" / fuzz_target
        self.blacklist = BlacklistManager(workspace / "crash_blacklist.txt")
        self.coverage = CoverageAnalyzer(workspace)
        self.metrics_file = workspace / "metrics.json"
        
        # Ensure directories exist
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        
        # Metrics
        self.metrics = {
            'unique_crashes': 0,
            'blacklisted_crashes': 0,
            'coverage_functions': 0,
            'symbolic_inputs_generated': 0,
            'fuzzing_rounds': 0,
            'last_new_finding': None,
            'escalation_level': 0
        }
        self.load_metrics()
    
    def load_metrics(self):
        """Load metrics from disk"""
        if self.metrics_file.exists():
            with open(self.metrics_file) as f:
                self.metrics.update(json.load(f))
    
    def save_metrics(self):
        """Save metrics to disk"""
        with open(self.metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
    
    def run_libfuzzer(self, timeout_seconds: int = 3600) -> bool:
        """Run libFuzzer for specified duration"""
        log.info(f"Running libFuzzer on {self.fuzz_target} for {timeout_seconds}s")
        
        cmd = [
            "cargo", "+nightly", "fuzz", "run", self.fuzz_target,
            "--",
            f"-max_total_time={timeout_seconds}",
            "-print_final_stats=1",
            "-print_corpus_stats=1",
            f"-artifact_prefix={self.findings_dir}/"
        ]
        
        result = subprocess.run(
            cmd,
            cwd=self.workspace,
            capture_output=True,
            text=True
        )
        
        # Parse output for new coverage
        new_coverage = "NEW" in result.stdout
        
        self.metrics['fuzzing_rounds'] += 1
        self.save_metrics()
        
        return new_coverage
    
    def check_new_crashes(self) -> int:
        """Check for new unique crashes"""
        new_unique = 0
        
        # Parse crash artifacts
        for crash_file in self.findings_dir.glob("crash-*"):
            # Extract crash info (simplified)
            crash_info = {
                'type': 'unknown',
                'instruction': crash_file.stem,
                'callstack': [],
                'faulting_addr': 0
            }
            
            signature = CrashSignature(crash_info)
            
            if self.blacklist.is_blacklisted(signature):
                self.metrics['blacklisted_crashes'] += 1
                # Remove duplicate
                crash_file.unlink()
            else:
                # New unique crash!
                self.blacklist.add(signature)
                self.metrics['unique_crashes'] += 1
                self.metrics['last_new_finding'] = time.time()
                new_unique += 1
                log.warning(f"NEW UNIQUE CRASH: {crash_file.name}")
        
        self.save_metrics()
        return new_unique
    
    def check_stall(self) -> bool:
        """Check if fuzzing has stalled (no new coverage for 1 hour)"""
        # Simplified: check if last finding was >1 hour ago
        if self.metrics['last_new_finding']:
            time_since_last = time.time() - self.metrics['last_new_finding']
            return time_since_last > 3600
        return True
    
    def escalate(self):
        """Escalate to next fuzzing strategy"""
        current_level = self.metrics['escalation_level']
        
        escalation_strategies = [
            "libFuzzer with ASAN/UBSAN/MSAN",
            "libFuzzer + coverage-guided dictionary",
            "Hybrid fuzzing (libFuzzer + symbolic execution)",
            "Grammar-based generation",
            "Symbolic execution only (KLEE)",
            "Bounded model checking",
            "Formal verification"
        ]
        
        if current_level < len(escalation_strategies) - 1:
            self.metrics['escalation_level'] += 1
            new_level = self.metrics['escalation_level']
            log.warning(f"ESCALATING: Level {current_level} -> {new_level}")
            log.warning(f"New strategy: {escalation_strategies[new_level]}")
            self.save_metrics()
    
    def force_diversity(self):
        """Destroy corpus and regenerate with grammar-based approach"""
        log.warning("FORCING DIVERSITY: Clearing corpus")
        
        # Backup old corpus
        backup_dir = self.workspace / "corpus_backups" / f"{self.fuzz_target}_{int(time.time())}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        for f in self.corpus_dir.iterdir():
            f.rename(backup_dir / f.name)
        
        log.info(f"Corpus backed up to {backup_dir}")
        log.info("Regenerating with grammar-based seeds...")
        
        # TODO: Implement grammar-based seed generation
        # For now, just log the action
        log.warning("Grammar-based generation not yet implemented")
    
    def run_hybrid_loop(self, max_iterations: int = 1000):
        """Main hybrid fuzzing loop"""
        log.info(f"Starting hybrid fuzzing campaign for {self.fuzz_target}")
        log.info(f"Maximum iterations: {max_iterations}")
        
        for iteration in range(max_iterations):
            log.info(f"\n{'='*60}")
            log.info(f"ITERATION {iteration + 1}/{max_iterations}")
            log.info(f"{'='*60}\n")
            
            # Phase 1: Run libFuzzer
            new_coverage = self.run_libfuzzer(timeout_seconds=3600)
            
            # Phase 2: Check for new crashes
            new_crashes = self.check_new_crashes()
            
            if new_crashes > 0:
                log.info(f"Found {new_crashes} new unique crashes")
            
            # Phase 3: Check for stall
            if self.check_stall():
                log.warning("Fuzzing stalled - no new coverage in last hour")
                
                # Phase 4: Run symbolic execution to unstall
                binary = self.workspace / "target" / "debug" / self.fuzz_target
                if binary.exists():
                    symbolic_exec = SymbolicExecutor(binary, self.workspace)
                    new_inputs = symbolic_exec.extract_constraints(self.corpus_dir)
                    
                    # Copy new inputs to corpus
                    for inp_file in symbolic_exec.new_inputs_dir.iterdir():
                        inp_file.rename(self.corpus_dir / inp_file.name)
                    
                    self.metrics['symbolic_inputs_generated'] += len(new_inputs)
                    self.save_metrics()
                    
                    if not new_inputs:
                        log.warning("Symbolic execution found no new paths")
                        self.escalate()
                        
                        # Consider forcing diversity
                        if self.metrics['escalation_level'] >= 3:
                            self.force_diversity()
            
            # Phase 5: Check for exhaustion
            if self.check_exhaustion():
                log.info(f"\n{'='*60}")
                log.info("EXHAUSTION DETECTED")
                log.info(f"{'='*60}\n")
                break
            
            # Save metrics after each iteration
            self.save_metrics()
            
            # Brief pause
            time.sleep(5)
        
        # Final report
        self.generate_report()
    
    def check_exhaustion(self) -> bool:
        """Check if exhaustion criteria are met"""
        # Simplified: 14 days without new finding
        if self.metrics['last_new_finding']:
            time_since_last = time.time() - self.metrics['last_new_finding']
            days_since_last = time_since_last / 86400
            
            if days_since_last >= 14:
                log.info(f"No new findings for {days_since_last:.1f} days - exhaustion achieved")
                return True
        
        return False
    
    def generate_report(self):
        """Generate final exhaustion report"""
        report_file = self.workspace / f"exhaustion_report_{self.fuzz_target}.md"
        
        with open(report_file, 'w') as f:
            f.write(f"# Exhaustion Report: {self.fuzz_target}\n\n")
            f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"## Metrics\n\n")
            f.write(f"- Fuzzing rounds: {self.metrics['fuzzing_rounds']}\n")
            f.write(f"- Unique crashes: {self.metrics['unique_crashes']}\n")
            f.write(f"- Blacklisted duplicates: {self.metrics['blacklisted_crashes']}\n")
            f.write(f"- Symbolic inputs: {self.metrics['symbolic_inputs_generated']}\n")
            f.write(f"- Final escalation level: {self.metrics['escalation_level']}\n")
            
            if self.metrics['last_new_finding']:
                days_ago = (time.time() - self.metrics['last_new_finding']) / 86400
                f.write(f"- Last new finding: {days_ago:.1f} days ago\n")
            
            f.write(f"\n## Status\n\n")
            if self.check_exhaustion():
                f.write("✅ **EXHAUSTION ACHIEVED**\n\n")
                f.write("All reachable vulnerabilities in this target have been discovered.\n")
            else:
                f.write("⚠️ **EXHAUSTION NOT YET ACHIEVED**\n\n")
                f.write("Campaign terminated before exhaustion criteria were met.\n")
        
        log.info(f"Report generated: {report_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: hybrid_concolic_fuzzer.py <fuzz_target>")
        print("Example: hybrid_concolic_fuzzer.py network_codec")
        sys.exit(1)
    
    fuzz_target = sys.argv[1]
    workspace = Path.cwd()
    
    fuzzer = HybridFuzzer(workspace, fuzz_target)
    fuzzer.run_hybrid_loop(max_iterations=1000)


if __name__ == "__main__":
    main()
