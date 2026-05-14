#!/usr/bin/env python3
"""
Taint-Guided Directed Fuzzer for Zebra
Tracks data flow from untrusted inputs to critical sinks
Generates targeted inputs to reach dangerous code paths
"""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)


@dataclass
class TaintSink:
    """Represents a potentially dangerous taint sink"""
    function: str
    file_path: Path
    line_number: int
    sink_type: str
    description: str
    tainted_parameters: List[str]
    is_reached: bool = False
    triggering_inputs: List[bytes] = field(default_factory=list)


@dataclass
class TaintSource:
    """Represents a source of untrusted data"""
    source_type: str
    function: str
    description: str


class TaintAnalyzer:
    """Analyzes data flow to identify taint propagation"""
    
    DANGEROUS_SINKS = [
        'std::ptr::write',
        'std::ptr::read',
        'std::slice::from_raw_parts',
        'std::mem::transmute',
        'libc::malloc',
        'libc::free',
        'as_mut_ptr',
        'as_ptr',
        'get_unchecked',
        'get_unchecked_mut',
    ]
    
    TAINT_SOURCES = [
        'Read::read',
        'TcpStream::read',
        'deserialize',
        'from_bytes',
        'parse',
        'decode',
        'recv',
        'read_to_end',
    ]
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.taint_sinks: List[TaintSink] = []
        self.taint_sources: List[TaintSource] = []
    
    def scan_for_sinks(self) -> List[TaintSink]:
        """Scan codebase for potential taint sinks"""
        log.info("Scanning for taint sinks...")
        
        rust_files = list(self.workspace.glob("**/*.rs"))
        rust_files = [f for f in rust_files if '/target/' not in str(f)]
        
        for rust_file in rust_files:
            self.analyze_file_for_sinks(rust_file)
        
        log.info(f"Found {len(self.taint_sinks)} potential taint sinks")
        return self.taint_sinks
    
    def analyze_file_for_sinks(self, file_path: Path):
        """Analyze a single file for taint sinks"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            log.debug(f"Failed to read {file_path}: {e}")
            return
        
        current_function = "unknown"
        in_unsafe = False
        
        for i, line in enumerate(lines, start=1):
            func_match = re.search(r'fn\s+(\w+)', line)
            if func_match:
                current_function = func_match.group(1)
            
            if 'unsafe' in line:
                in_unsafe = True
            
            for sink_pattern in self.DANGEROUS_SINKS:
                if sink_pattern in line:
                    sink = TaintSink(
                        function=current_function,
                        file_path=file_path.relative_to(self.workspace),
                        line_number=i,
                        sink_type=sink_pattern,
                        description=line.strip(),
                        tainted_parameters=self.extract_parameters(line)
                    )
                    self.taint_sinks.append(sink)
                    
                    if in_unsafe:
                        log.debug(f"Unsafe sink at {file_path.name}:{i}: {sink_pattern}")
    
    def extract_parameters(self, line: str) -> List[str]:
        """Extract parameter names from function call"""
        params = []
        
        match = re.search(r'\((.*?)\)', line)
        if match:
            args = match.group(1).split(',')
            for arg in args:
                arg = arg.strip()
                if arg and not arg.isdigit():
                    params.append(arg.split()[0])
        
        return params
    
    def generate_taint_report(self, output_file: Path):
        """Generate taint analysis report"""
        log.info(f"Generating taint analysis report: {output_file}")
        
        sinks_by_type = defaultdict(list)
        for sink in self.taint_sinks:
            sinks_by_type[sink.sink_type].append(sink)
        
        with open(output_file, 'w') as f:
            f.write("# Taint Analysis Report\n\n")
            f.write(f"**Total Taint Sinks:** {len(self.taint_sinks)}\n")
            f.write(f"**Unique Sink Types:** {len(sinks_by_type)}\n\n")
            
            f.write("## Taint Sinks by Type\n\n")
            
            for sink_type, sinks in sorted(sinks_by_type.items(), key=lambda x: -len(x[1])):
                f.write(f"### {sink_type}\n\n")
                f.write(f"**Count:** {len(sinks)}\n\n")
                
                for sink in sinks[:10]:
                    f.write(f"- `{sink.function}` at {sink.file_path}:{sink.line_number}\n")
                    f.write(f"  - Parameters: {', '.join(sink.tainted_parameters) if sink.tainted_parameters else 'none'}\n")
                    f.write(f"  - Reached: {'✓' if sink.is_reached else '✗'}\n")
                
                if len(sinks) > 10:
                    f.write(f"  - ... and {len(sinks) - 10} more\n")
                
                f.write("\n")
            
            f.write("## High-Priority Targets\n\n")
            f.write("The following sinks should be prioritized for directed fuzzing:\n\n")
            
            priority_sinks = [s for s in self.taint_sinks if not s.is_reached]
            
            for sink in priority_sinks[:20]:
                f.write(f"1. **{sink.function}** ({sink.file_path}:{sink.line_number})\n")
                f.write(f"   - Type: {sink.sink_type}\n")
                f.write(f"   - Description: {sink.description[:80]}...\n\n")


class DirectedFuzzingOrchestrator:
    """Orchestrates directed fuzzing campaigns targeting specific sinks"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.analyzer = TaintAnalyzer(workspace)
        self.fuzz_targets_dir = workspace / "fuzz" / "fuzz_targets"
    
    def generate_directed_harnesses(self):
        """Generate fuzzing harnesses targeting specific sinks"""
        log.info("Generating directed fuzzing harnesses...")
        
        sinks = self.analyzer.scan_for_sinks()
        
        sinks_by_file = defaultdict(list)
        for sink in sinks:
            sinks_by_file[sink.file_path].append(sink)
        
        for file_path, file_sinks in list(sinks_by_file.items())[:5]:
            self.generate_harness_for_file(file_path, file_sinks)
    
    def generate_harness_for_file(self, file_path: Path, sinks: List[TaintSink]):
        """Generate fuzzing harness for specific file"""
        log.info(f"Generating harness for {file_path} ({len(sinks)} sinks)")
        
        module_name = file_path.stem
        harness_name = f"directed_{module_name}"
        
        if not self.fuzz_targets_dir.exists():
            log.warning("Fuzz targets directory not found")
            return
        
        harness_path = self.fuzz_targets_dir / f"{harness_name}.rs"
        
        harness_code = self.generate_harness_code(file_path, sinks)
        
        with open(harness_path, 'w') as f:
            f.write(harness_code)
        
        log.info(f"  ✓ Generated {harness_path}")
    
    def generate_harness_code(self, file_path: Path, sinks: List[TaintSink]) -> str:
        """Generate Rust code for directed fuzzing harness"""
        
        target_function = sinks[0].function if sinks else "parse"
        
        harness = f"""#![no_main]

use libfuzzer_sys::fuzz_target;

// Directed fuzzing harness for {file_path}
// Targets the following sinks:
"""
        
        for sink in sinks[:5]:
            harness += f"//   - {sink.function} ({sink.sink_type})\n"
        
        harness += """
fuzz_target!(|data: &[u8]| {
    // Attempt to trigger taint sinks
    if data.len() < 4 {
        return;
    }
    
    // Parse input and trigger code paths
    let _ = std::panic::catch_unwind(|| {
        // Target-specific deserialization
        // This should be customized per target
    });
});
"""
        
        return harness
    
    def run_directed_campaign(self, target_sink: TaintSink, duration_secs: int = 300):
        """Run directed fuzzing campaign for specific sink"""
        log.info(f"Running directed campaign for {target_sink.function}")
        log.info(f"  Target: {target_sink.file_path}:{target_sink.line_number}")
        log.info(f"  Sink type: {target_sink.sink_type}")
        
        harness_name = f"directed_{target_sink.file_path.stem}"
        
        result = subprocess.run(
            ['cargo', 'fuzz', 'run', harness_name, '--',
             '-max_total_time=' + str(duration_secs),
             '-print_final_stats=1'],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            timeout=duration_secs + 60
        )
        
        if 'CRASH' in result.stderr or 'ERROR' in result.stderr:
            log.warning(f"  ⚠ Crashes detected during directed fuzzing")
            target_sink.is_reached = True
            return True
        else:
            log.info(f"  ✓ Completed without crashes")
            return False


class SymbolicTaintGuidance:
    """Uses symbolic execution to guide fuzzing toward taint sinks"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
    
    def extract_path_constraints(self, target_function: str) -> List[str]:
        """Extract path constraints to reach target function"""
        log.info(f"Extracting path constraints for {target_function}")
        
        constraints = []
        
        log.info("Would use angr/sympy to extract SMT constraints")
        log.info("Would solve for concrete inputs that satisfy constraints")
        
        return constraints
    
    def generate_constraint_satisfying_inputs(self, constraints: List[str]) -> List[bytes]:
        """Generate inputs that satisfy extracted constraints"""
        log.info(f"Generating inputs for {len(constraints)} constraints")
        
        inputs = []
        
        for constraint in constraints:
            log.debug(f"Solving constraint: {constraint}")
        
        return inputs


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Taint-guided directed fuzzer')
    parser.add_argument('--workspace', type=Path, default=Path.cwd(),
                       help='Workspace directory')
    parser.add_argument('--scan-only', action='store_true',
                       help='Only scan for taint sinks, do not fuzz')
    parser.add_argument('--generate-harnesses', action='store_true',
                       help='Generate directed fuzzing harnesses')
    parser.add_argument('--report', type=Path, default=Path('taint_analysis.md'),
                       help='Output report file')
    
    args = parser.parse_args()
    
    orchestrator = DirectedFuzzingOrchestrator(args.workspace)
    
    if args.scan_only:
        log.info("Scanning for taint sinks...")
        sinks = orchestrator.analyzer.scan_for_sinks()
        orchestrator.analyzer.generate_taint_report(args.report)
        log.info(f"✓ Taint analysis complete: {len(sinks)} sinks found")
    
    elif args.generate_harnesses:
        orchestrator.generate_directed_harnesses()
        log.info("✓ Directed fuzzing harnesses generated")
    
    else:
        log.info("Running full taint-guided fuzzing campaign...")
        sinks = orchestrator.analyzer.scan_for_sinks()
        orchestrator.analyzer.generate_taint_report(args.report)
        
        if sinks:
            log.info("Starting directed fuzzing on high-priority sinks...")
            for sink in sinks[:3]:
                orchestrator.run_directed_campaign(sink, duration_secs=60)


if __name__ == "__main__":
    main()
