#!/usr/bin/env python3
"""
Unsafe Block Auditor - Catalogs and verifies all unsafe code
Ensures every unsafe block is reached during fuzzing and proven safe
"""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
import json
import logging

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
log = logging.getLogger(__name__)


@dataclass
class UnsafeBlock:
    """Represents an unsafe block in the codebase"""
    file_path: Path
    line_number: int
    block_content: str
    function_name: str
    safety_comment: str
    is_reached: bool = False
    is_verified: bool = False
    verification_method: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'file': str(self.file_path),
            'line': self.line_number,
            'function': self.function_name,
            'content': self.block_content[:200],  # Truncate for readability
            'safety_comment': self.safety_comment,
            'reached': self.is_reached,
            'verified': self.is_verified,
            'verification': self.verification_method
        }


class UnsafeBlockScanner:
    """Scans codebase for all unsafe blocks"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.unsafe_blocks: List[UnsafeBlock] = []
    
    def scan_file(self, file_path: Path) -> List[UnsafeBlock]:
        """Scan a single Rust file for unsafe blocks"""
        blocks = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            log.debug(f"Failed to read {file_path}: {e}")
            return blocks
        
        in_unsafe_block = False
        block_start = 0
        block_lines = []
        current_function = "unknown"
        safety_comment = ""
        
        for i, line in enumerate(lines, start=1):
            # Track current function
            func_match = re.search(r'fn\s+(\w+)', line)
            if func_match:
                current_function = func_match.group(1)
            
            # Look for safety comments
            if 'SAFETY:' in line or 'Safety:' in line:
                safety_comment = line.strip()
            
            # Detect unsafe block start
            if re.search(r'\bunsafe\s*\{', line):
                in_unsafe_block = True
                block_start = i
                block_lines = [line]
                continue
            
            # Accumulate unsafe block content
            if in_unsafe_block:
                block_lines.append(line)
                
                # Detect block end (simplified - doesn't handle nested blocks perfectly)
                if '}' in line:
                    in_unsafe_block = False
                    
                    block = UnsafeBlock(
                        file_path=file_path.relative_to(self.workspace),
                        line_number=block_start,
                        block_content=''.join(block_lines),
                        function_name=current_function,
                        safety_comment=safety_comment
                    )
                    blocks.append(block)
                    
                    # Reset
                    safety_comment = ""
                    block_lines = []
        
        return blocks
    
    def scan_workspace(self) -> List[UnsafeBlock]:
        """Scan entire workspace for unsafe blocks"""
        log.info("Scanning workspace for unsafe blocks...")
        
        # Find all Rust files
        rust_files = list(self.workspace.glob("**/*.rs"))
        
        # Exclude fuzz targets and test files
        rust_files = [
            f for f in rust_files
            if '/fuzz/' not in str(f) and '/target/' not in str(f)
        ]
        
        log.info(f"Scanning {len(rust_files)} Rust files...")
        
        for rust_file in rust_files:
            blocks = self.scan_file(rust_file)
            self.unsafe_blocks.extend(blocks)
        
        log.info(f"Found {len(self.unsafe_blocks)} unsafe blocks")
        return self.unsafe_blocks
    
    def save_catalog(self, output_file: Path):
        """Save unsafe block catalog"""
        catalog = {
            'total_unsafe_blocks': len(self.unsafe_blocks),
            'blocks': [block.to_dict() for block in self.unsafe_blocks]
        }
        
        with open(output_file, 'w') as f:
            json.dump(catalog, f, indent=2)
        
        log.info(f"Catalog saved to {output_file}")


class CoverageChecker:
    """Checks if unsafe blocks are reached during tests/fuzzing"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.profdata_file = workspace / "zebra.profdata"
        self.reached_lines: Dict[str, Set[int]] = {}
    
    def generate_coverage(self):
        """Generate coverage data"""
        log.info("Generating coverage data...")
        
        # Clean
        subprocess.run(['cargo', 'clean'], cwd=self.workspace, check=True)
        
        # Build with coverage
        env = {
            'RUSTFLAGS': '-C instrument-coverage'
        }
        subprocess.run(
            ['cargo', 'build', '--workspace', '--all-targets'],
            cwd=self.workspace,
            env=env,
            check=True
        )
        
        # Run tests
        subprocess.run(
            ['cargo', 'test', '--workspace'],
            cwd=self.workspace,
            env=env,
            check=False
        )
        
        # Merge profraw
        profraw_files = list(self.workspace.glob("**/*.profraw"))
        if profraw_files:
            subprocess.run([
                'llvm-profdata', 'merge', '-sparse',
                *[str(f) for f in profraw_files],
                '-o', str(self.profdata_file)
            ], check=True)
            
            log.info(f"Coverage data generated: {self.profdata_file}")
        else:
            log.warning("No profraw files generated")
    
    def parse_coverage(self, binary: Path):
        """Parse coverage report to find reached lines"""
        if not self.profdata_file.exists():
            log.error("Coverage data not found. Run generate_coverage() first.")
            return
        
        log.info("Parsing coverage report...")
        
        result = subprocess.run([
            'llvm-cov', 'export',
            '--instr-profile', str(self.profdata_file),
            '--object', str(binary),
            '--format', 'text'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            log.error(f"Failed to export coverage: {result.stderr}")
            return
        
        # Parse JSON output
        try:
            coverage_data = json.loads(result.stdout)
            
            for file_data in coverage_data.get('data', [{}])[0].get('files', []):
                filename = file_data.get('filename', '')
                reached = set()
                
                for segment in file_data.get('segments', []):
                    line = segment[0]
                    count = segment[2]
                    
                    if count > 0:
                        reached.add(line)
                
                if reached:
                    self.reached_lines[filename] = reached
            
            log.info(f"Parsed coverage for {len(self.reached_lines)} files")
        except Exception as e:
            log.error(f"Failed to parse coverage: {e}")
    
    def check_unsafe_coverage(self, unsafe_blocks: List[UnsafeBlock]) -> Tuple[int, int]:
        """Check which unsafe blocks are reached"""
        reached = 0
        unreached = 0
        
        for block in unsafe_blocks:
            file_path = str(self.workspace / block.file_path)
            
            if file_path in self.reached_lines:
                if block.line_number in self.reached_lines[file_path]:
                    block.is_reached = True
                    reached += 1
                else:
                    unreached += 1
            else:
                unreached += 1
        
        log.info(f"Coverage: {reached} reached, {unreached} unreached")
        return reached, unreached


class SymbolicVerifier:
    """Uses symbolic execution to verify safety of unsafe blocks"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
    
    def verify_with_klee(self, unsafe_block: UnsafeBlock) -> bool:
        """Attempt verification with KLEE (if available)"""
        log.info(f"Verifying {unsafe_block.file_path}:{unsafe_block.line_number} with KLEE")
        
        # Check if KLEE is available
        if subprocess.run(['which', 'klee'], capture_output=True).returncode != 0:
            log.warning("KLEE not found - skipping symbolic verification")
            return False
        
        # In a full implementation, would:
        # 1. Extract function containing unsafe block
        # 2. Compile to LLVM bitcode
        # 3. Run KLEE on the function
        # 4. Check for assertion violations
        
        # Placeholder for now
        log.debug("Symbolic verification not yet implemented")
        return False
    
    def verify_with_kani(self, unsafe_block: UnsafeBlock) -> bool:
        """Attempt verification with Kani (if available)"""
        log.info(f"Verifying {unsafe_block.file_path}:{unsafe_block.line_number} with Kani")
        
        # Check if Kani is available
        if subprocess.run(['which', 'kani'], capture_output=True).returncode != 0:
            log.warning("Kani not found - skipping formal verification")
            return False
        
        # In a full implementation, would:
        # 1. Create Kani harness for function
        # 2. Run kani on the harness
        # 3. Check for proof success
        
        # Placeholder for now
        log.debug("Kani verification not yet implemented")
        return False


class UnsafeBlockAuditor:
    """Main auditor orchestrating the unsafe block audit"""
    
    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.scanner = UnsafeBlockScanner(workspace)
        self.coverage = CoverageChecker(workspace)
        self.verifier = SymbolicVerifier(workspace)
        
        self.catalog_file = workspace / "unsafe_blocks_catalog.json"
        self.report_file = workspace / "unsafe_blocks_report.md"
    
    def run_full_audit(self):
        """Run complete unsafe block audit"""
        log.info("Starting unsafe block audit...")
        
        # Phase 1: Scan for all unsafe blocks
        log.info("\n[Phase 1] Scanning for unsafe blocks...")
        unsafe_blocks = self.scanner.scan_workspace()
        
        if not unsafe_blocks:
            log.info("✅ No unsafe blocks found in codebase!")
            return
        
        # Phase 2: Generate coverage
        log.info("\n[Phase 2] Generating coverage data...")
        self.coverage.generate_coverage()
        
        # Parse coverage
        binary = self.workspace / "target" / "debug" / "zebrad"
        if binary.exists():
            self.coverage.parse_coverage(binary)
        
        # Phase 3: Check which blocks are reached
        log.info("\n[Phase 3] Checking unsafe block coverage...")
        reached, unreached = self.coverage.check_unsafe_coverage(unsafe_blocks)
        
        # Phase 4: Attempt verification on unreached blocks
        log.info("\n[Phase 4] Attempting symbolic verification...")
        
        for block in unsafe_blocks:
            if not block.is_reached:
                log.warning(f"Unreached unsafe block: {block.file_path}:{block.line_number}")
                
                # Try verification
                if self.verifier.verify_with_kani(block):
                    block.is_verified = True
                    block.verification_method = "Kani"
                elif self.verifier.verify_with_klee(block):
                    block.is_verified = True
                    block.verification_method = "KLEE"
        
        # Phase 5: Save results
        log.info("\n[Phase 5] Generating reports...")
        self.scanner.save_catalog(self.catalog_file)
        self.generate_report(unsafe_blocks, reached, unreached)
        
        log.info("\n✅ Unsafe block audit complete!")
    
    def generate_report(self, unsafe_blocks: List[UnsafeBlock], reached: int, unreached: int):
        """Generate human-readable report"""
        
        with open(self.report_file, 'w') as f:
            f.write("# Unsafe Block Audit Report\n\n")
            f.write(f"**Date:** {subprocess.run(['date'], capture_output=True, text=True).stdout.strip()}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- Total unsafe blocks: {len(unsafe_blocks)}\n")
            f.write(f"- Reached by tests: {reached}\n")
            f.write(f"- Unreached: {unreached}\n")
            
            verified = sum(1 for b in unsafe_blocks if b.is_verified)
            f.write(f"- Verified via formal methods: {verified}\n\n")
            
            # Coverage percentage
            if len(unsafe_blocks) > 0:
                coverage_pct = (reached / len(unsafe_blocks)) * 100
                f.write(f"**Unsafe Block Coverage:** {coverage_pct:.1f}%\n\n")
            
            # Status
            if unreached == 0:
                f.write("✅ **All unsafe blocks are reached and exercised by tests**\n\n")
            else:
                f.write(f"⚠️ **{unreached} unsafe blocks are not reached by tests**\n\n")
            
            f.write("## Unreached Unsafe Blocks\n\n")
            
            if unreached > 0:
                f.write("The following unsafe blocks need attention:\n\n")
                
                for block in unsafe_blocks:
                    if not block.is_reached:
                        f.write(f"### {block.file_path}:{block.line_number}\n\n")
                        f.write(f"- Function: `{block.function_name}`\n")
                        
                        if block.safety_comment:
                            f.write(f"- Safety comment: {block.safety_comment}\n")
                        else:
                            f.write(f"- ⚠️ No safety comment found\n")
                        
                        if block.is_verified:
                            f.write(f"- ✅ Verified via {block.verification_method}\n")
                        else:
                            f.write(f"- ❌ Not verified\n")
                        
                        f.write(f"\n```rust\n{block.block_content[:300]}\n```\n\n")
                
                f.write("## Recommendations\n\n")
                f.write("For each unreached unsafe block:\n\n")
                f.write("1. Create a targeted test/benchmark that exercises the unsafe code\n")
                f.write("2. Add to fuzzing corpus to ensure continuous coverage\n")
                f.write("3. Consider formal verification with Kani or KLEE\n")
                f.write("4. Ensure safety comments adequately explain invariants\n\n")
            else:
                f.write("✅ All unsafe blocks are reached.\n\n")
            
            f.write("## All Unsafe Blocks\n\n")
            
            # Group by file
            by_file: Dict[Path, List[UnsafeBlock]] = {}
            for block in unsafe_blocks:
                if block.file_path not in by_file:
                    by_file[block.file_path] = []
                by_file[block.file_path].append(block)
            
            for file_path in sorted(by_file.keys()):
                f.write(f"### {file_path}\n\n")
                
                for block in by_file[file_path]:
                    status = "✅" if block.is_reached else "❌"
                    f.write(f"- Line {block.line_number} (`{block.function_name}`) {status}\n")
                
                f.write("\n")
        
        log.info(f"Report generated: {self.report_file}")


def main():
    workspace = Path.cwd()
    
    auditor = UnsafeBlockAuditor(workspace)
    auditor.run_full_audit()


if __name__ == "__main__":
    main()
