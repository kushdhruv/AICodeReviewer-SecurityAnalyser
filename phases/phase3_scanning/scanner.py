import asyncio
import json
import subprocess
from pathlib import Path
from typing import List
from dataclasses import dataclass, field

from utils.logger import get_logger
from phases.phase2_parsing.parser import CodeChunk

logger = get_logger(__name__)

@dataclass
class StaticFinding:
    """A standardized finding from any static analysis tool (Ruff, Semgrep)."""
    tool_name: str
    rule_id: str
    message: str
    severity: str
    file_path: str
    line_number: int

@dataclass
class EnrichedCodeChunk:
    """A Phase 2 CodeChunk enriched with Phase 3 Static Findings."""
    chunk: CodeChunk
    findings: List[StaticFinding] = field(default_factory=list)
    rag_context: str = "" # Added in Phase 5 to hold official vulnerability definitions from Vector DB

class StaticScanner:
    """
    Executes Ruff (Syntax/Lint) and Semgrep (Security) against the workspace.
    Correlates their findings with the AST CodeChunks.
    """
    
    def __init__(self, workspace_path: str):
        self.workspace_path = Path(workspace_path)
        
    async def run_scans(self) -> List[StaticFinding]:
        """Runs Ruff and Semgrep concurrently and normalizes their outputs."""
        logger.info(f"Running static analysis on {self.workspace_path}")
        
        # Run tools concurrently
        ruff_task = self._run_ruff()
        semgrep_task = self._run_semgrep()
        
        ruff_findings, semgrep_findings = await asyncio.gather(ruff_task, semgrep_task)
        
        all_findings = ruff_findings + semgrep_findings
        logger.info(f"Scan complete. Found {len(all_findings)} total static issues.")
        return all_findings
        
    async def _run_ruff(self) -> List[StaticFinding]:
        """Executes Ruff and parses JSON output."""
        logger.info("Starting Ruff (Linter/Syntax)...")
        findings = []
        try:
            # We use subprocess.run for simplicity, capturing stdout
            # We use create_subprocess_shell for Windows compatibility
            process = await asyncio.create_subprocess_shell(
                f"ruff check {self.workspace_path} --output-format=json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                raw_data = json.loads(stdout.decode())
                for item in raw_data:
                    # Ruff formatting to our standard
                    findings.append(StaticFinding(
                        tool_name="Ruff",
                        rule_id=item.get("code", "UNKNOWN"),
                        message=item.get("message", ""),
                        severity="ERROR", # Ruff is generally strict errors/syntax
                        file_path=item.get("filename", ""),
                        line_number=item.get("location", {}).get("row", 0)
                    ))
        except FileNotFoundError:
            logger.warning("Ruff is not installed or not in PATH. Skipping.")
        except Exception as e:
            logger.error(f"Ruff execution failed: {e}")
            
        return findings

    async def _run_semgrep(self) -> List[StaticFinding]:
        """Executes Semgrep and parses JSON output."""
        logger.info("Starting Semgrep (Security SAST)...")
        findings = []
        try:
            # Run with default security rules
            # Use shell=True equivalent for Windows virtual environment path resolution
            process = await asyncio.create_subprocess_shell(
                f"semgrep scan --config=p/security-audit --json {self.workspace_path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                raw_data = json.loads(stdout.decode())
                for result in raw_data.get("results", []):
                    findings.append(StaticFinding(
                        tool_name="Semgrep",
                        rule_id=result.get("check_id", "UNKNOWN"),
                        message=result.get("extra", {}).get("message", ""),
                        severity=result.get("extra", {}).get("severity", "WARNING"),
                        file_path=result.get("path", ""),
                        line_number=result.get("start", {}).get("line", 0)
                    ))
        except FileNotFoundError:
            logger.warning("Semgrep is not installed or not in PATH. Skipping.")
        except Exception as e:
            logger.error(f"Semgrep execution failed: {e}")
            
        return findings

    def correlate_findings(self, code_chunks: List[CodeChunk], findings: List[StaticFinding]) -> List[EnrichedCodeChunk]:
        """
        Maps raw findings to their exact AST function code chunks.
        """
        logger.info("Correlating static findings back to AST Code Chunks...")
        enriched_chunks = [EnrichedCodeChunk(chunk=c) for c in code_chunks]
        
        mapped_count = 0
        for finding in findings:
            finding_path = Path(finding.file_path).resolve() if finding.file_path else None
            # For each finding, find which chunk it belongs to based on line numbers
            for enriched in enriched_chunks:
                chunk_path = Path(enriched.chunk.file_path).resolve()
                if finding_path and chunk_path != finding_path:
                    continue
                # Basic correlation: if finding line is within the function's start/end lines
                if enriched.chunk.start_line <= finding.line_number <= enriched.chunk.end_line:
                    enriched.findings.append(finding)
                    mapped_count += 1
                    break # A finding usually belongs to exactly one innermost chunk
                    
        logger.info(f"Successfully mapped {mapped_count} findings to specific code blocks.")
        
        # For the pipeline, we usually only care about chunks that actually HAVE findings to pass to the LLM
        vulnerable_chunks = [c for c in enriched_chunks if len(c.findings) > 0]
        logger.info(f"Identified {len(vulnerable_chunks)} distinct code blocks requiring LLM review.")
        
        return vulnerable_chunks
