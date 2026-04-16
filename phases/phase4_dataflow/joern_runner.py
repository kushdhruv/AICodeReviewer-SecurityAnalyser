"""
Phase 4: Dataflow & Taint Analysis via Joern CPG (v2 — Server-Based)

Architecture:
  - Joern runs as a persistent HTTP server on port 9000
  - We send per-finding targeted Scala queries via the REST API
  - Each Semgrep finding gets its OWN taint trace (not one global dump)
  - Workspace management allows CPG reuse across queries

This is the research-grade approach matching HackerSec's architecture.

Setup:
  1. Install Joern: https://joern.io
  2. Start Joern server: `joern --server --server-host localhost --server-port 9000`
  3. Or via Docker: see docker-compose.yml
"""

import os
import json
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

import httpx

from utils.logger import get_logger
from phases.phase4_dataflow.exceptions import JoernConnectionError, JoernQueryError
from phases.phase4_dataflow.queries import (
    build_taint_query, build_sensitive_sink_query, build_method_summary_query
)

logger = get_logger(__name__)

_DEFAULT_JOERN_URL = os.getenv("JOERN_BASE_URL", "http://localhost:9000")


@dataclass
class TaintFlow:
    """A single taint trace: sequence of code nodes from source to sink."""
    nodes: List[Dict[str, Any]]  # Each node: {"line": int, "code": str}

    @property
    def source(self) -> str:
        return self.nodes[0].get("code", "?") if self.nodes else "?"

    @property
    def sink(self) -> str:
        return self.nodes[-1].get("code", "?") if self.nodes else "?"

    @property
    def depth(self) -> int:
        return len(self.nodes)

    def to_readable(self) -> str:
        """Human-readable flow for LLM prompt injection."""
        parts = []
        for n in self.nodes:
            parts.append(f"  L{n.get('line', '?')}: {n.get('code', '?')}")
        return "\n".join(parts)


@dataclass
class FindingCPGContext:
    """
    Per-finding CPG context — attached to individual EnrichedCodeChunks.
    This is the KEY difference from v1: each finding gets its own taint data.
    """
    cpg_status: str  # "success" | "no_flow_found" | "failed" | "skipped"
    taint_flows: List[TaintFlow] = field(default_factory=list)
    method_context: Optional[Dict[str, Any]] = None  # Caller/callee info
    error_message: Optional[str] = None

    def to_prompt_context(self) -> str:
        """Formats CPG data for injection into LangGraph agent prompts."""
        if self.cpg_status == "skipped":
            return "No CPG dataflow analysis available (Joern not running)."
        if self.cpg_status == "failed":
            return f"CPG analysis failed: {self.error_message}"
        if self.cpg_status == "no_flow_found":
            return "No taint flows detected for this specific code location."

        lines = ["=== JOERN CPG TAINT ANALYSIS (Per-Finding) ==="]

        # Taint flows
        for i, flow in enumerate(self.taint_flows[:3], 1):  # Cap at 3 for prompt size
            lines.append(f"Taint Flow {i} (depth={flow.depth}):")
            lines.append(f"  Source: {flow.source}")
            lines.append(f"  Sink:   {flow.sink}")
            lines.append(flow.to_readable())

        # Method context (callers/callees)
        if self.method_context:
            calls = self.method_context.get("calls", [])
            called_by = self.method_context.get("called_by", [])
            if calls:
                lines.append(f"Function calls: {', '.join(calls[:5])}")
            if called_by:
                lines.append(f"Called by: {', '.join(called_by[:5])}")

        return "\n".join(lines)


class JoernClient:
    """
    HTTP client for the Joern server REST API.
    Joern must be running as: `joern --server --server-host localhost --server-port 9000`
    """

    def __init__(self, base_url: str = _DEFAULT_JOERN_URL):
        self.base_url = base_url.rstrip("/")
        # Joern CPG queries can take significant time on large codebases
        self.client = httpx.Client(timeout=300.0)

    def ping(self) -> bool:
        """Check if the Joern server is reachable."""
        try:
            res = self.client.get(f"{self.base_url}/query/help", timeout=5.0)
            return res.status_code == 200
        except httpx.RequestError:
            return False

    def execute_query(self, query: str) -> dict:
        """Send a raw Scala query to the Joern server and return the response."""
        payload = {"query": query}
        try:
            res = self.client.post(f"{self.base_url}/query", json=payload)
            res.raise_for_status()
            return res.json()
        except httpx.RequestError as e:
            raise JoernConnectionError(f"Failed to reach Joern server: {e}")
        except httpx.HTTPStatusError as e:
            raise JoernQueryError(f"Joern query HTTP error: {e}")

    def create_workspace(self, workspace_name: str) -> None:
        """Create a named workspace in Joern for CPG reuse."""
        try:
            self.execute_query(f'workspace.create("{workspace_name}")')
            logger.info(f"  Created Joern workspace: {workspace_name}")
        except (JoernConnectionError, JoernQueryError) as e:
            logger.warning(f"Workspace creation failed (may already exist): {e}")

    def import_code(self, code_path: Path, workspace_name: str = "") -> None:
        """Import source code into a Joern workspace to generate the CPG."""
        if workspace_name:
            self.execute_query(f'workspace("{workspace_name}")')

        # Use forward slashes for Joern (Scala/JVM expects POSIX paths)
        posix_path = code_path.absolute().as_posix()
        if "/workspace/" in posix_path:
            posix_path = "/workspace/" + posix_path.split("/workspace/")[-1]
            logger.info(f"  Remapped path for Docker Joern volume: {posix_path}")
        result = self.execute_query(f'importCode("{posix_path}")')

        response_text = result.get("response", "")
        if "Error" in response_text:
            raise JoernQueryError(f"Failed to import code: {response_text}")

        logger.info(f"  Imported code into CPG from: {posix_path}")

    def query_taint_for_line(self, sink_line: int) -> FindingCPGContext:
        """
        Execute a targeted taint query for a SPECIFIC sink line number.
        This is the core per-finding query that makes our analysis precise.
        """
        query = build_taint_query(sink_line)

        try:
            result = self.execute_query(query)
            output = result.get("response", "[]").strip()

            # Parse JSON from Joern's response
            if not (output.startswith("[") and output.endswith("]")):
                if "No flows" in output or "empty" in output or output == "List()":
                    return FindingCPGContext(cpg_status="no_flow_found")
                raise JoernQueryError(f"Unexpected Joern output: {output[:200]}")

            raw_flows = json.loads(output)

            if not raw_flows:
                return FindingCPGContext(cpg_status="no_flow_found")

            # Convert raw JSON arrays into TaintFlow objects
            taint_flows = []
            for flow_nodes in raw_flows:
                if isinstance(flow_nodes, list):
                    taint_flows.append(TaintFlow(nodes=flow_nodes))

            return FindingCPGContext(
                cpg_status="success",
                taint_flows=taint_flows
            )

        except json.JSONDecodeError as e:
            return FindingCPGContext(cpg_status="failed", error_message=f"JSON parse: {e}")
        except (JoernConnectionError, JoernQueryError) as e:
            return FindingCPGContext(cpg_status="failed", error_message=str(e))

    def query_method_context(self, method_name: str) -> Optional[Dict[str, Any]]:
        """Get caller/callee context for a specific method."""
        query = build_method_summary_query(method_name)
        try:
            result = self.execute_query(query)
            output = result.get("response", "{}").strip()
            return json.loads(output)
        except Exception:
            return None

    def close(self):
        """Close the HTTP client."""
        self.client.close()


class JoernRunner:
    """
    High-level orchestrator that manages the Joern server connection,
    workspace/CPG lifecycle, and per-finding taint queries.
    """

    def __init__(self, workspace_name: str = "btp_analysis"):
        self.workspace_name = workspace_name
        self.client = JoernClient()
        self._cpg_ready = False

    def is_available(self) -> bool:
        """Check if Joern server is running and reachable."""
        return self.client.ping()

    def initialize_cpg(self, repo_path: Path) -> bool:
        """
        One-time CPG generation for a repository.
        After this, all per-finding queries reuse the same CPG.
        """
        if not self.is_available():
            logger.warning(
                "⚠️ Joern server is NOT running. "
                "Start it with: joern --server --server-host localhost --server-port 9000"
            )
            return False

        try:
            logger.info(f"[Joern] Creating workspace '{self.workspace_name}'...")
            self.client.create_workspace(self.workspace_name)

            logger.info(f"[Joern] Importing code and generating CPG for {repo_path}...")
            self.client.import_code(repo_path, self.workspace_name)

            self._cpg_ready = True
            logger.info("✅ Joern CPG generated and workspace ready for queries.")
            return True

        except (JoernConnectionError, JoernQueryError) as e:
            logger.error(f"❌ Joern CPG initialization failed: {e}")
            return False

    def analyze_finding(
        self,
        sink_line: int,
        function_name: str = ""
    ) -> FindingCPGContext:
        """
        Analyze a SINGLE finding by querying its specific sink line.
        This is called per-chunk in the pipeline, not once globally.
        
        Args:
            sink_line: The exact line number where Semgrep flagged the vulnerability
            function_name: Optional function name for caller/callee context
        """
        if not self._cpg_ready:
            return FindingCPGContext(
                cpg_status="skipped",
                error_message="CPG not initialized (Joern unavailable)"
            )

        logger.info(f"  [Joern] Querying taint flows for line {sink_line}...")

        # Get targeted taint flows for this specific line
        context = self.client.query_taint_for_line(sink_line)

        # Optionally enrich with method caller/callee context
        if function_name:
            context.method_context = self.client.query_method_context(function_name)

        if context.cpg_status == "success":
            logger.info(
                f"  ✅ Found {len(context.taint_flows)} taint flows "
                f"(max depth: {max((f.depth for f in context.taint_flows), default=0)})"
            )
        elif context.cpg_status == "no_flow_found":
            logger.info("  ℹ️ No taint flows reach this code location.")
        else:
            logger.warning(f"  ⚠️ Joern query issue: {context.error_message}")

        return context

    def close(self):
        """Clean up the HTTP client."""
        self.client.close()
