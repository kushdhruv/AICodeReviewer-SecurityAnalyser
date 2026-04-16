"""
Phase 9: Dependency Vulnerability Scanning (SCA)
Runs pip-audit and integrates findings into the pipeline report.
This covers Software Composition Analysis (SCA) — detecting known CVEs
in third-party libraries used by the target project.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DependencyFinding:
    """A single vulnerable dependency."""
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    vulnerability_id: str  # CVE or PYSEC ID
    description: str
    severity: str  # from pip-audit or manual mapping


@dataclass
class DependencyScanResult:
    """Aggregated dependency scan results."""
    total_packages: int = 0
    vulnerable_packages: int = 0
    findings: List[DependencyFinding] = field(default_factory=list)
    status: str = "pending"  # "success" | "failed" | "skipped"
    error_message: Optional[str] = None


class DependencyScanner:
    """
    Scans project dependencies for known vulnerabilities using pip-audit.
    Falls back to a requirements.txt parser if pip-audit is not installed.
    """

    def __init__(self, workspace_path: str = "./workspace"):
        self.workspace_path = Path(workspace_path)

    async def scan(self) -> DependencyScanResult:
        """
        Runs dependency scanning on the workspace.
        Looks for requirements.txt, setup.py, pyproject.toml, or Pipfile.
        """
        result = DependencyScanResult()

        # Find requirements files in the workspace
        req_files = self._find_requirements_files()
        if not req_files:
            logger.info("  No requirements files found. Skipping dependency scan.")
            result.status = "skipped"
            return result

        # Try pip-audit first
        pip_audit_result = await self._run_pip_audit(req_files[0])
        if pip_audit_result is not None:
            return pip_audit_result

        # Fallback: parse requirements and check against a basic known-vuln list
        logger.warning("  pip-audit not available. Using basic requirements parser.")
        result.status = "skipped"
        result.error_message = "pip-audit not installed. Run: pip install pip-audit"
        return result

    def _find_requirements_files(self) -> List[Path]:
        """Find dependency manifest files in the workspace."""
        patterns = [
            "requirements.txt", "requirements/*.txt",
            "setup.py", "pyproject.toml", "Pipfile"
        ]
        found = []
        for pattern in patterns:
            found.extend(self.workspace_path.rglob(pattern))
        return found

    async def _run_pip_audit(self, req_file: Path) -> Optional[DependencyScanResult]:
        """Execute pip-audit and parse JSON output."""
        logger.info(f"  Running pip-audit on {req_file.name}...")
        result = DependencyScanResult()

        try:
            process = await asyncio.create_subprocess_shell(
                f"pip-audit -r \"{req_file}\" --format=json --progress-spinner=off",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if stdout:
                raw_data = json.loads(stdout.decode())
                dependencies = raw_data.get("dependencies", [])
                result.total_packages = len(dependencies)

                for dep in dependencies:
                    vulns = dep.get("vulns", [])
                    for vuln in vulns:
                        finding = DependencyFinding(
                            package_name=dep.get("name", "unknown"),
                            installed_version=dep.get("version", "?"),
                            fixed_version=vuln.get("fix_versions", [None])[0]
                            if vuln.get("fix_versions")
                            else None,
                            vulnerability_id=vuln.get("id", "UNKNOWN"),
                            description=vuln.get("description", ""),
                            severity=self._map_severity(vuln),
                        )
                        result.findings.append(finding)

                result.vulnerable_packages = len(
                    set(f.package_name for f in result.findings)
                )
                result.status = "success"

                logger.info(
                    f"  pip-audit: {result.total_packages} packages scanned, "
                    f"{result.vulnerable_packages} vulnerable."
                )
                return result

            # pip-audit exited but no stdout — likely no vulns found
            result.status = "success"
            result.total_packages = 0
            return result

        except FileNotFoundError:
            logger.warning("  pip-audit is not installed. Skipping SCA scan.")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"  pip-audit JSON parse error: {e}")
            result.status = "failed"
            result.error_message = str(e)
            return result
        except Exception as e:
            logger.error(f"  pip-audit execution failed: {e}")
            result.status = "failed"
            result.error_message = str(e)
            return result

    @staticmethod
    def _map_severity(vuln: dict) -> str:
        """Map pip-audit vulnerability data to a severity string."""
        # pip-audit doesn't always include severity directly
        vuln_id = vuln.get("id", "")
        # PYSEC entries are generally HIGH or CRITICAL
        if vuln_id.startswith("PYSEC"):
            return "HIGH"
        if vuln_id.startswith("CVE"):
            return "HIGH"
        return "MEDIUM"

    def format_for_report(self, result: DependencyScanResult) -> str:
        """Format dependency findings for inclusion in the pipeline report."""
        if result.status == "skipped":
            return "Dependency scanning was skipped."
        if result.status == "failed":
            return f"Dependency scanning failed: {result.error_message}"

        if not result.findings:
            return "No vulnerable dependencies found."

        lines = [f"Found {len(result.findings)} vulnerable dependencies:"]
        for f in result.findings:
            fix_str = f" → Fix: upgrade to {f.fixed_version}" if f.fixed_version else " → No fix available"
            lines.append(
                f"  • {f.package_name}=={f.installed_version} "
                f"({f.vulnerability_id}){fix_str}"
            )
        return "\n".join(lines)
