"""
Phase 10: Security Report Generator
Goal: Aggregate all pipeline outputs (Semgrep findings, Joern taint flows, 
      ML Fusion verdicts, LangGraph debate results, applied patches) 
      into a comprehensive JSON + HTML report.
"""

import json
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VulnerabilityReport:
    """Final report entry for a single vulnerability."""
    file_path: str
    function_name: str
    start_line: int
    end_line: int
    vulnerability_type: str  # e.g., "SQL Injection"
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    cwe_id: str  # e.g., "CWE-89"
    semgrep_rule: str
    rag_context: str
    joern_taint_flow: str
    ml_fusion_verdict: str  # "true_positive" | "false_positive"
    ml_fusion_confidence: float
    attacker_exploit: str
    defender_patch: str
    judge_verdict: str  # "PASS" | "FAIL"
    patch_applied: bool = False
    human_approved: Optional[bool] = None


@dataclass
class PipelineReport:
    """Complete pipeline execution report."""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    target_repository: str = ""
    total_files_scanned: int = 0
    total_code_blocks: int = 0
    total_static_findings: int = 0
    findings_after_ml_filter: int = 0
    vulnerabilities: List[VulnerabilityReport] = field(default_factory=list)
    
    # Aggregate metrics
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    patches_applied: int = 0
    patches_rejected: int = 0


class ReportGenerator:
    """Generates JSON and HTML reports from pipeline execution data."""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json_report(self, report: PipelineReport) -> str:
        """Writes the full pipeline report to a timestamped JSON file."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.json"
        filepath = self.output_dir / filename

        # Convert dataclass to dict
        report_dict = asdict(report)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, default=str)

        logger.info(f"📄 JSON Report saved: {filepath}")
        return str(filepath)

    def generate_html_report(self, report: PipelineReport) -> str:
        """Generates a styled HTML security report for human review."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.html"
        filepath = self.output_dir / filename

        # Compute severity distribution
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in report.vulnerabilities:
            sev = v.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        vuln_rows = ""
        for i, v in enumerate(report.vulnerabilities, 1):
            status_badge = (
                '<span style="color:#22c55e">✅ Patched</span>'
                if v.patch_applied
                else '<span style="color:#ef4444">❌ Unpatched</span>'
            )
            severity_color = {
                "CRITICAL": "#dc2626", "HIGH": "#f97316",
                "MEDIUM": "#eab308", "LOW": "#3b82f6"
            }.get(v.severity.upper(), "#6b7280")

            vuln_rows += f"""
            <tr>
                <td>{i}</td>
                <td><code>{v.file_path}</code></td>
                <td><code>{v.function_name}</code></td>
                <td style="color:{severity_color};font-weight:bold">{v.severity.upper()}</td>
                <td>{v.vulnerability_type}</td>
                <td>{v.cwe_id}</td>
                <td>{v.judge_verdict}</td>
                <td>{status_badge}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        .header {{ text-align: center; padding: 2rem; background: linear-gradient(135deg, #1e293b, #334155); border-radius: 12px; margin-bottom: 2rem; }}
        .header h1 {{ font-size: 2rem; color: #38bdf8; }}
        .header p {{ color: #94a3b8; margin-top: 0.5rem; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: #1e293b; padding: 1.5rem; border-radius: 10px; text-align: center; }}
        .stat-card .number {{ font-size: 2.5rem; font-weight: bold; color: #38bdf8; }}
        .stat-card .label {{ color: #94a3b8; font-size: 0.9rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }}
        th {{ background: #334155; padding: 12px; text-align: left; color: #38bdf8; }}
        td {{ padding: 12px; border-bottom: 1px solid #334155; }}
        tr:hover {{ background: #253347; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }}
        .footer {{ text-align: center; margin-top: 2rem; color: #64748b; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI Security Code Review Report</h1>
        <p>Generated: {report.timestamp} | Target: {report.target_repository}</p>
        <p>Pipeline: Semgrep → Joern CPG → ML Fusion → LangGraph MoA Debate → Patch</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="number">{report.total_files_scanned}</div>
            <div class="label">Files Scanned</div>
        </div>
        <div class="stat-card">
            <div class="number">{report.total_static_findings}</div>
            <div class="label">Static Findings</div>
        </div>
        <div class="stat-card">
            <div class="number">{report.findings_after_ml_filter}</div>
            <div class="label">After ML Filter</div>
        </div>
        <div class="stat-card">
            <div class="number">{len(report.vulnerabilities)}</div>
            <div class="label">Confirmed Vulns</div>
        </div>
        <div class="stat-card">
            <div class="number">{report.patches_applied}</div>
            <div class="label">Patches Applied</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#ef4444">{severity_counts.get('CRITICAL', 0)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#f97316">{severity_counts.get('HIGH', 0)}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color:#eab308">{severity_counts.get('MEDIUM', 0)}</div>
            <div class="label">Medium</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>File</th>
                <th>Function</th>
                <th>Severity</th>
                <th>Vulnerability</th>
                <th>CWE</th>
                <th>Judge</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {vuln_rows}
        </tbody>
    </table>

    <div class="footer">
        <p>AI Security Code Reviewer — B.Tech Project | Powered by LangGraph MoA + DeepSeek-V2 + Qwen2.5</p>
    </div>
</body>
</html>"""

        filepath.write_text(html, encoding="utf-8")
        logger.info(f"🌐 HTML Report saved: {filepath}")
        return str(filepath)
