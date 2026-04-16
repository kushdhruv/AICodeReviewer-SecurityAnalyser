"""
Phase 4.5 - ML Feature Extraction
Converts raw StaticFinding + EnrichedCodeChunk data into a numerical feature vector 
for the GradientBoosting classifier. Inspired by HackerSec's analysis/ml/features.py.
"""

from typing import List
from utils.logger import get_logger
from phases.phase3_scanning.scanner import EnrichedCodeChunk

logger = get_logger(__name__)

# Severity -> numerical confidence mapping (inheriting HackerSec's SEVERITY_CONFIDENCE)
SEVERITY_CONFIDENCE = {
    "CRITICAL": 1.0, "critical": 1.0,
    "HIGH": 0.8, "high": 0.8,
    "ERROR": 0.8,       # Ruff uses ERROR severity
    "WARNING": 0.6,
    "MEDIUM": 0.5, "medium": 0.5,
    "LOW": 0.2, "low": 0.2,
    "INFO": 0.1, "info": 0.1,
}

# Known critical CWE categories (from HackerSec features.py)
CRITICAL_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-798", "CWE-77"}
HIGH_CWES = {"CWE-79", "CWE-22", "CWE-918", "CWE-287", "CWE-306", "CWE-434"}


def extract_features(chunk: EnrichedCodeChunk) -> List[float]:
    """
    Extracts a 6-dimensional feature vector from an EnrichedCodeChunk:
    
    [0] static_confidence   — highest severity score across all findings
    [1] finding_count       — total number of static findings (normalized)
    [2] code_complexity     — proxy for complexity (line count of chunk)
    [3] has_dangerous_sink  — 1.0 if code contains exec/eval/query/system calls
    [4] cwe_severity_score  — scored from our critical CWE lookup table
    [5] multi_tool_agreement— 1.0 if both Ruff and Semgrep flagged this chunk
    """

    # [0] Static Confidence: take the max severity across all findings
    max_severity = 0.0
    for f in chunk.findings:
        score = SEVERITY_CONFIDENCE.get(f.severity, 0.3)
        if score > max_severity:
            max_severity = score
    static_confidence = max_severity

    # [1] Finding Count: normalize (cap at 10 findings)
    finding_count = min(len(chunk.findings) / 10.0, 1.0)

    # [2] Code Complexity: line count proxy (normalized to 0-1, cap at 100 lines)
    line_count = chunk.chunk.content.count("\n") + 1
    code_complexity = min(line_count / 100.0, 1.0)

    # [3] Has Dangerous Sink: check if the code contains exploitable function calls
    dangerous_keywords = [
        "execute", "query", "system", "eval", "exec", "popen",
        "subprocess", "os.system", "cursor.execute", "shell=True",
        "pickle.loads", "yaml.load", "open("
    ]
    code_lower = chunk.chunk.content.lower()
    has_dangerous_sink = 1.0 if any(kw in code_lower for kw in dangerous_keywords) else 0.0

    # [4] CWE Severity Score: check if any finding rule_id maps to a known critical CWE
    cwe_severity_score = 0.3  # default
    for f in chunk.findings:
        rule_id_upper = f.rule_id.upper()
        # Many Semgrep rules embed CWE in the rule ID
        for cwe in CRITICAL_CWES:
            if cwe.replace("-", "") in rule_id_upper or cwe in f.message.upper():
                cwe_severity_score = 1.0
                break
        if cwe_severity_score < 0.8:
            for cwe in HIGH_CWES:
                if cwe.replace("-", "") in rule_id_upper or cwe in f.message.upper():
                    cwe_severity_score = 0.8

    # [5] Multi-Tool Agreement: both Ruff AND Semgrep flagged this chunk
    tools_seen = set(f.tool_name for f in chunk.findings)
    multi_tool_agreement = 1.0 if len(tools_seen) > 1 else 0.0

    return [
        static_confidence,
        finding_count,
        code_complexity,
        has_dangerous_sink,
        cwe_severity_score,
        multi_tool_agreement,
    ]
