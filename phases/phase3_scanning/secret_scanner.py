"""
Phase 3 Add-on: Secret Scanner
Regex + entropy-based scanner for detecting hardcoded credentials,
API keys, tokens, and private keys in source code.
Complements Semgrep/Ruff by catching secrets that static rules miss.
"""

import re
import math
from pathlib import Path
from typing import List
from dataclasses import dataclass

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SecretFinding:
    """A detected secret/credential in source code."""
    file_path: str
    line_number: int
    secret_type: str      # e.g., "AWS Access Key", "Generic API Key"
    matched_text: str     # The redacted matched text
    confidence: str       # "HIGH" | "MEDIUM"


# ---- REGEX PATTERNS ----
# Each tuple: (name, compiled_regex, confidence)
SECRET_PATTERNS = [
    (
        "AWS Access Key ID",
        re.compile(r"(?:AKIA)[A-Z0-9]{16}", re.ASCII),
        "HIGH",
    ),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "HIGH",
    ),
    (
        "GitHub Token",
        re.compile(r"(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}"),
        "HIGH",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "HIGH",
    ),
    (
        "Slack Token",
        re.compile(r"xox[bporas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}"),
        "HIGH",
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "HIGH",
    ),
    (
        "Generic API Key Assignment",
        re.compile(r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"][A-Za-z0-9+/=_\-]{20,}['"]"""),
        "MEDIUM",
    ),
    (
        "Generic Password Assignment",
        re.compile(r"""(?i)(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]"""),
        "MEDIUM",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "MEDIUM",
    ),
    (
        "Hex-encoded Secret (32+ chars)",
        re.compile(r"""(?i)(?:secret|token|key)\s*[=:]\s*['"]?[0-9a-f]{32,}['"]?"""),
        "MEDIUM",
    ),
]

# Files to skip (binaries, lock files, etc.)
SKIP_EXTENSIONS = {
    ".lock", ".min.js", ".min.css", ".map", ".woff", ".woff2",
    ".ttf", ".eot", ".ico", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".pdf", ".zip", ".gz", ".tar", ".pyc", ".pyo",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. High entropy → likely a secret."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _redact(text: str, visible: int = 6) -> str:
    """Redact a secret, showing only the first few characters."""
    if len(text) <= visible:
        return "***REDACTED***"
    return text[:visible] + "..." + "*" * min(8, len(text) - visible)


class SecretScanner:
    """
    Scans source files for hardcoded secrets using regex patterns
    and Shannon entropy analysis.
    """

    def __init__(self, entropy_threshold: float = 4.5):
        self.entropy_threshold = entropy_threshold

    def scan_directory(self, directory: Path) -> List[SecretFinding]:
        """Scan all files in a directory tree for secrets."""
        findings = []
        if not directory.exists():
            logger.warning(f"Directory does not exist: {directory}")
            return findings

        for file_path in directory.rglob("*"):
            # Skip directories and non-text files
            if file_path.is_dir():
                continue
            if file_path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if any(skip_dir in file_path.parts for skip_dir in SKIP_DIRS):
                continue
            # Only scan reasonably-sized text files
            if file_path.stat().st_size > 1_000_000:  # 1MB limit
                continue

            try:
                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)
            except (UnicodeDecodeError, PermissionError):
                continue

        logger.info(f"Secret Scanner: found {len(findings)} potential secrets in {directory}")
        return findings

    def _scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file for secrets."""
        findings = []
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return findings

        for line_num, line in enumerate(lines, 1):
            # Skip comment-only lines that are documentation
            stripped = line.strip()
            if stripped.startswith("#") and "example" in stripped.lower():
                continue

            # Pattern-based detection
            for pattern_name, pattern, confidence in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    matched = match.group(0)
                    findings.append(SecretFinding(
                        file_path=str(file_path),
                        line_number=line_num,
                        secret_type=pattern_name,
                        matched_text=_redact(matched),
                        confidence=confidence,
                    ))

            # Entropy-based detection for long strings (catch unknown key formats)
            self._check_entropy(line, line_num, str(file_path), findings)

        return findings

    def _check_entropy(
        self, line: str, line_num: int, file_path: str,
        findings: List[SecretFinding]
    ):
        """Check for high-entropy strings that may be secrets."""
        # Find quoted strings
        for match in re.finditer(r"""['"]([A-Za-z0-9+/=_\-]{24,})['"]""", line):
            candidate = match.group(1)
            entropy = _shannon_entropy(candidate)
            if entropy >= self.entropy_threshold:
                # Check it wasn't already caught by regex patterns
                already_found = any(
                    f.line_number == line_num and f.file_path == file_path
                    for f in findings
                )
                if not already_found:
                    findings.append(SecretFinding(
                        file_path=file_path,
                        line_number=line_num,
                        secret_type=f"High-Entropy String (Shannon={entropy:.2f})",
                        matched_text=_redact(candidate),
                        confidence="MEDIUM",
                    ))
