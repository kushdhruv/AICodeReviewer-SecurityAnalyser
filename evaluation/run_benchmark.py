"""
Evaluation Benchmark Harness
============================
Automated evaluation of the full pipeline (Semgrep + ML Fusion + LangGraph MoA)
against a labeled dataset of known-vulnerable and known-safe code samples.

Produces Precision, Recall, F1, and FPR metrics comparing:
  - Baseline: Semgrep-only detection
  - Full Pipeline: Semgrep + ML Fusion Classifier

Usage:
  python -m evaluation.run_benchmark
  python -m evaluation.run_benchmark --dataset data/benchmark_dataset

The benchmark dataset should be a folder of Python files with naming convention:
  CWE-89_vuln_001.py   → known vulnerable (label=1)
  CWE-89_safe_001.py   → known safe (label=0)
"""

import asyncio
import json
import argparse
import datetime
from pathlib import Path
from typing import List, Dict, Any

from utils.logger import get_logger
from evaluation.metrics import calculate_metrics, export_results, print_comparison

logger = get_logger(__name__)


def parse_label_from_filename(filename: str) -> int:
    """
    Extract the ground-truth label from the filename convention.
    Files containing '_vuln_' are vulnerable (1), '_safe_' are safe (0).
    """
    name_lower = filename.lower()
    if "_vuln_" in name_lower or "_vulnerable_" in name_lower:
        return 1
    elif "_safe_" in name_lower or "_benign_" in name_lower:
        return 0
    else:
        # Unknown — treat as vulnerable to be conservative
        return 1


def extract_cwe_from_filename(filename: str) -> str:
    """Extract CWE ID from filename, e.g., 'CWE-89_vuln_001.py' → 'CWE-89'."""
    import re
    match = re.search(r"CWE-\d+", filename, re.IGNORECASE)
    return match.group(0).upper() if match else "UNKNOWN"


async def run_semgrep_on_file(file_path: Path) -> bool:
    """Run Semgrep on a single file and return whether it flagged any findings."""
    try:
        process = await asyncio.create_subprocess_shell(
            f'semgrep scan --config=p/security-audit --json "{file_path}"',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        if stdout:
            data = json.loads(stdout.decode())
            results = data.get("results", [])
            return len(results) > 0
        return False
    except Exception as e:
        logger.warning(f"Semgrep error on {file_path.name}: {e}")
        return False


async def run_ml_filter_on_file(file_path: Path, semgrep_flagged: bool) -> bool:
    """
    Simulate running the ML Fusion Classifier on a file.
    If Semgrep didn't flag it, the ML filter can't override (no finding to filter).
    If Semgrep did flag it, run through our feature extraction + classifier.
    """
    if not semgrep_flagged:
        return False  # Can't confirm what wasn't found

    try:
        from phases.phase2_parsing.parser import CodeParser, CodeChunk
        from phases.phase3_scanning.scanner import StaticFinding, EnrichedCodeChunk
        from phases.phase_ml_fusion.classifier import FusionClassifier

        # Parse the file
        parser = CodeParser()
        chunks = parser.parse_file(file_path)

        if not chunks:
            # File has no parseable functions — treat as a false positive
            return False

        # Create a synthetic EnrichedCodeChunk with a dummy finding
        chunk = chunks[0]
        dummy_finding = StaticFinding(
            tool_name="Semgrep",
            rule_id=extract_cwe_from_filename(file_path.name),
            message=f"Potential vulnerability detected in {chunk.name}",
            severity="HIGH",
            file_path=str(file_path),
            line_number=chunk.start_line,
        )
        enriched = EnrichedCodeChunk(chunk=chunk, findings=[dummy_finding])

        # Run through ML classifier
        classifier = FusionClassifier()
        result = classifier.predict_chunk(enriched)
        return result["prediction"] == "true_positive"

    except Exception as e:
        logger.warning(f"ML filter error on {file_path.name}: {e}")
        return semgrep_flagged  # Fallback to Semgrep result


async def run_benchmark(dataset_dir: str = "data/benchmark_dataset") -> Dict[str, Any]:
    """
    Execute the full benchmark: run each test case through Baseline and Pipeline.
    """
    dataset_path = Path(dataset_dir)
    if not dataset_path.exists():
        logger.error(f"Benchmark dataset not found at: {dataset_path}")
        logger.info("Creating sample dataset structure...")
        create_sample_dataset(dataset_path)
        logger.info(f"Sample dataset created at {dataset_path}")
        logger.info("Populate it with real test cases and re-run.")
        return {}

    # Collect all Python test files
    test_files = sorted(dataset_path.glob("*.py"))
    if not test_files:
        logger.error("No .py files found in benchmark dataset.")
        return {}

    logger.info(f"Found {len(test_files)} benchmark test cases.")

    eval_results = []

    for i, file_path in enumerate(test_files, 1):
        true_label = parse_label_from_filename(file_path.name)
        cwe = extract_cwe_from_filename(file_path.name)

        logger.info(f"  [{i}/{len(test_files)}] {file_path.name} (label={true_label}, {cwe})")

        # Baseline: Semgrep-only
        baseline_flagged = await run_semgrep_on_file(file_path)

        # Pipeline: Semgrep + ML Fusion
        pipeline_flagged = await run_ml_filter_on_file(file_path, baseline_flagged)

        eval_results.append({
            "file": file_path.name,
            "cwe": cwe,
            "true_label": true_label,
            "baseline_pred": 1 if baseline_flagged else 0,
            "pipeline_pred": 1 if pipeline_flagged else 0,
        })

    # Calculate metrics
    metrics = calculate_metrics(eval_results)
    metrics["benchmark_date"] = datetime.datetime.now().isoformat()
    metrics["dataset_path"] = str(dataset_path)

    return metrics


def create_sample_dataset(dataset_path: Path):
    """
    Creates a sample benchmark dataset with clearly vulnerable and safe files.
    These serve as a starting point — add real-world test cases for better benchmarks.
    """
    dataset_path.mkdir(parents=True, exist_ok=True)

    # --- SQL Injection: Vulnerable ---
    (dataset_path / "CWE-89_vuln_001.py").write_text('''
import sqlite3

def get_user(db_path, username):
    """VULNERABLE: SQL Injection via string concatenation."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
''', encoding="utf-8")

    # --- SQL Injection: Safe ---
    (dataset_path / "CWE-89_safe_001.py").write_text('''
import sqlite3

def get_user(db_path, username):
    """SAFE: Uses parameterized query."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()
''', encoding="utf-8")

    # --- Command Injection: Vulnerable ---
    (dataset_path / "CWE-78_vuln_001.py").write_text('''
import subprocess

def ping_host(host):
    """VULNERABLE: Command injection via shell=True."""
    cmd = f"ping -c 4 {host}"
    return subprocess.check_output(cmd, shell=True)
''', encoding="utf-8")

    # --- Command Injection: Safe ---
    (dataset_path / "CWE-78_safe_001.py").write_text('''
import subprocess

def ping_host(host):
    """SAFE: Uses list args without shell."""
    cmd = ["ping", "-c", "4", host]
    return subprocess.check_output(cmd, shell=False)
''', encoding="utf-8")

    # --- XSS: Vulnerable ---
    (dataset_path / "CWE-79_vuln_001.py").write_text('''
from flask import request, render_template_string

def hello():
    """VULNERABLE: Reflected XSS."""
    name = request.args.get("name", "World")
    return render_template_string("<h1>Hello {}!</h1>".format(name))
''', encoding="utf-8")

    # --- XSS: Safe ---
    (dataset_path / "CWE-79_safe_001.py").write_text('''
import html
from flask import request

def hello():
    """SAFE: HTML-escapes user input."""
    name = request.args.get("name", "World")
    safe_name = html.escape(name)
    return f"<h1>Hello {safe_name}!</h1>"
''', encoding="utf-8")

    # --- Deserialization: Vulnerable ---
    (dataset_path / "CWE-502_vuln_001.py").write_text('''
import pickle

def load_data(raw_bytes):
    """VULNERABLE: Unsafe pickle deserialization."""
    return pickle.loads(raw_bytes)
''', encoding="utf-8")

    # --- Deserialization: Safe ---
    (dataset_path / "CWE-502_safe_001.py").write_text('''
import json

def load_data(raw_bytes):
    """SAFE: Uses JSON instead of pickle."""
    return json.loads(raw_bytes)
''', encoding="utf-8")

    # --- Hardcoded Credentials: Vulnerable ---
    (dataset_path / "CWE-798_vuln_001.py").write_text('''
import boto3

def get_client():
    """VULNERABLE: Hardcoded AWS credentials."""
    return boto3.client("s3",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY"
    )
''', encoding="utf-8")

    # --- Hardcoded Credentials: Safe ---
    (dataset_path / "CWE-798_safe_001.py").write_text('''
import boto3
import os

def get_client():
    """SAFE: Credentials from environment variables."""
    return boto3.client("s3",
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY")
    )
''', encoding="utf-8")

    # --- Path Traversal: Vulnerable ---
    (dataset_path / "CWE-22_vuln_001.py").write_text('''
import os
from flask import send_file, request

def download():
    """VULNERABLE: Path traversal via unvalidated input."""
    filename = request.args.get("file")
    filepath = os.path.join("/var/www/uploads", filename)
    return send_file(filepath)
''', encoding="utf-8")

    # --- Path Traversal: Safe ---
    (dataset_path / "CWE-22_safe_001.py").write_text('''
import os
from flask import send_file, request, abort
from werkzeug.utils import secure_filename

def download():
    """SAFE: Uses secure_filename + path validation."""
    filename = request.args.get("file")
    safe_name = secure_filename(filename)
    filepath = os.path.join("/var/www/uploads", safe_name)
    if not os.path.abspath(filepath).startswith("/var/www/uploads"):
        abort(403)
    return send_file(filepath)
''', encoding="utf-8")

    logger.info(f"Created {len(list(dataset_path.glob('*.py')))} sample benchmark files.")


def main():
    parser = argparse.ArgumentParser(
        description="Run the Benchmark Harness: Baseline (Semgrep) vs Full Pipeline"
    )
    parser.add_argument(
        "--dataset", "-d",
        default="data/benchmark_dataset",
        help="Path to the benchmark dataset folder (default: data/benchmark_dataset)"
    )
    parser.add_argument(
        "--output", "-o",
        default="./eval_results",
        help="Directory to save evaluation results (default: ./eval_results)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("📊 Security Pipeline Benchmark Harness")
    print("=" * 60)

    metrics = asyncio.run(run_benchmark(dataset_dir=args.dataset))

    if metrics:
        print_comparison(metrics)
        export_path = export_results(metrics, out_dir=args.output)
        print(f"\n📄 Full results exported to: {export_path}")
    else:
        print("\n⚠️ No results generated. Populate the benchmark dataset and retry.")


if __name__ == "__main__":
    main()
