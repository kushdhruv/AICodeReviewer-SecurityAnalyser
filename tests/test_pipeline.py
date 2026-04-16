"""
Unit Tests for the AI Security Code Reviewer Pipeline.
Covers: ML feature extraction, evaluation metrics, and patch applicator.

Run with:
  python -m pytest tests/ -v
"""

import os
import json
import tempfile
from pathlib import Path

import pytest


# ====================================
# TEST 1: ML Feature Extraction
# ====================================

class TestFeatureExtraction:
    """Tests for phases/phase_ml_fusion/features.py"""

    def _make_chunk(self, code: str, severity: str = "HIGH",
                    rule_id: str = "CWE-89", tool: str = "Semgrep"):
        """Helper: creates an EnrichedCodeChunk for testing."""
        from phases.phase2_parsing.parser import CodeChunk
        from phases.phase3_scanning.scanner import StaticFinding, EnrichedCodeChunk

        chunk = CodeChunk(
            file_path="test.py",
            chunk_type="function",
            name="test_func",
            start_line=1,
            end_line=10,
            content=code,
            language="python",
        )
        finding = StaticFinding(
            tool_name=tool,
            rule_id=rule_id,
            message="Test vulnerability",
            severity=severity,
            file_path="test.py",
            line_number=5,
        )
        return EnrichedCodeChunk(chunk=chunk, findings=[finding])

    def test_feature_vector_length(self):
        """Feature vector must always be exactly 6 elements."""
        from phases.phase_ml_fusion.features import extract_features

        chunk = self._make_chunk("def foo(): pass")
        features = extract_features(chunk)
        assert len(features) == 6, f"Expected 6 features, got {len(features)}"

    def test_dangerous_sink_detection(self):
        """Code with eval/exec/system should have has_dangerous_sink=1.0."""
        from phases.phase_ml_fusion.features import extract_features

        safe_chunk = self._make_chunk("def foo():\n    return 42")
        dangerous_chunk = self._make_chunk("def foo():\n    eval(user_input)")

        safe_features = extract_features(safe_chunk)
        dangerous_features = extract_features(dangerous_chunk)

        assert safe_features[3] == 0.0, "Safe code should not flag dangerous sink"
        assert dangerous_features[3] == 1.0, "eval() should flag as dangerous sink"

    def test_severity_mapping(self):
        """HIGH severity should produce higher static_confidence than LOW."""
        from phases.phase_ml_fusion.features import extract_features

        high_chunk = self._make_chunk("def foo(): pass", severity="HIGH")
        low_chunk = self._make_chunk("def foo(): pass", severity="LOW")

        high_features = extract_features(high_chunk)
        low_features = extract_features(low_chunk)

        assert high_features[0] > low_features[0], \
            f"HIGH ({high_features[0]}) should score higher than LOW ({low_features[0]})"

    def test_critical_cwe_score(self):
        """CWE-89 (SQL Injection) should get max CWE severity score."""
        from phases.phase_ml_fusion.features import extract_features

        sqli_chunk = self._make_chunk("def foo(): pass", rule_id="CWE-89")
        features = extract_features(sqli_chunk)

        assert features[4] == 1.0, f"CWE-89 should score 1.0, got {features[4]}"

    def test_multi_tool_agreement(self):
        """Multi-tool agreement should be 1.0 when both Ruff and Semgrep flag."""
        from phases.phase2_parsing.parser import CodeChunk
        from phases.phase3_scanning.scanner import StaticFinding, EnrichedCodeChunk
        from phases.phase_ml_fusion.features import extract_features

        chunk = CodeChunk(
            file_path="test.py", chunk_type="function", name="test_func",
            start_line=1, end_line=10, content="def foo(): eval(x)",
            language="python",
        )
        findings = [
            StaticFinding("Semgrep", "CWE-94", "eval", "HIGH", "test.py", 1),
            StaticFinding("Ruff", "S307", "eval", "ERROR", "test.py", 1),
        ]
        enriched = EnrichedCodeChunk(chunk=chunk, findings=findings)

        features = extract_features(enriched)
        assert features[5] == 1.0, "Two tools should give agreement=1.0"


# ====================================
# TEST 2: Evaluation Metrics
# ====================================

class TestEvaluationMetrics:
    """Tests for evaluation/metrics.py"""

    def test_perfect_scores(self):
        """A perfect classifier should get Precision=1.0, Recall=1.0, F1=1.0, FPR=0.0."""
        from evaluation.metrics import calculate_metrics

        results = [
            {"file": "a.py", "cwe": "CWE-89", "true_label": 1, "baseline_pred": 1, "pipeline_pred": 1},
            {"file": "b.py", "cwe": "CWE-89", "true_label": 0, "baseline_pred": 0, "pipeline_pred": 0},
            {"file": "c.py", "cwe": "CWE-78", "true_label": 1, "baseline_pred": 1, "pipeline_pred": 1},
            {"file": "d.py", "cwe": "CWE-78", "true_label": 0, "baseline_pred": 0, "pipeline_pred": 0},
        ]
        metrics = calculate_metrics(results)
        pm = metrics["pipeline_metrics"]

        assert pm["precision"] == 1.0
        assert pm["recall"] == 1.0
        assert pm["f1"] == 1.0
        assert pm["fpr"] == 0.0

    def test_all_false_positives(self):
        """A classifier that flags everything has FPR=1.0 and low precision."""
        from evaluation.metrics import calculate_metrics

        results = [
            {"file": "a.py", "cwe": "CWE-89", "true_label": 0, "baseline_pred": 1, "pipeline_pred": 1},
            {"file": "b.py", "cwe": "CWE-89", "true_label": 0, "baseline_pred": 1, "pipeline_pred": 1},
            {"file": "c.py", "cwe": "CWE-89", "true_label": 1, "baseline_pred": 1, "pipeline_pred": 1},
        ]
        metrics = calculate_metrics(results)
        pm = metrics["pipeline_metrics"]

        assert pm["fpr"] == 1.0, f"FPR should be 1.0 when all negatives are flagged"
        assert pm["precision"] < 1.0, "Precision should be less than 1.0"

    def test_pipeline_improves_over_baseline(self):
        """The pipeline should reduce FPs compared to baseline."""
        from evaluation.metrics import calculate_metrics

        results = [
            # Baseline flags both, pipeline only flags the real vuln
            {"file": "a.py", "cwe": "CWE-89", "true_label": 1, "baseline_pred": 1, "pipeline_pred": 1},
            {"file": "b.py", "cwe": "CWE-89", "true_label": 0, "baseline_pred": 1, "pipeline_pred": 0},
        ]
        metrics = calculate_metrics(results)

        assert metrics["pipeline_metrics"]["fpr"] < metrics["baseline_metrics"]["fpr"], \
            "Pipeline should have lower FPR than baseline"


# ====================================
# TEST 3: Patch Applicator
# ====================================

class TestPatchApplicator:
    """Tests for phases/phase7_patching/apply.py"""

    def test_successful_patch(self):
        """A valid patch should be applied and the file content should change."""
        from phases.phase7_patching.apply import PatchApplicator

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "target.py"
            test_file.write_text(
                "line1\n"
                "def vulnerable():\n"
                "    query = 'SELECT * FROM ' + user_input\n"
                "line4\n",
                encoding="utf-8"
            )

            patcher = PatchApplicator(backup_dir=str(Path(tmpdir) / "backups"))
            success = patcher.apply_patch(
                file_path=str(test_file),
                original_code="def vulnerable():\n    query = 'SELECT * FROM ' + user_input",
                patched_code="def safe():\n    query = 'SELECT * FROM users WHERE id = ?'",
                start_line=2,
                end_line=3,
            )

            assert success, "Patch application should succeed"
            content = test_file.read_text(encoding="utf-8")
            assert "safe" in content, "Patched code should be in file"

    def test_syntax_error_rejected(self):
        """A patch with syntax errors should be rejected."""
        from phases.phase7_patching.apply import PatchApplicator

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "target.py"
            test_file.write_text("def foo():\n    pass\n", encoding="utf-8")

            patcher = PatchApplicator(backup_dir=str(Path(tmpdir) / "backups"))
            success = patcher.apply_patch(
                file_path=str(test_file),
                original_code="def foo():\n    pass",
                patched_code="def foo(:\n    broken syntax here!!!",  # Invalid
                start_line=1,
                end_line=2,
            )

            assert not success, "Patch with syntax errors should be rejected"

    def test_backup_created(self):
        """Applying a patch should create a .bak backup file."""
        from phases.phase7_patching.apply import PatchApplicator

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "target.py"
            test_file.write_text("def foo():\n    pass\n", encoding="utf-8")
            backup_dir = Path(tmpdir) / "backups"

            patcher = PatchApplicator(backup_dir=str(backup_dir))
            patcher.apply_patch(
                file_path=str(test_file),
                original_code="def foo():\n    pass",
                patched_code="def bar():\n    return 42",
                start_line=1,
                end_line=2,
            )

            backups = list(backup_dir.glob("*.bak"))
            assert len(backups) >= 1, "A backup file should have been created"

    def test_rollback(self):
        """Rolling back should restore the original file content."""
        from phases.phase7_patching.apply import PatchApplicator

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "target.py"
            original_content = "def foo():\n    pass\n"
            test_file.write_text(original_content, encoding="utf-8")

            patcher = PatchApplicator(backup_dir=str(Path(tmpdir) / "backups"))

            # Apply patch
            patcher.apply_patch(
                file_path=str(test_file),
                original_code="def foo():\n    pass",
                patched_code="def bar():\n    return 42",
                start_line=1,
                end_line=2,
            )
            assert "bar" in test_file.read_text(encoding="utf-8")

            # Rollback
            success = patcher.rollback(str(test_file))
            assert success, "Rollback should succeed"
            assert test_file.read_text(encoding="utf-8") == original_content


# ====================================
# TEST 4: Secret Scanner
# ====================================

class TestSecretScanner:
    """Tests for phases/phase3_scanning/secret_scanner.py"""

    def test_detects_aws_key(self):
        """Should detect an AWS Access Key ID pattern."""
        from phases.phase3_scanning.secret_scanner import SecretScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "config.py"
            test_file.write_text(
                'aws_key = "AKIAIOSFODNN7EXAMPLE"\n',
                encoding="utf-8"
            )

            scanner = SecretScanner()
            findings = scanner.scan_directory(Path(tmpdir))
            assert len(findings) >= 1, "Should detect AWS key"
            assert any("AWS" in f.secret_type for f in findings)

    def test_no_false_positive_on_safe_code(self):
        """Normal code should not trigger secret detection."""
        from phases.phase3_scanning.secret_scanner import SecretScanner

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "safe.py"
            test_file.write_text(
                'def hello():\n    return "Hello World"\n',
                encoding="utf-8"
            )

            scanner = SecretScanner()
            findings = scanner.scan_directory(Path(tmpdir))
            assert len(findings) == 0, f"Safe code should have 0 findings, got {len(findings)}"
