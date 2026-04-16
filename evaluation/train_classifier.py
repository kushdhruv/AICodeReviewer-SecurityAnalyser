"""
ML Fusion Classifier — Training Script (RLHF Loop)
===================================================
Trains a GradientBoosting classifier from the human-feedback RLHF dataset 
(training_dataset.jsonl) generated during pipeline runs.

This closes the RLHF loop:
  Pipeline Run → Human Approves/Rejects Patches → training_dataset.jsonl
  → This Script → fusion_model.joblib → Pipeline uses trained model

Usage:
  python -m evaluation.train_classifier
  python -m evaluation.train_classifier --input training_dataset.jsonl --output ./data/fusion_model.joblib

Requires:
  pip install scikit-learn pandas joblib shap
"""

import json
import argparse
import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix, precision_score,
    recall_score, f1_score
)

from utils.logger import get_logger

logger = get_logger(__name__)

# Feature names must match what extract_features() returns
FEATURE_NAMES = [
    "static_confidence", "finding_count", "code_complexity",
    "has_dangerous_sink", "cwe_severity_score", "multi_tool_agreement"
]

# Known dangerous sinks (mirrors features.py)
DANGEROUS_KEYWORDS = [
    "execute", "query", "system", "eval", "exec", "popen",
    "subprocess", "os.system", "cursor.execute", "shell=true",
    "pickle.loads", "yaml.load", "open("
]

# CWE severity mapping (mirrors features.py)
CRITICAL_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-798", "CWE-77"}
HIGH_CWES = {"CWE-79", "CWE-22", "CWE-918", "CWE-287", "CWE-306", "CWE-434"}

SEVERITY_CONFIDENCE = {
    "CRITICAL": 1.0, "critical": 1.0,
    "HIGH": 0.8, "high": 0.8,
    "ERROR": 0.8,
    "WARNING": 0.6,
    "MEDIUM": 0.5, "medium": 0.5,
    "LOW": 0.2, "low": 0.2,
    "INFO": 0.1, "info": 0.1,
}


def extract_features_from_rlhf(entry: Dict[str, Any]) -> List[float]:
    """
    Extract the same 6-dimensional feature vector from an RLHF training entry.
    This mirrors phases/phase_ml_fusion/features.py but works on the JSONL format
    rather than EnrichedCodeChunk objects.
    """
    vuln_desc = entry.get("vulnerability_description", "")
    code = entry.get("original_code", "")

    # [0] Static Confidence: guess from severity keywords in description
    static_confidence = 0.5
    for sev, score in SEVERITY_CONFIDENCE.items():
        if sev.lower() in vuln_desc.lower():
            static_confidence = max(static_confidence, score)

    # [1] Finding Count: approximate from description (each "Severity:" block)
    finding_count = min(vuln_desc.count("Severity:") / 10.0, 1.0)

    # [2] Code Complexity: line count proxy
    line_count = code.count("\n") + 1
    code_complexity = min(line_count / 100.0, 1.0)

    # [3] Has Dangerous Sink
    code_lower = code.lower()
    has_dangerous_sink = 1.0 if any(kw in code_lower for kw in DANGEROUS_KEYWORDS) else 0.0

    # [4] CWE Severity Score
    cwe_severity_score = 0.3
    desc_upper = vuln_desc.upper()
    for cwe in CRITICAL_CWES:
        if cwe in desc_upper or cwe.replace("-", "") in desc_upper:
            cwe_severity_score = 1.0
            break
    if cwe_severity_score < 0.8:
        for cwe in HIGH_CWES:
            if cwe in desc_upper or cwe.replace("-", "") in desc_upper:
                cwe_severity_score = 0.8

    # [5] Multi-tool agreement: check if description mentions multiple tools
    tools_mentioned = 0
    if "semgrep" in vuln_desc.lower() or "Severity:" in vuln_desc:
        tools_mentioned += 1
    if "ruff" in vuln_desc.lower():
        tools_mentioned += 1
    multi_tool = 1.0 if tools_mentioned > 1 else 0.0

    return [
        static_confidence, finding_count, code_complexity,
        has_dangerous_sink, cwe_severity_score, multi_tool,
    ]


def load_training_data(jsonl_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load and featurize the training dataset.
    
    Returns:
        X: feature matrix (n_samples, 6)
        y: labels (1 = true positive / human approved, 0 = false positive / rejected)
    """
    path = Path(jsonl_path)
    if not path.exists():
        raise FileNotFoundError(f"Training dataset not found: {jsonl_path}")

    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    if len(entries) < 10:
        logger.warning(
            f"Only {len(entries)} training samples found. "
            f"Recommend at least 50+ for meaningful training."
        )

    X = np.array([extract_features_from_rlhf(e) for e in entries])
    y = np.array([1 if e.get("human_approved", False) else 0 for e in entries])

    logger.info(f"Loaded {len(entries)} samples: {sum(y)} positive, {len(y) - sum(y)} negative")
    return X, y


def train_model(
    X: np.ndarray,
    y: np.ndarray,
    output_path: str = "./data/fusion_model.joblib",
) -> Dict[str, Any]:
    """
    Trains a GradientBoostingClassifier and saves it.
    
    Returns:
        Dictionary with training metrics.
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Hyperparameters tuned for security classification
    model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.8,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
    )

    # Cross-validation to estimate generalization
    metrics = {}
    if len(y) >= 20:
        cv = StratifiedKFold(n_splits=min(5, len(y) // 4), shuffle=True, random_state=42)

        precision_scores = cross_val_score(model, X, y, cv=cv, scoring="precision")
        recall_scores = cross_val_score(model, X, y, cv=cv, scoring="recall")
        f1_scores = cross_val_score(model, X, y, cv=cv, scoring="f1")

        metrics["cv_precision"] = round(float(np.mean(precision_scores)), 4)
        metrics["cv_recall"] = round(float(np.mean(recall_scores)), 4)
        metrics["cv_f1"] = round(float(np.mean(f1_scores)), 4)

        logger.info(f"Cross-Validation Results:")
        logger.info(f"  Precision: {metrics['cv_precision']:.4f} ± {np.std(precision_scores):.4f}")
        logger.info(f"  Recall:    {metrics['cv_recall']:.4f} ± {np.std(recall_scores):.4f}")
        logger.info(f"  F1:        {metrics['cv_f1']:.4f} ± {np.std(f1_scores):.4f}")
    else:
        logger.warning("Too few samples for cross-validation. Training on all data.")

    # Train final model on all data
    model.fit(X, y)

    # Feature importances
    importances = dict(zip(FEATURE_NAMES, model.feature_importances_))
    metrics["feature_importances"] = {k: round(float(v), 4) for k, v in importances.items()}

    logger.info("Feature Importances:")
    for name, imp in sorted(importances.items(), key=lambda x: -x[1]):
        logger.info(f"  {name}: {imp:.4f}")

    # Save the trained model
    joblib.dump(model, str(output_file))
    logger.info(f"✅ Trained model saved to {output_file}")

    # Save training metadata
    meta = {
        "trained_at": datetime.datetime.now().isoformat(),
        "n_samples": len(y),
        "n_positive": int(sum(y)),
        "n_negative": int(len(y) - sum(y)),
        "metrics": metrics,
    }
    meta_path = output_file.with_suffix(".meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    logger.info(f"📄 Training metadata saved to {meta_path}")

    return metrics


def main():
    parser = argparse.ArgumentParser(
        description="Train the ML Fusion Classifier from RLHF human feedback data."
    )
    parser.add_argument(
        "--input", "-i",
        default="training_dataset.jsonl",
        help="Path to the RLHF training dataset (default: training_dataset.jsonl)"
    )
    parser.add_argument(
        "--output", "-o",
        default="./data/fusion_model.joblib",
        help="Path to save the trained model (default: ./data/fusion_model.joblib)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("🧠 ML Fusion Classifier — Training Pipeline")
    print("=" * 60)

    try:
        X, y = load_training_data(args.input)
        metrics = train_model(X, y, output_path=args.output)

        print("\n" + "=" * 60)
        print("✅ TRAINING COMPLETE")
        print("=" * 60)
        if "cv_f1" in metrics:
            print(f"  Cross-Val F1:    {metrics['cv_f1']:.4f}")
            print(f"  Cross-Val Prec:  {metrics['cv_precision']:.4f}")
            print(f"  Cross-Val Rec:   {metrics['cv_recall']:.4f}")
        print(f"  Model saved to:  {args.output}")
        print("=" * 60)

    except FileNotFoundError as e:
        print(f"\n❌ {e}")
        print("Run the pipeline first to generate training data:")
        print("  python main.py <repo_url>")
        print("  Then approve/reject patches to build the RLHF dataset.")

    except Exception as e:
        print(f"\n❌ Training failed: {e}")
        raise


if __name__ == "__main__":
    main()
