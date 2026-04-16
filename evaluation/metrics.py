"""
Evaluation Metrics Module
Computes Precision, Recall, F1, and False Positive Rate comparing
Baseline (SAST-only) versus Full Pipeline (SAST + ML Fusion + LangGraph MoA).
Ported from HackerSec's evaluation/metrics.py and adapted for our pipeline.
"""

import json
import datetime
from pathlib import Path
from typing import List, Dict, Any

from utils.logger import get_logger

logger = get_logger(__name__)


def calculate_metrics(eval_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes absolute performance bounds comparing Baseline (SAST-only) against
    the full ML + LangGraph pipeline.
    
    Each eval_result entry should have:
        {
            "file": str,
            "cwe": str,
            "true_label": int (1=vulnerable, 0=safe),
            "baseline_pred": int (1=flagged, 0=not flagged),
            "pipeline_pred": int (1=flagged, 0=not flagged)
        }
    """
    metrics = {
        "baseline": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "pipeline": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
    }

    for res in eval_results:
        true_label = res["true_label"]
        b_pred = res["baseline_pred"]
        p_pred = res["pipeline_pred"]

        # Baseline (Semgrep-only) confusion matrix
        if b_pred == 1 and true_label == 1: metrics["baseline"]["tp"] += 1
        elif b_pred == 1 and true_label == 0: metrics["baseline"]["fp"] += 1
        elif b_pred == 0 and true_label == 0: metrics["baseline"]["tn"] += 1
        elif b_pred == 0 and true_label == 1: metrics["baseline"]["fn"] += 1

        # Full Pipeline confusion matrix
        if p_pred == 1 and true_label == 1: metrics["pipeline"]["tp"] += 1
        elif p_pred == 1 and true_label == 0: metrics["pipeline"]["fp"] += 1
        elif p_pred == 0 and true_label == 0: metrics["pipeline"]["tn"] += 1
        elif p_pred == 0 and true_label == 1: metrics["pipeline"]["fn"] += 1

    def _compute_scores(counts: Dict[str, int]) -> Dict[str, float]:
        tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        }

    return {
        "baseline_metrics": _compute_scores(metrics["baseline"]),
        "pipeline_metrics": _compute_scores(metrics["pipeline"]),
        "raw_counts": metrics,
        "total_samples": len(eval_results),
    }


def export_results(metrics: Dict[str, Any], out_dir: str = "./eval_results") -> str:
    """Saves evaluation metrics to a timestamped JSON file."""
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)

    filename = f"{datetime.date.today().isoformat()}_eval_run.json"
    filepath = base / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    logger.info(f"📊 Evaluation results exported: {filepath}")
    return str(filepath)


def print_comparison(metrics: Dict[str, Any]):
    """Pretty-prints a side-by-side comparison of Baseline vs Pipeline metrics."""
    bl = metrics["baseline_metrics"]
    pl = metrics["pipeline_metrics"]

    print("\n" + "=" * 60)
    print("📊 EVALUATION RESULTS: BASELINE vs FULL PIPELINE")
    print("=" * 60)
    print(f"{'Metric':<15} {'Baseline (SAST)':<20} {'Full Pipeline':<20}")
    print("-" * 55)
    print(f"{'Precision':<15} {bl['precision']:<20.4f} {pl['precision']:<20.4f}")
    print(f"{'Recall':<15} {bl['recall']:<20.4f} {pl['recall']:<20.4f}")
    print(f"{'F1 Score':<15} {bl['f1']:<20.4f} {pl['f1']:<20.4f}")
    print(f"{'FPR':<15} {bl['fpr']:<20.4f} {pl['fpr']:<20.4f}")
    print("=" * 60)
    print(f"Total Samples: {metrics['total_samples']}")
    print("=" * 60 + "\n")
