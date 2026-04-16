"""
Phase 4.5 - ML Fusion Classifier
A GradientBoosting classifier that filters static analysis findings to reduce 
false positives before forwarding them to the expensive LangGraph LLM debate.

Inspired by HackerSec's analysis/ml/inference.py but adapted for our 
EnrichedCodeChunk pipeline and with a security-conservative bias.
"""

import numpy as np
import joblib
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

from utils.logger import get_logger
from phases.phase3_scanning.scanner import EnrichedCodeChunk
from phases.phase_ml_fusion.features import extract_features

logger = get_logger(__name__)

# Security-conservative threshold: lower than 0.5 to bias toward flagging
# It's better to flag a false positive than miss a real vulnerability
DECISION_THRESHOLD = 0.4

FEATURE_NAMES = [
    "static_confidence", "finding_count", "code_complexity",
    "has_dangerous_sink", "cwe_severity_score", "multi_tool_agreement"
]


class FusionClassifier:
    """
    Wrapper around a trained scikit-learn model.
    Loads a pre-trained model if available, otherwise defaults to
    a heuristic-based fallback that never drops critical findings.
    """

    def __init__(self, model_path: str = "./data/fusion_model.joblib"):
        self.model_path = Path(model_path)
        self.model = None
        self._load()

    def _load(self):
        """Load pre-trained model if it exists."""
        if self.model_path.exists():
            try:
                self.model = joblib.load(str(self.model_path))
                logger.info(f"✅ Fusion Classifier loaded from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load fusion model: {e}")
                self.model = None
        else:
            logger.info(
                "⚠️ No pre-trained fusion model found. "
                "Using heuristic-based filtering as fallback."
            )

    def predict_chunk(self, chunk: EnrichedCodeChunk) -> Dict[str, Any]:
        """
        Predicts whether a chunk's findings are true positives or false positives.
        
        Returns:
            {
                "prediction": "true_positive" | "false_positive",
                "confidence": float (0.0 - 1.0),
                "shap_values": dict | None (feature importance if SHAP available)
            }
        """
        features = extract_features(chunk)
        X = np.array([features])

        # --- TRAINED MODEL PATH ---
        if self.model:
            try:
                probs = self.model.predict_proba(X)[0]
                prob_tp = probs[1] if len(probs) >= 2 else float(self.model.predict(X)[0])

                prediction = "true_positive" if prob_tp >= DECISION_THRESHOLD else "false_positive"

                # SHAP explainability
                shap_dict = self._explain(X) if SHAP_AVAILABLE else None

                return {
                    "prediction": prediction,
                    "confidence": round(float(prob_tp), 4),
                    "shap_values": shap_dict
                }

            except Exception as e:
                logger.error(f"Fusion predict exception: {e}")
                # On error, default to true_positive (security conservative)
                return {"prediction": "true_positive", "confidence": 0.5, "error": str(e)}

        # --- HEURISTIC FALLBACK PATH ---
        return self._heuristic_predict(features)

    def _heuristic_predict(self, features: List[float]) -> Dict[str, Any]:
        """
        Rule-based fallback when no trained model is available.
        Uses a weighted sum of features to make a security-conservative decision.
        """
        weights = [0.25, 0.10, 0.05, 0.30, 0.20, 0.10]
        weighted_score = sum(f * w for f, w in zip(features, weights))

        # Normalize to 0-1
        confidence = min(max(weighted_score / max(sum(weights), 1e-9), 0.0), 1.0)

        prediction = "true_positive" if confidence >= DECISION_THRESHOLD else "false_positive"

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "shap_values": None,
            "method": "heuristic_fallback"
        }

    def _explain(self, X: np.ndarray) -> Optional[Dict[str, float]]:
        """Generate SHAP feature importance values for transparency."""
        if not SHAP_AVAILABLE or not self.model:
            return None

        try:
            explainer = shap.TreeExplainer(self.model)
            shap_vals = explainer.shap_values(X)

            if isinstance(shap_vals, list) and len(shap_vals) >= 2:
                target_shap = shap_vals[1][0]
            elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
                target_shap = shap_vals[0]
            else:
                target_shap = shap_vals[0] if isinstance(shap_vals, (list, np.ndarray)) else []

            return {
                name: round(float(target_shap[i]), 4)
                for i, name in enumerate(FEATURE_NAMES) if i < len(target_shap)
            }
        except Exception as e:
            logger.warning(f"SHAP explainer failed: {e}")
            return None


def filter_false_positives(
    chunks: List[EnrichedCodeChunk],
    model_path: str = "./data/fusion_model.joblib"
) -> List[EnrichedCodeChunk]:
    """
    Convenience function: runs all chunks through the Fusion Classifier
    and returns only true positives (chunks worth sending to the LLM debate).
    """
    classifier = FusionClassifier(model_path=model_path)
    filtered = []
    dropped = 0

    for chunk in chunks:
        result = classifier.predict_chunk(chunk)
        if result["prediction"] == "true_positive":
            filtered.append(chunk)
            logger.info(
                f"  ✅ KEEP: {chunk.chunk.name} "
                f"(confidence={result['confidence']}, method={result.get('method', 'model')})"
            )
        else:
            dropped += 1
            logger.info(
                f"  🗑️ DROP: {chunk.chunk.name} "
                f"(confidence={result['confidence']}, likely false positive)"
            )

    logger.info(
        f"Fusion Classifier: {len(filtered)} true positives retained, "
        f"{dropped} false positives dropped."
    )
    return filtered
