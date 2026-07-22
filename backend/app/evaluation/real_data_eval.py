"""Evaluate models trained on a real public NIDS dataset against a held-out split.

Sibling of :mod:`app.evaluation.detection_eval` (which scores the behavioural
agent on the synthetic corpus). This module scores flow-level artifacts
(:class:`app.ml.real_data_detector.DetectorArtifact`) on the real test split and
reports detection rate at fixed FPR operating points, ROC-AUC, the confusion
matrix, and a calibration check. Every number is computed at run time from the
supplied labels and scores; nothing is asserted or hardcoded.
"""

from __future__ import annotations

from typing import Any, Dict, List

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
)

from app.evaluation.calibration import _fit_logistic
from app.evaluation.detection_eval import _metrics_at_threshold
from app.ml.real_data_detector import DetectorArtifact

FIXED_FPR_POINTS = (0.01, 0.05, 0.10)


def _detection_at_fpr(
    y_true: np.ndarray, y_score: np.ndarray, target_fpr: float
) -> Dict[str, Any]:
    fpr, tpr, thresholds = roc_curve(y_true, y_score)
    eligible = np.where(fpr <= target_fpr)[0]
    if eligible.size == 0:
        idx = int(np.argmin(fpr))
    else:
        idx = int(eligible[np.argmax(tpr[eligible])])
    threshold = float(thresholds[idx])
    y_pred = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "target_fpr": target_fpr,
        "threshold": round(threshold, 6),
        "achieved_fpr": round(float(fpr[idx]), 6),
        "detection_rate": round(float(tpr[idx]), 6),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def _calibration_check(y_true: np.ndarray, y_score: np.ndarray) -> Dict[str, Any]:
    lo, hi = float(np.min(y_score)), float(np.max(y_score))
    if hi <= lo:
        return {"applies": False, "reason": "degenerate score range"}
    normalised = (y_score - lo) / (hi - lo)
    b0, b1 = _fit_logistic(normalised, y_true.astype(float))
    brier = float(brier_score_loss(y_true, normalised))
    return {
        "applies": True,
        "method": "1-feature logistic (calibration._fit_logistic) on min-max scores",
        "logistic_intercept": round(b0, 4),
        "logistic_slope": round(b1, 4),
        "slope_positive": b1 > 0,
        "brier_score_minmax": round(brier, 4),
        "note": (
            "Slope>0 confirms higher scores track higher attack probability. "
            "Brier is on min-max-normalised scores, not a probability the model "
            "emits, so read it as relative reliability, not an absolute figure."
        ),
    }


def evaluate_artifact(
    artifact: DetectorArtifact, x_test_raw: pd.DataFrame, y_test: np.ndarray
) -> Dict[str, Any]:
    y_test = np.asarray(y_test).astype(int)
    scores = artifact.score(x_test_raw)
    if scores.shape[0] != y_test.shape[0]:
        raise ValueError(
            f"score/label length mismatch: {scores.shape[0]} vs {y_test.shape[0]}"
        )

    roc_auc = float(roc_auc_score(y_test, scores))
    avg_precision = float(average_precision_score(y_test, scores))
    det_at_fpr = [_detection_at_fpr(y_test, scores, p) for p in FIXED_FPR_POINTS]

    diagnostic = None
    if artifact.kind == "isolation_forest" and roc_auc < 0.5:
        mal_rate = float(y_test.mean())
        diagnostic = (
            f"ROC-AUC {roc_auc:.3f} is below 0.5: the unsupervised score is "
            f"anti-correlated with the label. On this split attacks are the "
            f"MAJORITY class ({mal_rate:.1%}), so IsolationForest learns the "
            f"attack traffic as the dense 'normal' region and flags the benign "
            f"minority as anomalous. Unsupervised novelty detection assumes "
            f"anomalies are rare; that assumption is violated here. A benign-only "
            f"(semi-supervised) fit would fix it but needs labels at fit time, "
            f"which this run deliberately does not use. This is a real property "
            f"of the dataset/method, not a scoring bug - see the supervised model."
        )

    operating = det_at_fpr[1]
    confusion_at_5pct = _metrics_at_threshold(y_test, scores, operating["threshold"])

    return {
        "kind": artifact.kind,
        "test_samples": int(y_test.shape[0]),
        "test_malicious": int(y_test.sum()),
        "test_malicious_rate": round(float(y_test.mean()), 6),
        "roc_auc": round(roc_auc, 6),
        "average_precision": round(avg_precision, 6),
        "detection_rate_at_fixed_fpr": det_at_fpr,
        "confusion_matrix_at_5pct_fpr": confusion_at_5pct,
        "calibration": _calibration_check(y_test, scores),
        "score_orientation": "higher = more likely attack",
        "diagnostic": diagnostic,
        "metadata": artifact.metadata,
    }


def evaluate_real_models(
    artifacts: Dict[str, DetectorArtifact],
    x_test_raw: pd.DataFrame,
    y_test: np.ndarray,
) -> Dict[str, Any]:
    results = {name: evaluate_artifact(art, x_test_raw, y_test) for name, art in artifacts.items()}
    return {
        "models": results,
        "fixed_fpr_points": list(FIXED_FPR_POINTS),
        "interpretation": (
            "detection_rate_at_fixed_fpr is the recall achievable while holding "
            "false positives at 1/5/10%. Compare the unsupervised IsolationForest "
            "against the supervised RandomForest: the gap is the value the labels "
            "add on this dataset."
        ),
    }
