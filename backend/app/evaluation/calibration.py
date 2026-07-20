"""Derive the two calibrated constants the detection pipeline ships.

This module is the *provenance* for numbers that would otherwise be magic
constants in ``app.api.ingest`` and ``app.agents.behaviour_agent``:

1. ``ANOMALY_LR_INTERCEPT`` / ``ANOMALY_LR_SLOPE`` - the anomaly-score term of
   the Bayesian likelihood ratio in ``api.ingest.derive_likelihood_ratio``.
2. ``DECISION_THRESHOLD`` - ``BehaviourLearningAgent.confidence_threshold``,
   the score above which an event is called anomalous.

Both are fit on the **calibration** slice of the chronological three-way split
(``BenchmarkDataset.split_three_way``) and are never fit on the holdout slice
that ``detection_eval`` reports. Run

    python -m app.evaluation.calibration

to re-derive them and print the values to paste back into the source, together
with the fit diagnostics. Nothing here runs at inference time.

The likelihood-ratio form
-------------------------
We want ``LR(s) = P(s | compromised) / P(s | benign)`` for a fused anomaly
score ``s``. Rather than inventing class-conditional densities, we fit the
*posterior* with a one-feature logistic regression on labelled calibration data

    P(malicious | s) = sigmoid(b0 + b1 * s)

and convert it to a likelihood ratio by dividing out the class prior, which is
exactly Bayes' rule rearranged:

    LR(s) = [P(mal|s) / P(ben|s)] / [P(mal) / P(ben)]
          = exp(b0 + b1 * s) / prior_odds

so, in log space, a straight line:

    log LR(s) = (b0 - log prior_odds) + b1 * s
              = ANOMALY_LR_INTERCEPT + ANOMALY_LR_SLOPE * s

Two constants, a closed form, and a neutral point (LR = 1) that falls wherever
the data actually puts it: ``s* = -INTERCEPT / SLOPE``. That neutral point is
the thing the previous hand-picked mapping got wrong - it sat at s ~= 0.486
while genuine attack steps scored below it, so roughly half of every intrusion's
evidence pushed P(compromised) *down*.

Dividing out the prior matters. The corpus is ~3% malicious; without that term
the "likelihood ratio" would silently smuggle the corpus base rate into a
quantity the world model then multiplies by its own prior, double-counting it.

The threshold
-------------
``DECISION_THRESHOLD`` is the smallest sweep threshold whose calibration-split
false-positive rate is at or below ``TARGET_FPR``. An FPR target is the right
knob for a SOC: it bounds analyst workload per unit of telemetry, which is the
binding constraint in practice, whereas maximising F1 optimises a quantity that
depends on the corpus class balance and so does not transfer to a live estate.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

from app.evaluation.datasets import (
    BenchmarkDataset,
    LabeledRecord,
    generate_benchmark_dataset,
    logger,
)

#: Operating point target: at most 5 false alerts per 100 benign records.
TARGET_FPR = 0.05


def _fit_logistic(x: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    """One-feature logistic regression by Newton-Raphson (no sklearn needed).

    Returns ``(b0, b1)`` for ``P(y=1 | x) = sigmoid(b0 + b1 * x)``. Newton is
    used rather than an off-the-shelf fitter so the whole derivation stays
    inspectable and dependency-free; on a single feature it converges in a few
    iterations.
    """
    X = np.column_stack([np.ones_like(x), x])
    beta = np.zeros(2)
    for _ in range(100):
        eta = X @ beta
        p = 1.0 / (1.0 + np.exp(-np.clip(eta, -30, 30)))
        w = np.clip(p * (1.0 - p), 1e-9, None)
        gradient = X.T @ (y - p)
        hessian = (X * w[:, None]).T @ X
        # Ridge term keeps the Hessian invertible when the split is separable.
        step = np.linalg.solve(hessian + 1e-6 * np.eye(2), gradient)
        beta = beta + step
        if np.max(np.abs(step)) < 1e-10:
            break
    return float(beta[0]), float(beta[1])


def score_split(
    agent: Any,
    baseline: Sequence[LabeledRecord],
    records: Sequence[LabeledRecord],
) -> tuple[np.ndarray, np.ndarray]:
    """Fit profiles on ``baseline``, return ``(labels, fused_scores)`` for ``records``."""
    for record in baseline:
        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, record.to_behaviour_input())
        agent._record_sample(profile)
    for entity_type in sorted({r.entity_type for r in baseline}):
        agent.train_baseline(entity_type, force=True)

    labels: List[int] = []
    scores: List[float] = []
    for record in records:
        event = record.to_behaviour_input()
        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, event)
        agent._record_sample(profile)
        model = agent._model_score(profile)
        rule = agent._detect_anomalies(profile, event)
        fused, _path = agent._combine_scores(
            float(rule.get("score", 0.0)), model,
            float(rule.get("specific_score", 0.0)),
        )
        labels.append(1 if record.is_malicious else 0)
        scores.append(float(fused))
    return np.asarray(labels, dtype=float), np.asarray(scores, dtype=float)


def derive_constants(dataset: Optional[BenchmarkDataset] = None) -> Dict[str, Any]:
    """Fit the LR mapping and select the decision threshold on the calibration split."""
    from app.agents.behaviour_agent import BehaviourLearningAgent

    dataset = dataset or generate_benchmark_dataset()
    baseline, calibration, holdout = dataset.split_three_way()

    y, s = score_split(BehaviourLearningAgent(), baseline, calibration)

    positives = float(y.sum())
    negatives = float(len(y) - positives)
    if positives == 0 or negatives == 0:
        raise ValueError(
            "calibration split contains a single class; cannot fit a likelihood "
            "ratio from it"
        )

    b0, b1 = _fit_logistic(s, y)
    prior_odds = positives / negatives
    intercept = b0 - math.log(prior_odds)
    slope = b1
    neutral_point = -intercept / slope if slope else float("nan")

    # Threshold: smallest sweep point meeting the FPR target on calibration.
    sweep: List[Dict[str, Any]] = []
    chosen: Optional[float] = None
    for threshold in np.arange(0.0, 1.0, 0.01):
        predicted = (s > threshold).astype(int)
        fp = float(((predicted == 1) & (y == 0)).sum())
        tp = float(((predicted == 1) & (y == 1)).sum())
        fn = float(((predicted == 0) & (y == 1)).sum())
        fpr = fp / negatives
        recall = tp / positives if positives else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        sweep.append({
            "threshold": round(float(threshold), 4),
            "fpr": round(fpr, 4),
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "f1": round(f1, 4),
        })
        if chosen is None and fpr <= TARGET_FPR:
            chosen = float(threshold)

    best_f1 = max(sweep, key=lambda row: row["f1"])

    return {
        "target_fpr": TARGET_FPR,
        "decision_threshold": None if chosen is None else round(chosen, 4),
        "anomaly_lr_intercept": round(intercept, 6),
        "anomaly_lr_slope": round(slope, 6),
        "logistic_b0": round(b0, 6),
        "logistic_b1": round(b1, 6),
        "calibration_prior_odds": round(prior_odds, 6),
        "neutral_point_score": round(neutral_point, 6),
        "calibration_records": int(len(y)),
        "calibration_positives": int(positives),
        "calibration_negatives": int(negatives),
        "holdout_records": len(holdout),
        "baseline_records": len(baseline),
        "best_f1_on_calibration": best_f1,
        "calibration_sweep": sweep,
        "seed": dataset.provenance.get("seed"),
        "dataset": dataset.provenance.get("dataset"),
    }


def main() -> None:  # pragma: no cover - operator entry point
    result = derive_constants()
    print("=" * 74)
    print("CALIBRATION - fit on the calibration split only")
    print("=" * 74)
    print(f"  dataset            : {result['dataset']} (seed {result['seed']})")
    print(f"  baseline records   : {result['baseline_records']}")
    print(f"  calibration records: {result['calibration_records']} "
          f"({result['calibration_positives']} malicious / "
          f"{result['calibration_negatives']} benign)")
    print(f"  holdout records    : {result['holdout_records']} (not used here)")
    print()
    print("  Paste into app/api/ingest.py:")
    print(f"    ANOMALY_LR_INTERCEPT = {result['anomaly_lr_intercept']}")
    print(f"    ANOMALY_LR_SLOPE     = {result['anomaly_lr_slope']}")
    print(f"    (logistic b0={result['logistic_b0']} b1={result['logistic_b1']}, "
          f"prior odds={result['calibration_prior_odds']})")
    print(f"    LR = 1 at anomaly score {result['neutral_point_score']}")
    print()
    print("  Paste into app/agents/behaviour_agent.py:")
    print(f"    DECISION_THRESHOLD = {result['decision_threshold']} "
          f"(first sweep point with FPR <= {result['target_fpr']})")
    print(f"    best F1 on calibration: {result['best_f1_on_calibration']}")
    print("=" * 74)


if __name__ == "__main__":  # pragma: no cover
    main()
