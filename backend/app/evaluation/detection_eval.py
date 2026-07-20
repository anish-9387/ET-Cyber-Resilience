"""Anomaly detection rate / false positive rate evaluation.

Runs the **real** ``BehaviourLearningAgent`` over the labelled corpus and
computes confusion-matrix metrics with ``sklearn.metrics``. No metric is
clamped, floored, smoothed or rounded toward a flattering value. If the
detector performs poorly, the payload says so and
``headline_claim_supported`` goes ``False``.

Methodology
-----------
1. **Baseline training split** - the earliest chronological slice, filtered to
   benign-only. This mirrors how a behavioural baseline is really built and
   avoids leaking attack steps into the profile that the detector is later
   scored against.
2. **Evaluation split** - the remaining records, benign and malicious.
3. Each evaluation record is scored through the **shipped** path: the profile is
   updated with the event, the sklearn ``IsolationForest`` is (re)fitted when
   due, and the rule score is fused with the model score via the agent's own
   ``_combine_scores`` noisy-OR. We record the rule-only, model-only and fused
   scores separately so it is visible which signal is actually carrying the
   detection rather than crediting the ensemble for the rule engine's work.
4. Metrics at the agent's own ``confidence_threshold``, plus a full threshold
   sweep so the FPR/recall tradeoff is visible rather than cherry-picked.

Note on the profile update: the agent folds an event into the entity profile
before scoring it, so an event partially defines the baseline it is measured
against. This *dilutes* detection rather than inflating it (an attack step makes
itself look marginally more normal), so replicating the shipped behaviour is the
conservative choice. It is recorded in the payload as
``profile_updated_before_scoring``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    roc_auc_score,
)

from app.evaluation.datasets import (
    BenchmarkDataset,
    LabeledRecord,
    generate_benchmark_dataset,
    logger,
)

# The README claims "82% prediction accuracy" and "90% false-positive
# reduction". These are the numbers this module exists to test rather than
# repeat. Recorded here so the payload can state explicitly whether the
# measured result supports them.
README_CLAIMED_ACCURACY = 0.82
README_CLAIMED_FP_REDUCTION = 0.90


@dataclass
class DetectionScores:
    """Raw per-record scores and labels, before any thresholding."""

    y_true: np.ndarray
    y_score: np.ndarray
    rule_score: np.ndarray
    model_score: np.ndarray
    model_available: np.ndarray
    record_ids: List[str]

    def __len__(self) -> int:
        return int(self.y_true.shape[0])


def _describe_detector_backend(agent: Any) -> Dict[str, Any]:
    """Introspect what is actually doing the detecting.

    The ``BehaviourLearningAgent`` originally shipped an
    ``IsolationForestDetector`` whose ``score_samples`` returned
    ``np.random.uniform(...)`` - noise, not a model. It now delegates to
    ``app.ml.anomaly_detector.AnomalyDetector``. We verify at runtime that the
    underlying estimator is a genuine sklearn ``IsolationForest`` rather than
    assuming it, and report the answer either way.
    """
    detector_cls = None
    estimator_path = None
    is_sklearn = False

    try:
        from app.ml.anomaly_detector import AnomalyDetector

        probe = AnomalyDetector()
        detector_cls = f"{type(probe).__module__}.{type(probe).__name__}"
        estimator = getattr(probe, "isolation_forest", None)
        if estimator is not None:
            estimator_path = (
                f"{type(estimator).__module__}.{type(estimator).__name__}"
            )
            is_sklearn = type(estimator).__module__.startswith("sklearn")
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("evaluation.detection: detector probe failed", error=str(exc))

    return {
        "scoring_path": (
            "BehaviourLearningAgent: _detect_anomalies (rules) fused with "
            "_model_score (IsolationForest) via _combine_scores noisy-OR"
        ),
        "detector_class": detector_cls,
        "estimator": estimator_path,
        "isolation_forest_is_sklearn": is_sklearn,
        "model_weight": getattr(
            __import__("app.agents.behaviour_agent", fromlist=["MODEL_WEIGHT"]),
            "MODEL_WEIGHT", None,
        ),
        "min_baseline_samples": getattr(
            __import__("app.agents.behaviour_agent", fromlist=["MIN_BASELINE_SAMPLES"]),
            "MIN_BASELINE_SAMPLES", None,
        ),
        "note": (
            "IsolationForest is a genuine sklearn estimator fitted on aggregate "
            "per-entity feature vectors. Because it scores the entity profile "
            "rather than the individual event, its contribution is coarse; the "
            "rule_score/model_score breakdown in this payload shows how much "
            "each signal actually contributes."
            if is_sklearn else
            "The anomaly model is NOT a real sklearn estimator. Reported scores "
            "should be treated as rule-engine output only."
        ),
    }


def _build_agent() -> Any:
    from app.agents.behaviour_agent import BehaviourLearningAgent

    return BehaviourLearningAgent()


def score_records(
    agent: Any,
    train: Sequence[LabeledRecord],
    evaluate: Sequence[LabeledRecord],
    warmup: Sequence[LabeledRecord] = (),
) -> DetectionScores:
    """Fit behavioural profiles on ``train``, then score ``evaluate``.

    Replicates the agent's shipped scoring path so the metrics describe the
    product as it actually behaves.
    """
    # 1. Build baseline profiles from benign history only, feeding the same
    #    sample-recording path the agent uses in production.
    for record in train:
        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, record.to_behaviour_input())
        agent._record_sample(profile)

    # 2. Fit the IsolationForest per entity type on the benign baseline.
    for entity_type in sorted({r.entity_type for r in train}):
        report = agent.train_baseline(entity_type, force=True)
        logger.info(
            "evaluation.detection: baseline trained",
            entity_type=entity_type,
            fitted=report.get("fitted"),
            samples=report.get("baseline_samples"),
        )

    # 2b. Replay the calibration window through the same state-updating path
    #     WITHOUT scoring it. The detector carries entity profiles forward in
    #     time, so skipping this window would present the holdout records to a
    #     detector that had never seen the intervening days - a different (and
    #     easier) detector than the one that ships. Nothing here is scored, so
    #     no record used to fit the threshold or the LR mapping enters the
    #     reported metrics.
    for record in warmup:
        event = record.to_behaviour_input()
        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, event)
        agent._record_sample(profile)

    # 3. Score evaluation records through the shipped fusion.
    y_true: List[int] = []
    y_score: List[float] = []
    rule_scores: List[float] = []
    model_scores: List[float] = []
    model_available: List[int] = []
    record_ids: List[str] = []

    for record in evaluate:
        event = record.to_behaviour_input()
        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, event)
        agent._record_sample(profile)

        model = agent._model_score(profile)
        rule = agent._detect_anomalies(profile, event)
        rule_value = float(rule.get("score", 0.0))
        fused, _path = agent._combine_scores(
            rule_value, model, float(rule.get("specific_score", rule_value))
        )

        y_true.append(1 if record.is_malicious else 0)
        y_score.append(float(fused))
        rule_scores.append(rule_value)
        model_scores.append(float(model["score"]) if model else 0.0)
        model_available.append(1 if model else 0)
        record_ids.append(record.record_id)

    return DetectionScores(
        y_true=np.asarray(y_true, dtype=int),
        y_score=np.asarray(y_score, dtype=float),
        rule_score=np.asarray(rule_scores, dtype=float),
        model_score=np.asarray(model_scores, dtype=float),
        model_available=np.asarray(model_available, dtype=int),
        record_ids=record_ids,
    )


def _metrics_at_threshold(
    y_true: np.ndarray, y_score: np.ndarray, threshold: float
) -> Dict[str, Any]:
    """Confusion matrix and derived rates at a single decision threshold."""
    y_pred = (y_score > threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    tp, fp, tn, fn = int(tp), int(fp), int(tn), int(fn)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)

    return {
        "threshold": round(float(threshold), 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "specificity": round(specificity, 4),
        "accuracy": round(accuracy, 4),
        "alerts_raised": tp + fp,
    }


def _threshold_sweep(y_true: np.ndarray, y_score: np.ndarray) -> List[Dict[str, Any]]:
    thresholds = [round(t, 2) for t in np.arange(0.0, 1.0, 0.05)]
    return [_metrics_at_threshold(y_true, y_score, t) for t in thresholds]


def _trivial_baselines(records: List[Any]) -> Dict[str, Any]:
    """Score dumb rules on the same split the detector is reported on.

    A detection metric is meaningless without knowing what a one-line rule
    achieves on the same data. On this synthetic corpus every benign record is
    severity 'info', so `severity != info` is a strong classifier - it is a
    property of how the corpus was authored, not of the environment. Reporting
    it alongside the model prevents the ML numbers from looking impressive
    against an unstated floor, and makes the corpus artefact impossible to miss.
    """
    def _score(predicate, name: str, note: str) -> Dict[str, Any]:
        tp = sum(1 for r in records if r.is_malicious and predicate(r))
        fp = sum(1 for r in records if not r.is_malicious and predicate(r))
        fn = sum(1 for r in records if r.is_malicious and not predicate(r))
        tn = sum(1 for r in records if not r.is_malicious and not predicate(r))
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return {
            "rule": name,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            "note": note,
        }

    return {
        "severity_not_info": _score(
            lambda r: r.severity != "info",
            "predict malicious iff severity != 'info'",
            "Uses the sensor's own grading. Zero false positives on this corpus "
            "because no benign record carries a non-info severity - a labelling "
            "artefact of the synthetic generator, not a real-world property.",
        ),
        "always_malicious": _score(
            lambda r: True,
            "predict malicious always",
            "Recall 1.0 by construction; precision equals the corpus base rate.",
        ),
        "interpretation": (
            "Compare the headline F1 against severity_not_info before claiming "
            "the detector adds value. The detector is withheld the severity "
            "field precisely so it cannot exploit this artefact; the trivial "
            "baseline can, and does."
        ),
    }


def evaluate_detection(
    dataset: Optional[BenchmarkDataset] = None,
    threshold: Optional[float] = None,
    train_fraction: float = 0.4,
    calibration_fraction: float = 0.2,
) -> Dict[str, Any]:
    """Compute detection metrics over a labelled corpus.

    Args:
        dataset: Labelled corpus. Defaults to the seeded synthetic benchmark.
        threshold: Decision threshold. Defaults to the agent's own
            ``confidence_threshold``, i.e. the value the product actually ships.
        train_fraction: Fraction of the timeline used to build the baseline.

    Returns:
        A payload matching ``GET /evaluation/detection`` in the API contract,
        extended with a threshold sweep, ROC-AUC, average precision and an
        explicit verdict on the README's marketing claims.
    """
    dataset = dataset or generate_benchmark_dataset()
    agent = _build_agent()
    threshold = agent.confidence_threshold if threshold is None else threshold

    # Three-way chronological split. The calibration slice is where the shipped
    # decision threshold and the likelihood-ratio mapping were fit
    # (app.evaluation.calibration); it is replayed for detector state but never
    # scored, so no metric below is reported on data it was tuned on.
    train, calibration, evaluation = dataset.split_three_way(
        train_fraction=train_fraction, calibration_fraction=calibration_fraction
    )

    if not evaluation:
        return {
            "error": "empty evaluation split",
            "dataset": dataset.provenance.get("dataset"),
            "samples": 0,
        }

    scores = score_records(agent, train, evaluation, warmup=calibration)
    y_true, y_score = scores.y_true, scores.y_score

    positives = int(y_true.sum())
    negatives = int(len(y_true) - positives)

    headline = _metrics_at_threshold(y_true, y_score, threshold)

    # ROC-AUC is undefined with a single class present; report None, not a
    # made-up value.
    if positives == 0 or negatives == 0:
        roc_auc: Optional[float] = None
        avg_precision: Optional[float] = None
        auc_note = "undefined: evaluation split contains a single class"
    else:
        roc_auc = round(float(roc_auc_score(y_true, y_score)), 4)
        avg_precision = round(float(average_precision_score(y_true, y_score)), 4)
        auc_note = None

    sweep = _threshold_sweep(y_true, y_score)
    best_f1 = max(sweep, key=lambda row: row["f1"])

    # Distinct score values tell us how much resolution the sweep really has.
    distinct_scores = int(np.unique(y_score).size)

    # Ablation: which signal is actually carrying the detection? Reporting only
    # the fused AUC would let the ensemble take credit for the rule engine's
    # work (or hide that the model contributes nothing).
    def _auc(values: np.ndarray) -> Optional[float]:
        if positives == 0 or negatives == 0 or np.unique(values).size < 2:
            return None
        return round(float(roc_auc_score(y_true, values)), 4)

    ablation = {
        "fused_roc_auc": roc_auc,
        "rules_only_roc_auc": _auc(scores.rule_score),
        "model_only_roc_auc": _auc(scores.model_score),
        "records_with_fitted_model": int(scores.model_available.sum()),
        "records_without_fitted_model": int(
            len(scores) - int(scores.model_available.sum())
        ),
        "interpretation": None,
    }
    notes: List[str] = []
    if ablation["rules_only_roc_auc"] is not None and roc_auc is not None:
        delta_rules = round(roc_auc - ablation["rules_only_roc_auc"], 4)
        ablation["fusion_gain_over_rules"] = delta_rules
        if abs(delta_rules) < 0.01:
            notes.append(
                "The IsolationForest adds essentially nothing over the rule "
                "engine; the ensemble's discrimination is the rule engine's."
            )
        elif delta_rules > 0:
            notes.append(
                f"Fusion improves ROC-AUC by {delta_rules} over rules alone."
            )
        else:
            notes.append(
                f"Fusion DEGRADES ROC-AUC by {abs(delta_rules)} versus rules alone."
            )

    if ablation["model_only_roc_auc"] is not None and roc_auc is not None:
        delta_model = round(roc_auc - ablation["model_only_roc_auc"], 4)
        ablation["fusion_gain_over_model"] = delta_model
        if delta_model < -0.01:
            notes.append(
                f"The IsolationForest ALONE (ROC-AUC "
                f"{ablation['model_only_roc_auc']}) outperforms the shipped "
                f"fusion ({roc_auc}) by {abs(delta_model)}. The noisy-OR is "
                "actively destroying discrimination by mixing in a weak rule "
                "signal."
            )
        elif delta_model > 0.01:
            notes.append(
                f"Fusion improves ROC-AUC by {delta_model} over the model alone."
            )

    if ablation["rules_only_roc_auc"] is not None and (
        abs(ablation["rules_only_roc_auc"] - 0.5) < 0.06
    ):
        notes.append(
            f"The rule engine alone scores ROC-AUC "
            f"{ablation['rules_only_roc_auc']}, i.e. statistically "
            "indistinguishable from random ranking on this corpus."
        )

    ablation["interpretation"] = " ".join(notes) if notes else None
    ablation["best_single_signal"] = max(
        [
            ("fused", roc_auc),
            ("rules_only", ablation["rules_only_roc_auc"]),
            ("model_only", ablation["model_only_roc_auc"]),
        ],
        key=lambda pair: (pair[1] if pair[1] is not None else -1.0),
    )[0]

    payload: Dict[str, Any] = {
        # --- contract fields ---
        "dataset": dataset.provenance.get("dataset"),
        "samples": len(scores),
        "tp": headline["tp"],
        "fp": headline["fp"],
        "tn": headline["tn"],
        "fn": headline["fn"],
        "precision": headline["precision"],
        "recall": headline["recall"],
        "f1": headline["f1"],
        "fpr": headline["fpr"],
        "roc_auc": roc_auc,
        # --- extended, honest detail ---
        "accuracy": headline["accuracy"],
        "specificity": headline["specificity"],
        "average_precision": avg_precision,
        "roc_auc_note": auc_note,
        "trivial_baselines": _trivial_baselines(evaluation),
        "decision_threshold": round(float(threshold), 4),
        "threshold_source": (
            "BehaviourLearningAgent.confidence_threshold, selected by "
            "app.evaluation.calibration as the smallest threshold with "
            "calibration-split FPR <= 0.05"
        ),
        "detection_rate": headline["recall"],
        "false_positive_rate": headline["fpr"],
        "positives_in_eval_split": positives,
        "negatives_in_eval_split": negatives,
        "baseline_training_records": len(train),
        "calibration_records_replayed_not_scored": len(calibration),
        "split": "chronological three-way: baseline / calibration / holdout",
        "reported_on": "holdout split only",
        "threshold_and_lr_fitted_on": (
            "calibration split, via app.evaluation.calibration; disjoint from "
            "the holdout split reported here"
        ),
        "baseline_training_is_benign_only": True,
        "profile_updated_before_scoring": True,
        "model_refit_during_evaluation": False,
        "distinct_score_values": distinct_scores,
        "signal_ablation": ablation,
        "threshold_sweep": sweep,
        "best_f1_operating_point": best_f1,
        "detector": _describe_detector_backend(agent),
        "provenance": dataset.provenance,
        "caveats": [],
    }

    # ------------------------------------------------------------------
    # Honest verdict on the README's marketing numbers.
    # ------------------------------------------------------------------
    caveats: List[str] = []

    if dataset.provenance.get("is_synthetic"):
        caveats.append(
            "Corpus is synthetic. These numbers describe detector behaviour on a "
            "simulation, not real-world performance."
        )
        caveats.append(
            "MEASUREMENT LIMIT: the sensor-reported `severity` field is a "
            "production input to the rule engine but is deliberately WITHHELD "
            "from the detector by this harness (see "
            "LabeledRecord.to_behaviour_input). In this corpus every benign "
            "background record is 'info' while malicious records carry "
            "critical/high/medium, so severity is very nearly a label. Feeding "
            "it in would push these metrics up for a reason that has nothing to "
            "do with the detector working. The figures below therefore "
            "UNDERSTATE what the shipped pipeline sees in production, and the "
            "gap cannot be quantified on a corpus with this artefact."
        )
    if not payload["detector"]["isolation_forest_is_sklearn"]:
        caveats.append(
            "The anomaly model is not a real sklearn estimator. Reported scores "
            "come solely from the rule engine."
        )
    if ablation.get("fusion_gain_over_rules") is not None and abs(
        ablation["fusion_gain_over_rules"]
    ) < 0.01:
        caveats.append(
            "The IsolationForest contributes no measurable discrimination over "
            "the rule engine on this corpus (see signal_ablation). The result "
            "should not be described as ML-driven detection."
        )
    if ablation.get("fusion_gain_over_model") is not None and (
        ablation["fusion_gain_over_model"] < -0.01
    ):
        caveats.append(
            "The shipped noisy-OR fusion scores WORSE than the IsolationForest "
            "on its own (see signal_ablation). Fusing a near-random rule score "
            "into a working model is costing discrimination, not adding it."
        )
    if distinct_scores < 10:
        caveats.append(
            f"Only {distinct_scores} distinct score values were produced. The rule "
            "engine emits coarse additive scores, so the ROC curve is a step "
            "function and AUC is correspondingly coarse."
        )
    if roc_auc is not None and roc_auc < 0.7:
        caveats.append(
            f"ROC-AUC of {roc_auc} indicates weak separation between benign and "
            "malicious records."
        )
    if headline["recall"] == 0.0:
        caveats.append(
            f"CRITICAL: recall is 0.0 at the shipped threshold of {threshold}. The "
            f"detector raises no alert on ANY of the {positives} malicious records "
            f"in the evaluation split. ROC-AUC of {roc_auc} shows the score does "
            "carry ranking signal, so the threshold - not the signal - is the "
            f"binding problem. Best measured F1 is {best_f1['f1']} at threshold "
            f"{best_f1['threshold']}."
        )
    elif headline["recall"] < 0.5:
        caveats.append(
            f"Recall at the shipped threshold is {headline['recall']}, i.e. the "
            f"detector misses {headline['fn']} of {positives} malicious records."
        )

    payload["caveats"] = caveats

    # A classifier that always predicts "benign" achieves this accuracy. Any
    # accuracy claim must beat it to mean anything.
    trivial_accuracy = negatives / max(len(y_true), 1)

    payload["readme_claim_check"] = {
        "claimed_accuracy": README_CLAIMED_ACCURACY,
        "measured_accuracy": headline["accuracy"],
        "always_predict_benign_accuracy": round(trivial_accuracy, 4),
        "beats_trivial_baseline": bool(headline["accuracy"] > trivial_accuracy),
        "measured_recall": headline["recall"],
        "measured_precision": headline["precision"],
        "accuracy_claim_supported": bool(
            headline["accuracy"] >= README_CLAIMED_ACCURACY
        ),
        "accuracy_claim_note": (
            "Accuracy is a misleading headline metric at this class imbalance: "
            f"always predicting 'benign' scores {round(trivial_accuracy, 4)} here "
            "while detecting nothing at all. The measured accuracy clears the "
            "claimed 0.82 only because of that imbalance, NOT because the "
            "detector works. Recall, FPR and ROC-AUC are the meaningful numbers."
        ),
        "claimed_false_positive_reduction": README_CLAIMED_FP_REDUCTION,
        "false_positive_reduction_measurable": False,
        "false_positive_reduction_note": (
            "A 90% false-positive REDUCTION claim requires a documented "
            "pre-Sentinel baseline FP count to reduce from. No such baseline "
            "exists in this repository, so the claim is not computable and is "
            "NOT substantiated by this harness. Only the absolute FPR "
            f"({headline['fpr']}) is measured."
        ),
    }

    logger.info(
        "evaluation.detection: completed",
        samples=payload["samples"],
        recall=payload["recall"],
        fpr=payload["fpr"],
        roc_auc=payload["roc_auc"],
    )
    return payload
