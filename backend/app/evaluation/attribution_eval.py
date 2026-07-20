"""APT attribution accuracy at MITRE ATT&CK technique level.

Feeds ground-truth-labelled malicious events through ``agents/mitre_mapper.py``
and compares the predicted ``technique_id`` against ``true_technique``.

Two limitations of the mapper are measured and reported explicitly rather than
being allowed to inflate the headline:

1. **Catalogue coverage.** ``MITRE_ATTACK_DATA`` contains a small hand-curated
   subset of ATT&CK Enterprise. Any ground-truth technique outside that subset
   is *unreachable* - the mapper cannot emit it under any input. We compute the
   subset size at runtime and report it against the published ATT&CK Enterprise
   counts, plus the fraction of the corpus that is unreachable.

2. **Constant confidence.** ``MitreMapper.map_event`` returns a hardcoded
   ``confidence: 0.85`` for every successful mapping regardless of evidence
   quality. That number is not a calibrated probability and must not be
   presented as one. We verify this at runtime and report it.

Sub-technique handling: ATT&CK sub-techniques are written ``T1021.002``. The
mapper only stores base techniques (``T1021``), so a prediction of ``T1021``
against a truth of ``T1021.002`` is scored as a **base-technique match**, not an
exact match. Both are reported separately.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Sequence

from app.evaluation.datasets import (
    BenchmarkDataset,
    LabeledRecord,
    generate_benchmark_dataset,
    logger,
)

# Published ATT&CK Enterprise counts used as the denominator for the coverage
# statement. Source: MITRE ATT&CK Enterprise matrix v14/v15 (attack.mitre.org).
# Stated as an external reference figure, not something measured here.
ATTACK_ENTERPRISE_BASE_TECHNIQUES = 201
ATTACK_ENTERPRISE_SUBTECHNIQUES = 424
ATTACK_ENTERPRISE_TOTAL = (
    ATTACK_ENTERPRISE_BASE_TECHNIQUES + ATTACK_ENTERPRISE_SUBTECHNIQUES
)
ATTACK_REFERENCE = "MITRE ATT&CK Enterprise v14/v15, attack.mitre.org"


def _base_technique(technique_id: Optional[str]) -> Optional[str]:
    """``T1021.002`` -> ``T1021``. Returns None for falsy input."""
    if not technique_id:
        return None
    return str(technique_id).split(".")[0].strip().upper()


def _mapper_catalogue() -> Dict[str, Any]:
    """Enumerate what the mapper can actually emit, and its tactic index."""
    from app.agents.mitre_mapper import MITRE_ATTACK_DATA

    technique_to_tactic: Dict[str, str] = {}
    for tactic_key, techniques in MITRE_ATTACK_DATA.items():
        for technique_id, info in techniques.items():
            # A technique can appear under several tactics (e.g. T1078 under
            # both Initial Access and Privilege Escalation). Keep the first,
            # but remember the full set for tactic-level scoring.
            technique_to_tactic.setdefault(technique_id, info.get("tactic", tactic_key))

    tactics_for_technique: Dict[str, set] = defaultdict(set)
    for tactic_key, techniques in MITRE_ATTACK_DATA.items():
        for technique_id, info in techniques.items():
            tactics_for_technique[technique_id].add(info.get("tactic", tactic_key))

    known = sorted(technique_to_tactic)
    return {
        "known_techniques": known,
        "technique_to_tactic": technique_to_tactic,
        "tactics_for_technique": {k: sorted(v) for k, v in tactics_for_technique.items()},
        "unique_technique_count": len(known),
        "sub_techniques_in_catalogue": sum(1 for t in known if "." in t),
    }


def _probe_confidence_is_constant() -> Dict[str, Any]:
    """Empirically check whether map_event ever varies its confidence."""
    from app.agents.mitre_mapper import mitre_mapper

    probes = [
        {"event_type": "credential_dumping", "description": "mimikatz lsass"},
        {"event_type": "ransomware_encryption", "description": "mass encryption"},
        {"event_type": "phishing", "description": "malicious attachment"},
        {"event_type": "lateral_movement_smb", "description": "rdp to server"},
        {"event_type": "port_scan", "description": "network scan"},
    ]
    values = []
    for probe in probes:
        result = mitre_mapper.map_event(probe)
        if result.get("mapped"):
            values.append(result.get("confidence"))

    distinct = sorted(set(values))
    return {
        "distinct_confidence_values_observed": distinct,
        "confidence_is_constant": len(distinct) <= 1,
        "constant_value": distinct[0] if len(distinct) == 1 else None,
        "note": (
            "MitreMapper.map_event returns a hardcoded confidence for every "
            "successful mapping. It is a literal, not a calibrated posterior, "
            "and must not be reported or displayed as model confidence."
            if len(distinct) <= 1 else
            "Confidence varies across probes; verify how it is derived before "
            "presenting it as calibrated."
        ),
    }


def evaluate_attribution(
    dataset: Optional[BenchmarkDataset] = None,
    records: Optional[Sequence[LabeledRecord]] = None,
) -> Dict[str, Any]:
    """Score the ATT&CK mapper against ground-truth technique labels.

    Only malicious records carrying a ``true_technique`` are scorable. Records
    without a ground-truth label are counted as ``unscorable`` and excluded from
    the denominators rather than being silently treated as correct or wrong.

    Returns:
        A payload matching ``GET /evaluation/attribution`` in the API contract,
        extended with coverage limits, a per-technique breakdown and a confusion
        summary.
    """
    from app.agents.mitre_mapper import mitre_mapper

    dataset = dataset or generate_benchmark_dataset()
    source_records = list(records) if records is not None else dataset.records

    catalogue = _mapper_catalogue()
    known = set(catalogue["known_techniques"])
    tactics_for_technique = catalogue["tactics_for_technique"]

    scorable = [r for r in source_records if r.is_malicious and r.true_technique]
    unscorable = [r for r in source_records if r.is_malicious and not r.true_technique]

    if not scorable:
        return {
            "error": "no records with ground-truth technique labels",
            "technique_accuracy": None,
            "tactic_accuracy": None,
            "per_technique": [],
            "scorable_records": 0,
            "unscorable_records": len(unscorable),
            "provenance": dataset.provenance,
        }

    exact_hits = 0
    base_hits = 0
    tactic_hits = 0
    unmapped = 0

    per_technique: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "support": 0,
            "exact": 0,
            "base_match": 0,
            "tactic_match": 0,
            "unmapped": 0,
            "predictions": Counter(),
            "in_mapper_catalogue": False,
            "reachable": False,
        }
    )
    confusion: Counter = Counter()

    for record in scorable:
        truth = str(record.true_technique).strip().upper()
        truth_base = _base_technique(truth)

        prediction = mitre_mapper.map_event(record.to_event())
        predicted = prediction.get("technique_id")
        predicted_norm = str(predicted).strip().upper() if predicted else None
        predicted_base = _base_technique(predicted_norm)

        bucket = per_technique[truth]
        bucket["support"] += 1
        bucket["in_mapper_catalogue"] = truth in known
        # "Reachable" means the mapper could in principle emit something that
        # scores as a base-technique match for this truth label.
        bucket["reachable"] = truth_base in known
        bucket["predictions"][predicted_norm or "UNMAPPED"] += 1
        confusion[(truth, predicted_norm or "UNMAPPED")] += 1

        if not prediction.get("mapped") or not predicted_norm:
            unmapped += 1
            bucket["unmapped"] += 1
            continue

        if predicted_norm == truth:
            exact_hits += 1
            bucket["exact"] += 1

        if predicted_base and predicted_base == truth_base:
            base_hits += 1
            bucket["base_match"] += 1

        # Tactic-level credit: the predicted technique's tactic set overlaps the
        # ground-truth technique's tactic set. Uses the base technique for the
        # truth because the mapper has no sub-technique entries.
        truth_tactics = set(tactics_for_technique.get(truth_base, []))
        predicted_tactics = set(tactics_for_technique.get(predicted_base, []))
        if truth_tactics and predicted_tactics and (truth_tactics & predicted_tactics):
            tactic_hits += 1
            bucket["tactic_match"] += 1

    total = len(scorable)

    # Coverage: how much of the ground truth the mapper could ever get right.
    truths = {str(r.true_technique).strip().upper() for r in scorable}
    unreachable_truths = sorted(t for t in truths if _base_technique(t) not in known)
    unreachable_records = sum(
        1 for r in scorable
        if _base_technique(str(r.true_technique).strip().upper()) not in known
    )

    per_technique_rows = []
    for technique_id in sorted(per_technique):
        bucket = per_technique[technique_id]
        support = bucket["support"]
        top_prediction, top_count = (
            bucket["predictions"].most_common(1)[0]
            if bucket["predictions"] else ("UNMAPPED", 0)
        )
        per_technique_rows.append({
            "true_technique": technique_id,
            "support": support,
            "exact_accuracy": round(bucket["exact"] / support, 4),
            "base_technique_accuracy": round(bucket["base_match"] / support, 4),
            "tactic_accuracy": round(bucket["tactic_match"] / support, 4),
            "unmapped": bucket["unmapped"],
            "in_mapper_catalogue": bucket["in_mapper_catalogue"],
            "reachable_at_base_level": bucket["reachable"],
            "most_common_prediction": top_prediction,
            "most_common_prediction_count": top_count,
        })

    confusion_rows = [
        {
            "true_technique": truth,
            "predicted_technique": predicted,
            "count": count,
            "correct": truth == predicted,
        }
        for (truth, predicted), count in confusion.most_common()
    ]

    coverage_fraction = (
        catalogue["unique_technique_count"] / ATTACK_ENTERPRISE_TOTAL
    )

    confidence_probe = _probe_confidence_is_constant()

    payload: Dict[str, Any] = {
        # --- contract fields ---
        "technique_accuracy": round(exact_hits / total, 4),
        "tactic_accuracy": round(tactic_hits / total, 4),
        "per_technique": per_technique_rows,
        # --- extended, honest detail ---
        "base_technique_accuracy": round(base_hits / total, 4),
        "exact_technique_matches": exact_hits,
        "base_technique_matches": base_hits,
        "tactic_matches": tactic_hits,
        "unmapped_events": unmapped,
        "unmapped_rate": round(unmapped / total, 4),
        "scorable_records": total,
        "unscorable_records": len(unscorable),
        "distinct_true_techniques": len(truths),
        "confusion_summary": confusion_rows,
        "technique_coverage": (
            f"{catalogue['unique_technique_count']}/{ATTACK_ENTERPRISE_TOTAL}"
        ),
        "coverage": {
            "mapper_technique_count": catalogue["unique_technique_count"],
            "mapper_sub_technique_count": catalogue["sub_techniques_in_catalogue"],
            "attack_enterprise_base_techniques": ATTACK_ENTERPRISE_BASE_TECHNIQUES,
            "attack_enterprise_sub_techniques": ATTACK_ENTERPRISE_SUBTECHNIQUES,
            "attack_enterprise_total": ATTACK_ENTERPRISE_TOTAL,
            "coverage_fraction_of_total": round(coverage_fraction, 4),
            "coverage_pct_of_total": round(coverage_fraction * 100, 2),
            "attack_reference": ATTACK_REFERENCE,
            "attack_reference_is_external": True,
            "unreachable_true_techniques": unreachable_truths,
            "unreachable_record_count": unreachable_records,
            "unreachable_record_pct": round(100 * unreachable_records / total, 2),
            "ceiling_note": (
                f"The mapper's table holds {catalogue['unique_technique_count']} "
                f"techniques against ATT&CK Enterprise's ~{ATTACK_ENTERPRISE_TOTAL} "
                f"(~{round(coverage_fraction * 100, 1)}%). It contains "
                f"{catalogue['sub_techniques_in_catalogue']} sub-technique entries, "
                "so exact sub-technique attribution (e.g. T1021.002) is "
                "STRUCTURALLY IMPOSSIBLE for it - exact_technique_accuracy is "
                "capped accordingly. Any technique outside the table is "
                "unreachable under any input."
            ),
        },
        "confidence_reporting": confidence_probe,
        "provenance": dataset.provenance,
        "caveats": [],
    }

    caveats: List[str] = []
    if dataset.provenance.get("is_synthetic"):
        caveats.append(
            "Ground-truth technique labels come from the synthetic scenario "
            "corpus, not from analyst-adjudicated real incidents."
        )
    if catalogue["sub_techniques_in_catalogue"] == 0:
        caveats.append(
            "The mapper stores zero sub-techniques, so exact-match accuracy "
            "against sub-technique ground truth is bounded above by the share "
            "of truth labels that are base techniques. Use "
            "base_technique_accuracy for a fair read of the mapper's ceiling."
        )
    if unreachable_records:
        caveats.append(
            f"{unreachable_records} of {total} scorable records "
            f"({round(100 * unreachable_records / total, 1)}%) carry a technique "
            "the mapper's table cannot emit at all."
        )
    if confidence_probe["confidence_is_constant"]:
        caveats.append(
            f"Mapper confidence is the constant "
            f"{confidence_probe['constant_value']} for every mapped event; it "
            "conveys no information and is not calibrated."
        )
    if payload["unmapped_rate"] > 0.2:
        caveats.append(
            f"{payload['unmapped_rate'] * 100:.1f}% of malicious events were not "
            "mapped to any technique."
        )
    payload["caveats"] = caveats

    logger.info(
        "evaluation.attribution: completed",
        technique_accuracy=payload["technique_accuracy"],
        base_technique_accuracy=payload["base_technique_accuracy"],
        tactic_accuracy=payload["tactic_accuracy"],
        coverage=payload["technique_coverage"],
    )
    return payload
